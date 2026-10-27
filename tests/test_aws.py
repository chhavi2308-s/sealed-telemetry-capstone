import json
from unittest.mock import patch

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws
from test_core import NOW, event

from sealed_telemetry.aws_handlers import collector, normalizer, persist, source_for_principal
from sealed_telemetry.schema import canonical, digest


@pytest.fixture
def aws(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("ARCHIVE_BUCKET", "sealed-lab-evidence-test")
    monkeypatch.setenv("EVENT_TABLE", "evidence")
    monkeypatch.setenv(
        "SOURCE_ROLES", json.dumps({"gateway": "arn:aws:iam::123456789012:role/gateway"})
    )
    with mock_aws():
        s3 = boto3.client("s3")
        s3.create_bucket(Bucket="sealed-lab-evidence-test")
        s3.put_bucket_versioning(
            Bucket="sealed-lab-evidence-test", VersioningConfiguration={"Status": "Enabled"}
        )
        boto3.client("dynamodb").create_table(
            TableName="evidence",
            BillingMode="PAY_PER_REQUEST",
            KeySchema=[{"AttributeName": "event_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "event_id", "AttributeType": "S"}],
        )
        monkeypatch.setenv("ACTIVE_TABLE", "active")
        monkeypatch.setenv("HEALTH_TABLE", "health")
        for name, key in (("active", "credential_fingerprint"), ("health", "source_id")):
            boto3.client("dynamodb").create_table(
                TableName=name,
                BillingMode="PAY_PER_REQUEST",
                KeySchema=[{"AttributeName": key, "KeyType": "HASH"}],
                AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}],
            )
        url = boto3.client("sqs").create_queue(QueueName="intake")["QueueUrl"]
        monkeypatch.setenv("QUEUE_URL", url)
        monkeypatch.setenv(
            "QUEUE_SOURCES", json.dumps({"arn:aws:sqs:us-east-1:123456789012:intake": "collector"})
        )
        yield


def envelope():
    raw = event().to_dict()
    return {
        "raw": raw,
        "receipt": {
            "canonical_hash": digest(raw),
            "authenticated_source": "gateway",
            "collector_received_at_utc": NOW,
            "collector_receipt_id": "receipt",
        },
    }


def test_principal_boundaries():
    roles = {"provider": "arn:aws:iam::123456789012:role/provider"}
    assert source_for_principal("arn:aws:sts::123456789012:assumed-role/provider/session", roles)
    for arn in [
        "arn:aws:sts::999999999999:assumed-role/provider/session",
        "arn:aws:sts::123456789012:assumed-role/provider-evil/session",
    ]:
        with pytest.raises(ValueError):
            source_for_principal(arn, roles)


def test_intake_to_archive_and_duplicate(aws):
    request = {
        "requestContext": {
            "identity": {"userArn": "arn:aws:sts::123456789012:assumed-role/gateway/session"}
        },
        "body": json.dumps(event().to_dict()),
    }
    assert collector(request, None)["statusCode"] == 202
    sqs = boto3.client("sqs")
    import os

    messages = sqs.receive_message(QueueUrl=os.environ["QUEUE_URL"])["Messages"]
    data = {
        "Records": [
            {
                "body": messages[0]["Body"],
                "messageId": "id",
                "eventSourceARN": "arn:aws:sqs:us-east-1:123456789012:intake",
            }
        ]
    }
    assert normalizer(data, None) == {"batchItemFailures": []}
    assert normalizer(data, None) == {"batchItemFailures": []}
    assert boto3.resource("dynamodb").Table("evidence").scan()["Count"] == 1
    versions = boto3.client("s3").list_object_versions(Bucket="sealed-lab-evidence-test")
    assert len(versions["Versions"]) == 1
    bad = {**request, "body": json.dumps(event("app", "INTENT_CREATED").to_dict())}
    assert collector(bad, None)["statusCode"] == 400
    assert collector({"body": "{}"}, None)["statusCode"] == 403
    assert collector({**request, "body": "x" * 17000}, None)["statusCode"] == 413


def test_partial_batch_and_conflicting_id(aws):
    data = envelope()
    persist(data)
    data["raw"]["operation"] = "evil"
    data["receipt"]["canonical_hash"] = digest(data["raw"])
    with pytest.raises(ValueError, match="content conflict"):
        persist(data)
    valid = envelope()
    result = normalizer(
        {
            "Records": [
                {
                    "messageId": "ok",
                    "eventSourceARN": "arn:aws:sqs:us-east-1:123456789012:intake",
                    "body": canonical(valid).decode(),
                },
                {
                    "messageId": "bad",
                    "eventSourceARN": "arn:aws:sqs:us-east-1:123456789012:intake",
                    "body": "invalid-json",
                },
            ]
        },
        None,
    )
    assert result["batchItemFailures"] == [{"itemIdentifier": "bad"}]


def test_archive_failure_does_not_commit_index(aws):
    with patch("sealed_telemetry.aws_handlers.boto3.client") as client:
        client.return_value.put_object.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "injected"}}, "PutObject"
        )
        with pytest.raises(ClientError):
            persist(envelope())
    assert boto3.resource("dynamodb").Table("evidence").scan()["Count"] == 0


def test_index_failure_recovers_from_existing_archive(aws):
    data = envelope()
    with patch("sealed_telemetry.aws_handlers.boto3.resource") as resource:
        resource.return_value.Table.return_value.put_item.side_effect = ClientError(
            {"Error": {"Code": "ProvisionedThroughputExceededException"}}, "PutItem"
        )
        with pytest.raises(ClientError):
            persist(data)
    persist(data)
    assert boto3.resource("dynamodb").Table("evidence").scan()["Count"] == 1
