import gzip
import json
from unittest.mock import patch
from uuid import uuid4

import pytest
from test_aws import aws, envelope  # noqa: F401 -- shared Moto fixture
from test_core import NOW, event

from sealed_telemetry.aws_handlers import normalizer, persist
from sealed_telemetry.schema import canonical
from sealed_telemetry.telemetry import (
    cloudtrail,
    cloudtrail_records,
    cloudwatch_records,
    publish,
    unpack_gzip,
)


def test_platform_whitelist_and_stable_identity():
    request = str(uuid4())
    batch = {
        "messageType": "DATA_MESSAGE",
        "logGroup": "app",
        "logStream": "stream",
        "logEvents": [
            {
                "id": "1",
                "timestamp": 1793008800000,
                "message": "START RequestId: " + request + " Version: $LATEST",
            },
            {
                "id": "2",
                "timestamp": 1793008800000,
                "message": "Bearer synthetic-secret-never-forward",
            },
        ],
    }
    records = cloudwatch_records(batch)
    assert len(records) == 1 and records[0].invocation_id == request
    assert records == cloudwatch_records(batch)
    assert "synthetic-secret" not in canonical([r.to_dict() for r in records]).decode()
    assert records[0].trace_context["telemetry_trust"].startswith("corroborative")
    assert cloudwatch_records({"messageType": "CONTROL_MESSAGE"}) == []


def test_cloudtrail_redacts_and_never_claims_outbound_saas():
    native = {
        "eventID": str(uuid4()),
        "eventTime": NOW,
        "eventSource": "lambda.amazonaws.com",
        "eventName": "Invoke",
        "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "requestParameters": {"token": "synthetic-secret-value"},
        "userIdentity": {"arn": "actor"},
    }
    obs = cloudtrail_records({"Records": [native]}, {})[0]
    assert obs.source_id == "cloudtrail" and obs.event_type == "AWS_API"
    assert obs.invocation_id is None and obs.credential_fingerprint == "0" * 64
    assert "synthetic-secret-value" not in canonical(obs.to_dict()).decode()
    assert obs.trace_context["aws_event_name"] == "Invoke"


def test_decompression_bound(monkeypatch):
    monkeypatch.setattr("sealed_telemetry.telemetry.MAX_BYTES", 256)
    with pytest.raises(ValueError, match="decompressed"):
        unpack_gzip(gzip.compress(b" " * 1000))


def test_partial_buffer_failure_is_retryable():
    records = cloudtrail_records(
        {
            "Records": [
                {
                    "eventID": str(uuid4()),
                    "eventTime": NOW,
                    "eventSource": "lambda.amazonaws.com",
                    "eventName": "Invoke",
                    "awsRegion": "us-east-1",
                    "recipientAccountId": "123456789012",
                }
            ]
        },
        {},
    )
    with patch("sealed_telemetry.telemetry.boto3.client") as client:
        client.return_value.send_message_batch.return_value = {"Failed": [{"Id": "0"}]}
        with pytest.raises(RuntimeError, match="partially"):
            publish(records, "queue")


@pytest.mark.usefixtures("aws")
def test_source_namespace_blocks_collision():
    first = envelope()
    persist(first)
    second = envelope()
    second["raw"] = event("app", "INTENT_CREATED", event_id=first["raw"]["event_id"]).to_dict()
    from sealed_telemetry.schema import digest

    second["receipt"].update(authenticated_source="app", canonical_hash=digest(second["raw"]))
    persist(second)
    import boto3

    assert boto3.resource("dynamodb").Table("evidence").scan()["Count"] == 2


@pytest.mark.usefixtures("aws")
def test_supplementary_queue_cannot_forge_provider(monkeypatch):
    arn = "arn:aws:sqs:us-east-1:123456789012:platform"
    monkeypatch.setenv("QUEUE_SOURCES", json.dumps({arn: "platform"}))
    raw = event("provider", "PROVIDER_ACTION", provider_request_id="request").to_dict()
    forged = envelope()
    forged["raw"] = raw
    forged["receipt"]["authenticated_source"] = "provider"
    result = normalizer(
        {
            "Records": [
                {"messageId": "forged", "eventSourceARN": arn, "body": canonical(forged).decode()}
            ]
        },
        None,
    )
    assert result["batchItemFailures"] == [{"itemIdentifier": "forged"}]


def test_cloudtrail_requires_version_pinned_origin(monkeypatch):
    monkeypatch.setenv("TRAIL_BUCKET", "logs")
    with patch("sealed_telemetry.telemetry.boto3.client"):
        with pytest.raises(ValueError, match="unversioned"):
            cloudtrail(
                {
                    "Records": [
                        {
                            "s3": {
                                "bucket": {"name": "logs"},
                                "object": {"key": "AWSLogs/123/CloudTrail/file.json.gz"},
                            }
                        }
                    ]
                },
                None,
            )
