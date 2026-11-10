"""Mappings exercised against actual legacy enqueue/persist code under mocked AWS."""

import json
from dataclasses import replace
from unittest.mock import patch

import boto3
import pytest
from test_four_stage_binding import lab as lab
from test_four_stage_collection import canonical_events, config, state_rows
from test_four_stage_collection import collection as collection

from sealed_telemetry import aws_handlers
from sealed_telemetry.four_stage_archive import events_v1, read_s3_v1, sqs_v1
from sealed_telemetry.four_stage_c3_schema import InvalidRecord, normalize, plain
from sealed_telemetry.four_stage_collection import Collector, Source
from sealed_telemetry.schema import canonical

NOW = "1970-01-01T00:16:41+00:00"


@pytest.fixture
def archive(collection, monkeypatch):
    conf = config(collection, canonical=True)
    events = canonical_events(collection)
    db = collection["lab"]["db"]
    roles = {}
    for source in ("gateway", "app", "provider", "health"):
        roles[source] = boto3.client("iam").create_role(
            RoleName="Archive-" + source,
            AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}),
        )["Role"]["Arn"]
    for name, key in (
        ("EventsV1", "event_id"),
        ("ActiveV1", "credential_fingerprint"),
        ("HealthV1", "source_id"),
    ):
        db.create_table(
            TableName=name,
            BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}],
            KeySchema=[{"AttributeName": key, "KeyType": "HASH"}],
        )
    s3 = boto3.client("s3", region_name="ap-south-1")
    bucket = "c4-archive-fixture"
    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": "ap-south-1"})
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    queue = boto3.client("sqs").create_queue(QueueName="c4-archive-fixture")["QueueUrl"]
    for key, value in {
        "ARCHIVE_BUCKET": bucket,
        "EVENT_TABLE": "EventsV1",
        "ACTIVE_TABLE": "ActiveV1",
        "HEALTH_TABLE": "HealthV1",
        "QUEUE_URL": queue,
    }.items():
        monkeypatch.setenv(key, value)
    conf = replace(
        conf,
        sources=(Source("archive", "aws-events-1", db.Table("EventsV1").table_arn, "event_id"),),
        archive_roles=tuple(roles.items()),
    )
    return {
        **collection,
        "config": conf,
        "events": events,
        "db": db,
        "roles": roles,
        "bucket": bucket,
        "s3": s3,
        "queue": queue,
    }


def persist(archive, event):
    with patch.object(aws_handlers, "utcnow", return_value=NOW):
        aws_handlers.enqueue(
            event,
            event.to_dict(),
            canonical(event.to_dict()).decode(),
            archive["roles"][event.source_id],
        )
    message = boto3.client("sqs").receive_message(
        QueueUrl=archive["queue"], MessageSystemAttributeNames=["SentTimestamp"]
    )["Messages"][0]
    envelope = json.loads(message["Body"])
    aws_handlers.persist(envelope)
    boto3.client("sqs").delete_message(
        QueueUrl=archive["queue"], ReceiptHandle=message["ReceiptHandle"]
    )
    row = plain(
        archive["db"]
        .Table("EventsV1")
        .get_item(Key={"event_id": event.source_id + ":" + event.event_id})["Item"]
    )
    return row, envelope, message


def test_explicit_mappings_match_existing_sqs_s3_and_events_table_formats(archive):
    event = archive["events"][0]
    row, _, message = persist(archive, event)
    assert events_v1(row, row["event_id"], archive["roles"]) == event.to_dict()
    mapped = read_s3_v1(
        archive["s3"],
        archive["bucket"],
        "123456789012",
        row["archive_key"],
        row["archive_version"],
        "gateway",
        archive["roles"],
    )
    assert mapped["event"] == event.to_dict()
    queue_arn = "arn:aws:sqs:ap-south-1:123456789012:c4-archive-fixture"
    mapped = sqs_v1(
        {
            "body": message["Body"],
            "eventSource": "aws:sqs",
            "eventSourceARN": queue_arn,
            "messageId": message["MessageId"],
            "attributes": {"SentTimestamp": "1000000"},
        },
        {queue_arn: "collector"},
        archive["roles"],
    )
    assert mapped["event"] == event.to_dict()


@pytest.mark.parametrize("tamper", ["body", "normalized", "principal", "index", "path", "private"])
def test_wrapper_or_receipt_tampering_is_quarantined_without_raw_private_exports(archive, tamper):
    row, envelope, _ = persist(archive, archive["events"][0])
    if tamper == "body":
        envelope["raw_body"] = "{}"
    elif tamper == "normalized":
        envelope["normalized"]["invocation_id"] = None
    elif tamper == "principal":
        envelope["receipt"]["authenticated_principal"] = archive["roles"]["app"]
    elif tamper == "index":
        row["run_id"] = "unrelated"
    elif tamper == "path":
        row["archive_key"] = "unrelated.json"
    else:
        envelope["raw"]["access_token"] = "private-synthetic-fixture"  # noqa: S105
    row["record"] = canonical(envelope).decode()
    archive["db"].Table("EventsV1").put_item(Item=row)
    result = Collector(archive["config"], archive["session"]).reconcile(NOW)
    assert not result["ready"] and "QUARANTINED_EVIDENCE" in result["blockers"]
    assert "private-synthetic-fixture" not in json.dumps(
        state_rows(archive, archive["config"]), default=str
    )


def test_legacy_health_without_observation_basis_does_not_make_archive_ready(archive):
    for event in archive["events"]:
        persist(archive, event)
    collector = Collector(archive["config"], archive["session"])
    result = collector.reconcile(NOW)
    assert not result["ready"] and result["submitted_count"] == 0
    assert "ARCHIVE_HEALTH_OBSERVATION_BASIS_UNKNOWN" in result["blockers"]
    assert all(value is None for value in result["source_health_snapshot"].values())
    assert collector.collect_all(NOW)["counts"]["duplicate"] == 7


def test_s3_never_falls_back_to_latest_or_unversioned_object(archive):
    with patch.object(archive["s3"], "get_object") as get:
        with pytest.raises(ValueError):
            read_s3_v1(
                archive["s3"],
                archive["bucket"],
                "123456789012",
                "any",
                "unversioned",
                "gateway",
                archive["roles"],
            )
        get.assert_not_called()


def test_unrelated_wrapper_cannot_be_treated_as_canonical(archive):
    event = archive["events"][0]
    with pytest.raises(InvalidRecord):
        normalize("gateway", "iber-1", "resource", event.event_id, {"body": event.to_dict()})


def test_unsupported_legacy_trace_context_remains_rejected_instead_of_stripped(archive):
    row, envelope, _ = persist(archive, archive["events"][0])
    event = replace(archive["events"][0], trace_context={"authorization_state": "accepted"})
    row, _, _ = persist(archive, replace(event, event_id=archive["events"][1].event_id))
    with pytest.raises(InvalidRecord):
        normalize(
            "archive",
            "aws-events-1",
            "resource",
            row["event_id"],
            row,
            archive["config"].archive_roles,
        )


def test_malformed_archive_diagnostics_never_echo_private_values(archive):
    row, envelope, _ = persist(archive, archive["events"][0])
    envelope["receipt"]["collector_received_at_utc"] = "private-synthetic-fixture"
    row["record"] = canonical(envelope).decode()
    with pytest.raises(ValueError) as error:
        events_v1(row, row["event_id"], archive["roles"])
    assert str(error.value) == "INVALID_AWS_ARCHIVE_RECORD"
