import json

import boto3
from moto import mock_aws
from test_core import LATER, NOW, event

from sealed_telemetry.cloud_detector import detector
from sealed_telemetry.schema import canonical, digest, timestamp


@mock_aws
def test_cloud_decision_transaction_and_revisions(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("EVENT_TABLE", "events")
    monkeypatch.setenv("DECISION_TABLE", "decisions")
    monkeypatch.setenv("FINDINGS_BUS", "findings")
    monkeypatch.setenv("ACTIVE_TABLE", "active")
    monkeypatch.setenv("HEALTH_TABLE", "health")
    client = boto3.client("dynamodb")
    for name, key in (("active", "credential_fingerprint"), ("health", "source_id")):
        client.create_table(
            TableName=name,
            BillingMode="PAY_PER_REQUEST",
            KeySchema=[{"AttributeName": key, "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}],
        )
    boto3.resource("dynamodb").Table("active").put_item(
        Item={
            "credential_fingerprint": "a" * 64,
            "expires_at": int(timestamp(NOW).timestamp()) + 900,
        }
    )
    client.create_table(
        TableName="events",
        BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[
            {"AttributeName": "event_id", "AttributeType": "S"},
            {"AttributeName": "credential_fingerprint", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "CredentialIndex",
                "KeySchema": [{"AttributeName": "credential_fingerprint", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        KeySchema=[{"AttributeName": "event_id", "KeyType": "HASH"}],
    )
    client.create_table(
        TableName="decisions",
        BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[
            {"AttributeName": "case_id", "AttributeType": "S"},
            {"AttributeName": "decision_id", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "case_id", "KeyType": "HASH"},
            {"AttributeName": "decision_id", "KeyType": "RANGE"},
        ],
    )
    boto3.client("events").create_event_bus(Name="findings")
    table = boto3.resource("dynamodb").Table("events")
    for evidence in [
        event(),
        event("app", "INTENT_CREATED"),
        event("provider", "PROVIDER_ACTION", provider_request_id="request"),
    ]:
        table.put_item(
            Item={
                "event_id": evidence.event_id,
                "credential_fingerprint": evidence.credential_fingerprint,
                "record": canonical(
                    {
                        "raw": evidence.to_dict(),
                        "receipt": {
                            "authenticated_source": evidence.source_id,
                            "canonical_hash": digest(evidence.to_dict()),
                            "collector_received_at_utc": NOW,
                        },
                    }
                ).decode(),
            }
        )
    for source in ("app", "gateway", "provider", "collector"):
        boto3.resource("dynamodb").Table("health").put_item(
            Item={"source_id": source, "checked_at": NOW, "state": "healthy"}
        )
    monkeypatch.setattr("sealed_telemetry.cloud_detector.utcnow", lambda: LATER)
    assert detector({}, None)["decisions"] == 1
    decisions = boto3.resource("dynamodb").Table("decisions")
    assert decisions.scan()["Count"] == 2  # one history row plus current pointer
    detector({}, None)
    assert decisions.scan()["Count"] == 2
    monkeypatch.setattr(
        "sealed_telemetry.cloud_detector.utcnow", lambda: "2026-10-26T10:10:00+00:00"
    )
    detector({}, None)
    assert decisions.scan()["Count"] == 3
    monkeypatch.setattr("sealed_telemetry.cloud_detector.utcnow", lambda: LATER)
    detector({}, None)
    rows = decisions.scan()["Items"]
    assert len(rows) == 4  # returning to prior state still records a new revision
    current = next(r for r in rows if r["decision_id"] == "CURRENT")
    assert current["revision"] == 3
    assert json.loads(current["body"])["state"] == "CONSISTENT"
