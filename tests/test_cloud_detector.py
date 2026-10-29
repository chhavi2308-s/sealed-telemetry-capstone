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


def test_capacity_overflow_does_not_starve_other_credentials(monkeypatch):
    from unittest.mock import MagicMock, patch

    from sealed_telemetry.schema import utcnow

    monkeypatch.setenv("EVENT_TABLE", "events")
    monkeypatch.setenv("DECISION_TABLE", "decisions")
    monkeypatch.setenv("ACTIVE_TABLE", "active")
    monkeypatch.setenv("HEALTH_TABLE", "health")
    tables = {n: MagicMock() for n in ["events", "decisions", "active", "health"]}
    tables["active"].get_item.return_value = {}
    tables["active"].scan.return_value = {
        "Items": [
            {"credential_fingerprint": fp, "expires_at": int(timestamp(utcnow()).timestamp()) + 900}
            for fp in ["a" * 64, "b" * 64]
        ]
    }
    tables["health"].get_item.return_value = {}
    tables["decisions"].get_item.return_value = {}
    e = event("provider", "PROVIDER_ACTION", provider_request_id="request")
    envelope = {
        "raw": e.to_dict(),
        "receipt": {"authenticated_source": "provider", "canonical_hash": digest(e.to_dict())},
    }
    tables["events"].query.side_effect = [
        {"Items": [{"record": canonical(envelope).decode()}] * 1001},
        {"Items": []},
    ]
    resource = MagicMock()
    resource.Table.side_effect = lambda name: tables[name]
    with (
        patch("sealed_telemetry.cloud_detector.boto3.resource", return_value=resource),
        patch("sealed_telemetry.cloud_detector.boto3.client") as client,
    ):
        result = detector({}, None)
        assert result["credential_groups"] == 2
        writes = client.return_value.transact_write_items.call_args.kwargs["TransactItems"]
        body = json.loads(writes[1]["Put"]["Item"]["body"]["S"])
        assert body["state"] == "INCONCLUSIVE"
        assert body["reason_codes"] == ["EVIDENCE_CAPACITY_EXCEEDED"]
        assert tables["events"].query.call_count == 2


def test_expired_active_pages_are_bounded_and_cursor_advances(monkeypatch):
    from unittest.mock import MagicMock, patch

    for env, value in [
        ("EVENT_TABLE", "events"),
        ("DECISION_TABLE", "decisions"),
        ("ACTIVE_TABLE", "active"),
        ("HEALTH_TABLE", "health"),
    ]:
        monkeypatch.setenv(env, value)
    tables = {name: MagicMock() for name in ["events", "decisions", "active", "health"]}
    tables["active"].get_item.return_value = {}
    tables["health"].get_item.return_value = {}
    tables["active"].scan.side_effect = [
        {
            "Items": [{"credential_fingerprint": "expired-" + str(i), "expires_at": 1}],
            "LastEvaluatedKey": {"credential_fingerprint": "expired-" + str(i)},
        }
        for i in range(20)
    ]
    resource = MagicMock()
    resource.Table.side_effect = lambda name: tables[name]
    with patch("sealed_telemetry.cloud_detector.boto3.resource", return_value=resource):
        assert detector({}, None)["credential_groups"] == 0
    assert tables["active"].scan.call_count == 20
    assert tables["active"].put_item.call_args.kwargs["Item"]["cursor"] == {
        "credential_fingerprint": "expired-19"
    }
