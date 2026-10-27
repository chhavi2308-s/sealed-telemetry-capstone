import json
from unittest.mock import patch
from uuid import uuid4

import boto3
from moto import mock_aws

from sealed_telemetry.cloud_lab import app, audit_forwarder, gateway, issuer, saas
from sealed_telemetry.schema import new_event


@mock_aws
def test_issuer_and_provider_outbox(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("TOKEN_TABLE", "tokens")
    monkeypatch.setenv("OUTBOX_TABLE", "outbox")
    monkeypatch.setenv("PSEUDONYM_SECRET", "hmac-key")
    for name, key in [("tokens", "token_hash"), ("outbox", "event_id")]:
        boto3.client("dynamodb").create_table(
            TableName=name,
            BillingMode="PAY_PER_REQUEST",
            KeySchema=[{"AttributeName": key, "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}],
        )
    boto3.client("secretsmanager").create_secret(Name="hmac-key", SecretString="x" * 64)
    key_id = boto3.client("kms").create_key()["KeyMetadata"]["KeyId"]
    monkeypatch.setenv("CREDENTIAL_KEY", key_id)
    token = issuer({"operation": "issue"}, None)
    request = {
        "headers": {"Authorization": "Bearer " + token["access_token"], "X-Run-Id": str(uuid4())}
    }
    assert saas(request, None)["statusCode"] == 200
    assert saas({"headers": {"X-Run-Id": str(uuid4())}}, None)["statusCode"] == 403
    rows = boto3.resource("dynamodb").Table("outbox").scan()["Items"]
    assert len(rows) == 2
    assert token["access_token"] not in json.dumps(rows)
    assert all(row["pending_partition"] == "pending" for row in rows)
    from boto3.dynamodb.types import TypeSerializer

    serializer = TypeSerializer()
    stream_record = {
        "eventName": "INSERT",
        "eventID": "stream-id",
        "dynamodb": {
            "NewImage": {k: serializer.serialize(v) for k, v in rows[0].items()},
            "SequenceNumber": "1",
        },
    }
    with patch("sealed_telemetry.cloud_lab.emit"):
        assert audit_forwarder({"Records": [stream_record]}, None)["batchItemFailures"] == []
    delivered = (
        boto3.resource("dynamodb")
        .Table("outbox")
        .get_item(Key={"event_id": rows[0]["event_id"]})["Item"]
    )
    assert "pending_partition" not in delivered and "delivered_at" in delivered
    revoke = {
        "requestContext": {},
        "path": "/oauth/revoke",
        "body": json.dumps({"token": token["access_token"]}),
    }
    assert issuer(revoke, None)["statusCode"] == 200
    assert issuer(revoke, None)["statusCode"] == 200
    rejected = saas(request, None)
    assert rejected["statusCode"] == 403
    assert json.loads(rejected["body"])["reason"] == "revoked"
    assert rejected["headers"]["Cache-Control"] == "no-store"
    assert token["access_token"] not in rejected["body"]


def test_gateway_suppression_is_explicit_lab_setting(monkeypatch):
    monkeypatch.setenv("ISSUER_FUNCTION", "issuer")
    monkeypatch.setenv("APP_FUNCTION", "app")
    monkeypatch.setenv("LAB_EXPOSURE_ENABLED", "false")
    with (
        patch("sealed_telemetry.cloud_lab.invoke") as invoke,
        patch("sealed_telemetry.cloud_lab.emit") as emit,
    ):
        invoke.side_effect = [
            {"access_token": "disposable", "credential_fingerprint": "a" * 64},
            {"status": 200},
        ]
        result = gateway(
            {"body": json.dumps({"expose_test_token": True, "suppress_log": True})}, None
        )
        assert "disposable" not in result["body"]
        assert not invoke.call_args_list[1].args[1]["suppress_log"]
        assert emit.call_args.args[0].source_id == "gateway"


def test_app_suppression_preserves_provider_call(monkeypatch):
    monkeypatch.setenv("SAAS_URL", "https://synthetic.example/records")
    fields = new_event(
        "gateway",
        "EXPECTED_ACTION",
        run_id=str(uuid4()),
        scenario_id="lab",
        event_time_utc="2026-10-26T10:00:00+00:00",
        actor_pseudonym="lab",
        credential_fingerprint="a" * 64,
        operation="records:read",
        resource_pseudonym="records",
        invocation_id="inv",
        action_id="act",
    ).to_dict()
    fields = {k: v for k, v in fields.items() if k not in {"event_id", "source_id", "event_type"}}
    with (
        patch("sealed_telemetry.cloud_lab.emit") as emit,
        patch(
            "sealed_telemetry.cloud_lab.https_json",
            return_value={"status": 200, "body": {"provider_request_id": "r"}},
        ) as call,
    ):
        assert (
            app({"fields": fields, "access_token": "disposable", "suppress_log": True}, None)[
                "status"
            ]
            == 200
        )
        emit.assert_not_called()
        call.assert_called_once()


def test_workload_permission_probe_is_fail_closed(monkeypatch):
    from unittest.mock import MagicMock

    import pytest
    from botocore.exceptions import ClientError

    monkeypatch.setenv("LAB_EXPOSURE_ENABLED", "false")
    with pytest.raises(ValueError, match="disabled"):
        app({"operation": "permission_probe"}, None)
    monkeypatch.setenv("LAB_EXPOSURE_ENABLED", "true")
    client = MagicMock()
    denied = ClientError({"Error": {"Code": "AccessDenied"}}, "SyntheticProbe")
    for method in ["put_object", "delete_object", "put_item", "send_message"]:
        getattr(client, method).side_effect = denied
    client.get_caller_identity.return_value = {
        "Arn": "arn:aws:sts::123456789012:assumed-role/app/session"
    }
    with patch("sealed_telemetry.cloud_lab.boto3.client", return_value=client):
        result = app(
            {
                "operation": "permission_probe",
                "archive_bucket": "archive",
                "event_table": "events",
                "provider_queue_url": "queue",
            },
            None,
        )
        assert result["passed"]
        client.put_object.side_effect = None
        result = app(
            {
                "operation": "permission_probe",
                "archive_bucket": "archive",
                "event_table": "events",
                "provider_queue_url": "queue",
            },
            None,
        )
        assert not result["passed"]
        assert result["results"]["archive_put"] == "UNEXPECTED_ALLOW"
        assert client.delete_object.call_args.kwargs["Key"].endswith("-absent")


def test_quiesced_workload_and_provider_do_not_create_new_actions(monkeypatch):
    monkeypatch.setenv("QUIESCED", "true")
    with (
        patch("sealed_telemetry.cloud_lab.emit") as emit,
        patch("sealed_telemetry.cloud_lab.boto3.resource") as db,
    ):
        assert gateway({}, None)["statusCode"] == 503
        assert saas({}, None)["statusCode"] == 503
        assert app({}, None)["status"] == 503
        emit.assert_not_called()
        db.assert_not_called()
