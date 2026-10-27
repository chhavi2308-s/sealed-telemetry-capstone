import json
from pathlib import Path
from unittest.mock import patch

import boto3
import pytest
from moto import mock_aws

from sealed_telemetry.approvals import action_fields
from sealed_telemetry.cloud_lab import issuer
from sealed_telemetry.cloud_response import responder
from sealed_telemetry.schema import digest, timestamp, utcnow


@pytest.mark.parametrize("reason", ["revoked", "gateway_forbidden"])
@pytest.mark.parametrize("scope", ["records:read", "records:export"])
@pytest.mark.parametrize("status", [200, 403, 500])
@mock_aws
def test_cloud_responder_verified_and_idempotent(monkeypatch, status, scope, reason):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("TOKEN_TABLE", "tokens")
    monkeypatch.setenv("RESPONSE_TABLE", "responses")
    monkeypatch.setenv("PSEUDONYM_SECRET", "hmac")
    monkeypatch.setenv("SAAS_URL", "https://synthetic.example/records")
    key = boto3.client("kms").create_key()["KeyMetadata"]["KeyId"]
    monkeypatch.setenv("CREDENTIAL_KEY", key)
    boto3.client("secretsmanager").create_secret(Name="hmac", SecretString="x" * 64)
    boto3.client("dynamodb").create_table(
        TableName="tokens",
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "token_hash", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "token_hash", "AttributeType": "S"},
            {"AttributeName": "credential_fingerprint", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "CredentialIndex",
                "KeySchema": [{"AttributeName": "credential_fingerprint", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
    )
    boto3.client("dynamodb").create_table(
        TableName="responses",
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "response_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "response_id", "AttributeType": "S"}],
    )
    monkeypatch.setenv("APPROVAL_TABLE", "approvals")
    monkeypatch.setenv("RESPONSE_HISTORY_TABLE", "history")
    for name, pk, sk in [("approvals", "approval_id", None), ("history", "response_id", "attempt")]:
        keys = [{"AttributeName": pk, "KeyType": "HASH"}]
        attrs = [{"AttributeName": pk, "AttributeType": "S"}]
        if sk:
            keys.append({"AttributeName": sk, "KeyType": "RANGE"})
            attrs.append({"AttributeName": sk, "AttributeType": "N"})
        boto3.client("dynamodb").create_table(
            TableName=name,
            BillingMode="PAY_PER_REQUEST",
            KeySchema=keys,
            AttributeDefinitions=attrs,
        )
    token = issuer({"operation": "issue", "scope": scope}, None)
    finding = {
        "approval_id": "approval",
        "approved_by": "operator",
        "state": "SUSPICIOUS",
        "approved": True,
        "disable_integration": True,
        "decision_id": "decision",
        "credential_fingerprint": token["credential_fingerprint"],
        "run_id": "run",
    }
    boto3.resource("dynamodb").Table("approvals").put_item(
        Item={
            "approval_id": "approval",
            "approved_by": "operator",
            "approved": True,
            "status": "approved",
            "request_hash": digest(action_fields(finding)),
            "authorized_until": int(timestamp(utcnow()).timestamp()) + 900,
        }
    )
    with (
        patch(
            "sealed_telemetry.cloud_response.https_json",
            return_value={
                "status": status,
                "body": {
                    "error": "invalid_token",
                    "reason": reason,
                    "provider_request_id": "provider-1",
                },
            },
        ) as call,
        patch("sealed_telemetry.cloud_response.emit") as emit,
    ):
        assert responder(finding, None)["status"] == (
            "verified" if status == 403 and reason == "revoked" else "unverified"
        )
        assert responder(finding, None)["status"] == (
            "verified" if status == 403 and reason == "revoked" else "unverified"
        )
        assert call.call_count == (2 if status == 500 else 1)
        assert call.call_args.args[0].endswith(
            "/export" if scope == "records:export" else "/records"
        )
        if status != 500:
            assert emit.call_args_list[0].args[0] == emit.call_args_list[1].args[0]
        assert token["access_token"] not in json.dumps(responder(finding, None))
    assert boto3.resource("dynamodb").Table("responses").scan()["Count"] == 1
    assert (
        not boto3.resource("dynamodb")
        .Table("tokens")
        .get_item(Key={"token_hash": "integration:enabled"})["Item"]["enabled"]
    )


def test_cloud_responder_without_approval():
    assert responder({}, None)["status"] == "approval_required"


def test_infrastructure_security_contract():
    t = json.loads((Path(__file__).parent.parent / "infra/template.yaml").read_text())
    r = t["Resources"]
    assert r["IntakeApi"]["Properties"]["Auth"]["DefaultAuthorizer"] == "AWS_IAM"
    app_permissions = r["AppPolicy"]["Properties"]["PolicyDocument"]["Statement"]
    assert all(s["Action"] == ["execute-api:Invoke"] for s in app_permissions)
    assert r["Archive"]["DeletionPolicy"] == "Retain"
    assert r["Archive"]["Properties"]["ObjectLockEnabled"]
    assert r["EvidenceQueue"]["Properties"]["VisibilityTimeout"] >= 6 * 25
    assert (
        r["ResponseWorkflow"]["Properties"]["Definition"]["States"]["ApprovalGate"]["Default"]
        == "Rejected"
    )
