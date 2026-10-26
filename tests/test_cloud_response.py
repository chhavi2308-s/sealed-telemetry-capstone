import json
from pathlib import Path
from unittest.mock import patch

import boto3
import pytest
from moto import mock_aws

from sealed_telemetry.cloud_lab import issuer
from sealed_telemetry.cloud_response import responder


@pytest.mark.parametrize("status", [200, 403, 500])
@mock_aws
def test_cloud_responder_verified_and_idempotent(monkeypatch, status):
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
    token = issuer({"operation": "issue"}, None)
    finding = {
        "state": "SUSPICIOUS",
        "approved": True,
        "disable_integration": True,
        "decision_id": "decision",
        "credential_fingerprint": token["credential_fingerprint"],
        "run_id": "run",
    }
    with (
        patch(
            "sealed_telemetry.cloud_response.https_json", return_value={"status": status}
        ) as call,
        patch("sealed_telemetry.cloud_response.emit") as emit,
    ):
        assert responder(finding, None)["status"] == ("verified" if status == 403 else "unverified")
        assert responder(finding, None)["status"] == ("verified" if status == 403 else "unverified")
        call.assert_called_once()
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
        == "ApprovalRequired"
    )
