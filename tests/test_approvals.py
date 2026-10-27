"""Approval tokens stay encrypted; authorization is bound to the exact reviewed action."""

import json
from unittest.mock import patch

import boto3
import pytest
from moto import mock_aws

from sealed_telemetry.approvals import api, broker, verify_proof


@pytest.fixture
def approval_store(monkeypatch):
    with mock_aws():
        monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
        monkeypatch.setenv("APPROVAL_TABLE", "approvals")
        monkeypatch.setenv("OPERATOR_PRINCIPAL", "arn:aws:iam::123456789012:role/operator")
        key = boto3.client("kms").create_key()["KeyMetadata"]["KeyId"]
        monkeypatch.setenv("APPROVAL_KEY", key)
        boto3.client("dynamodb").create_table(
            TableName="approvals",
            BillingMode="PAY_PER_REQUEST",
            KeySchema=[{"AttributeName": "approval_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "approval_id", "AttributeType": "S"}],
        )
        finding = {
            "decision_id": "decision",
            "run_id": "run",
            "state": "SUSPICIOUS",
            "credential_fingerprint": "a" * 64,
        }
        approval_id = broker(
            {
                "finding": finding,
                "task_token": "secret-callback-token",
                "execution_arn": "arn:aws:states:us-east-1:123456789012:execution:lab:test",
            },
            None,
        )["approval_id"]
        event = {
            "httpMethod": "POST",
            "pathParameters": {"approval_id": approval_id},
            "requestContext": {
                "identity": {"userArn": "arn:aws:sts::123456789012:assumed-role/operator/session"}
            },
            "body": json.dumps({"approved": True, "disable_integration": True}),
        }
        yield finding, event


def test_callback_proof_and_no_task_token_disclosure(approval_store):
    finding, event = approval_store
    original = boto3.client
    with (
        patch("sealed_telemetry.approvals.boto3.client", wraps=boto3.client) as client,
        patch("sealed_telemetry.approvals.emit") as emit,
    ):
        from unittest.mock import MagicMock

        sfn = MagicMock()
        client.side_effect = lambda name, **kw: (
            sfn if name == "stepfunctions" else original(name, **kw)
        )
        assert api(event, None)["statusCode"] == 200
        assert api(event, None)["statusCode"] == 200
        sfn.send_task_success.assert_called_once()
        assert emit.call_args_list[0].args[0] == emit.call_args_list[1].args[0]
        proof = json.loads(sfn.send_task_success.call_args.kwargs["output"])
        verify_proof({**finding, **proof})
        with pytest.raises(ValueError, match="proof"):
            verify_proof({**finding, **proof, "disable_integration": False})
    result = api({**event, "httpMethod": "GET"}, None)
    assert "secret-callback-token" not in result["body"]
    assert "encrypted_token" not in result["body"]
    assert "token_hash" not in result["body"]


def test_operator_identity_and_boolean_required(approval_store):
    _, event = approval_store
    assert api({**event, "requestContext": {}}, None)["statusCode"] == 403
    assert api({**event, "body": '{"approved":"true"}'}, None)["statusCode"] == 400
    with pytest.raises((ValueError, KeyError)):
        verify_proof({"approved": True, "approval_id": "invented"})
