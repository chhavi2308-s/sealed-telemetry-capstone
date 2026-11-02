"""Local-only tests: AWS calls intercepted by moto; Lambda transport stubbed."""

import json
from pathlib import Path
from unittest.mock import patch

import boto3
import pytest
from moto import mock_aws

from sealed_telemetry import four_stage as demo


@pytest.fixture
def lab(monkeypatch):
    with mock_aws():
        monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-south-1")
        for env, key in [
            ("EXPECTED_TABLE", "action_id"),
            ("TOKEN_TABLE", "token_hash"),
            ("AUDIT_TABLE", "provider_request_id"),
        ]:
            monkeypatch.setenv(env, env)
            boto3.client("dynamodb").create_table(
                TableName=env,
                BillingMode="PAY_PER_REQUEST",
                AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}],
                KeySchema=[{"AttributeName": key, "KeyType": "HASH"}],
            )
        yield


def request(body=None):
    return {
        "body": json.dumps(
            body
            if body is not None
            else {"operation": "files:upload", "filename": "invoice_101.pdf"}
        ),
        "requestContext": {
            "authorizer": {
                "iam": {"userArn": "arn:aws:sts::123456789012:assumed-role/test/session"}
            }
        },
    }


def test_four_stage_success_and_no_token_output(lab, caplog):
    calls = []

    def invoke(name, payload):
        calls.append(name)
        if name == "APP_FUNCTION":
            row = demo.table("EXPECTED_TABLE").get_item(Key={"action_id": payload["action_id"]})
            assert row["Item"]["event_type"] == "EXPECTED_ACTION"
        return {
            "APP_FUNCTION": demo.app,
            "ISSUER_FUNCTION": demo.issuer,
            "SAAS_FUNCTION": demo.saas,
        }[name](payload, None)

    with (
        patch.object(demo, "call", side_effect=invoke),
        patch.object(demo.secrets, "token_urlsafe", return_value="synthetic-token-never-log-this"),
    ):
        result = demo.authorization(request(), None)
    assert result["statusCode"] == 200
    output = json.loads(result["body"])
    expected = demo.table("EXPECTED_TABLE").get_item(Key={"action_id": output["action_id"]})["Item"]
    audit = demo.table("AUDIT_TABLE").get_item(
        Key={"provider_request_id": output["provider_request_id"]}
    )["Item"]
    assert audit["outcome"] == "success"
    assert audit["synthetic"] is True
    for key in ("action_id", "operation", "filename"):
        assert audit[key] == expected[key] == output[key]
    assert calls == ["APP_FUNCTION", "ISSUER_FUNCTION", "SAAS_FUNCTION"]
    tokens = demo.table("TOKEN_TABLE").scan()["Items"]
    assert (
        "synthetic-token-never-log-this"
        not in json.dumps(result) + str(tokens) + str(audit) + caplog.text
    )
    assert tokens[0]["expires_at"] - expected["authorized_at"] <= 300


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"operation": "files:upload", "filename": "private.pdf"},
        {"operation": "files:upload", "filename": "invoice_101.pdf", "expose_test_token": True},
    ],
)
def test_rejects_unapproved_actions_before_writes(lab, body):
    with patch.object(demo, "call") as invoke:
        assert demo.authorization(request(body), None)["statusCode"] == 400
        invoke.assert_not_called()
    assert demo.table("EXPECTED_TABLE").scan()["Count"] == 0


def test_requires_iam_context_and_valid_body(lab):
    assert demo.authorization({"body": "{}"}, None)["statusCode"] == 400
    event = request()
    event.pop("requestContext")
    assert demo.authorization(event, None)["statusCode"] == 403
    event["body"] = "not-json"
    assert demo.authorization(event, None)["statusCode"] == 400


def test_issuer_requires_matching_live_authorization(lab):
    payload = {"action_id": "test", "operation": "files:upload", "filename": "invoice_101.pdf"}
    assert demo.issuer(payload, None)["error"] == "not_authorized"
    demo.table("EXPECTED_TABLE").put_item(Item={**payload, "authorization_expires_at": 101})
    with patch.object(demo.time, "time", return_value=100):
        assert demo.issuer({**payload, "filename": "other.pdf"}, None)["error"] == "not_authorized"
        token = demo.issuer(payload, None)["access_token"]
        assert demo.saas({**payload, "access_token": token}, None)["status"] == "success"
        assert (
            demo.saas({**payload, "access_token": token, "action_id": "other"}, None)["status"]
            == "denied"
        )
    with patch.object(demo.time, "time", return_value=101):
        assert demo.issuer(payload, None)["error"] == "authorization_expired"
        assert demo.saas({**payload, "access_token": token}, None)["status"] == "denied"
    assert demo.table("AUDIT_TABLE").scan()["Count"] == 3


def test_failed_audit_never_returns_success(lab):
    with patch.object(demo, "table") as db:
        db.return_value.get_item.return_value = {}
        db.return_value.put_item.side_effect = RuntimeError("storage unavailable")
        with pytest.raises(RuntimeError, match="storage unavailable"):
            demo.saas({"action_id": "test"}, None)


def test_failed_expected_write_does_not_invoke_application(lab):
    with patch.object(demo, "table") as db, patch.object(demo, "call") as invoke:
        db.return_value.put_item.side_effect = RuntimeError("storage unavailable")
        with pytest.raises(RuntimeError):
            demo.authorization(request(), None)
        invoke.assert_not_called()


def test_minimal_template_is_isolated_and_iam_authenticated():
    template = json.loads(Path("infra/four-stage.yaml").read_text())
    resources = template["Resources"]
    assert {r["Type"] for r in resources.values()} == {
        "AWS::Serverless::HttpApi",
        "AWS::Serverless::Function",
        "AWS::IAM::Role",
        "AWS::DynamoDB::Table",
        "AWS::Logs::LogGroup",
    }
    assert len(resources) == 16
    assert resources["UploadApi"]["Properties"]["Auth"]["DefaultAuthorizer"] == "AWS_IAM"
    functions = [r for r in resources.values() if r["Type"] == "AWS::Serverless::Function"]
    assert len(functions) == 4
    assert sum("Events" in f["Properties"] for f in functions) == 1
    for resource in resources.values():
        if resource["Type"] == "AWS::IAM::Role":
            for policy in resource["Properties"]["Policies"]:
                for statement in policy["PolicyDocument"]["Statement"]:
                    assert statement["Resource"] != "*"
                    assert all("*" not in action for action in statement["Action"])


def test_client_rejects_mismatched_or_denied_audit():
    from scripts.four_stage_demo import verify

    output = {
        "action_id": "a",
        "provider_request_id": "p",
        "operation": "files:upload",
        "filename": "invoice_101.pdf",
    }
    expected = {**output, "event_type": "EXPECTED_ACTION"}
    audit = {**output, "event_type": "PROVIDER_ACTION", "outcome": "success", "synthetic": True}
    assert verify(expected, audit, output)
    assert not verify(expected, {**audit, "filename": "other.pdf"}, output)
    assert not verify(expected, {**audit, "outcome": "denied"}, output)
    assert not verify(None, audit, output)


def test_demo_http_timeout_is_explicit(monkeypatch):
    from unittest.mock import MagicMock

    from scripts import four_stage_demo as client

    session = MagicMock()
    session.client.return_value.get_caller_identity.return_value = {
        "Account": "123456789012",
        "Arn": "arn:aws:sts::123456789012:assumed-role/demo/test",
    }
    session.client.return_value.describe_stacks.return_value = {
        "Stacks": [
            {
                "Outputs": [
                    {
                        "OutputKey": "UploadUrl",
                        "OutputValue": "https://demo.execute-api.ap-south-1.amazonaws.com/demo/upload",
                    }
                ]
            }
        ]
    }
    opener = MagicMock()
    opener.open.side_effect = TimeoutError("synthetic timeout")
    monkeypatch.setattr(
        "sys.argv",
        [
            "four_stage_demo.py",
            "--profile",
            "fake",
            "--account",
            "123456789012",
            "--execute-approved",
        ],
    )
    with (
        patch.object(client.boto3, "Session", return_value=session),
        patch.object(client, "SigV4Auth"),
        patch.object(client, "build_opener", return_value=opener),
    ):
        with pytest.raises(TimeoutError):
            client.main()
    assert opener.open.call_args.kwargs["timeout"] == 35
