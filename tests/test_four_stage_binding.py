"""C2 offline tests: all SDK requests are intercepted by Moto or fault mocks."""

import base64
import hashlib
import json
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

import boto3
import pytest
from botocore.client import BaseClient
from botocore.exceptions import ClientError, ReadTimeoutError
from moto import mock_aws

from sealed_telemetry import four_stage as demo
from sealed_telemetry import four_stage_binding as binding
from sealed_telemetry.four_stage_evidence import CollectedRecord, normalize
from sealed_telemetry.four_stage_issuance import IssuanceAttestation, verify_attestation_fingerprint
from sealed_telemetry.schema import digest

NOW = 1000
# Public synthetic keys, used only in Moto fixtures; never deploy these keys.
KEY_V1 = bytes(range(32))
KEY_V2 = bytes(range(32, 64))


@pytest.fixture
def lab(monkeypatch):
    with mock_aws():
        monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-south-1")
        monkeypatch.setenv("FOUR_STAGE_EVIDENCE_MODE", "c2")
        db = boto3.resource("dynamodb", region_name="ap-south-1")
        for name, key in (
            ("EXPECTED_TABLE", "action_id"),
            ("TOKEN_TABLE", "token_hash"),
            ("ISSUANCE_TABLE", "issuance_id"),
            ("AUDIT_TABLE", "provider_request_id"),
        ):
            monkeypatch.setenv(name, name)
            db.create_table(
                TableName=name,
                BillingMode="PAY_PER_REQUEST",
                AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}],
                KeySchema=[{"AttributeName": key, "KeyType": "HASH"}],
            )
        secrets = boto3.client("secretsmanager", region_name="ap-south-1")
        identity = {
            "key_version": "v1",
            "key_b64": base64.b64encode(KEY_V2).decode(),
            "subject": "synthetic-oauth-integration",
        }
        credentials = {"active_version": "v1", "keys": {"v1": base64.b64encode(KEY_V1).decode()}}
        secrets.create_secret(Name="fixture-identity", SecretString=json.dumps(identity))
        secrets.create_secret(Name="fixture-credentials", SecretString=json.dumps(credentials))
        monkeypatch.setenv("FOUR_STAGE_IDENTITY_SECRET", "fixture-identity")
        monkeypatch.setenv("FOUR_STAGE_CREDENTIAL_SECRET", "fixture-credentials")
        with patch.object(demo.time, "time", return_value=NOW):
            yield {"db": db, "secrets": secrets, "identity": identity, "credentials": credentials}


def request():
    return {
        "body": json.dumps({"operation": demo.OPERATION, "filename": demo.FILENAME}),
        "requestContext": {
            "authorizer": {
                "iam": {"userArn": "arn:aws:sts::123456789012:assumed-role/fixture/session"}
            }
        },
    }


def authorize(lab):
    with patch.object(
        demo, "call", return_value={"status": "success", "provider_request_id": "fixture"}
    ):
        output = demo.authorization(request(), SimpleNamespace(aws_request_id="gateway-request"))
    assert output["statusCode"] == 200
    body = json.loads(output["body"])
    return {
        key: body[key]
        for key in (
            "action_id",
            "operation",
            "filename",
            "authorized_at",
            "authorization_expires_at",
        )
    }


def rows(lab, name):
    return lab["db"].Table(name).scan()["Items"]


def audit(lab, receipt):
    return (
        lab["db"]
        .Table("AUDIT_TABLE")
        .get_item(Key={"provider_request_id": receipt["provider_request_id"]}, ConsistentRead=True)[
            "Item"
        ]
    )


def test_atomic_issuance_links_private_registry_and_redacted_issuer_record(lab):
    payload = authorize(lab)
    credential = demo.issuer(payload, None)
    assert "access_token" in credential
    registry = rows(lab, "TOKEN_TABLE")
    evidence = rows(lab, "ISSUANCE_TABLE")
    assert len(registry) == 1 and len(evidence) == 2
    private = IssuanceAttestation.parse(registry[0]["private_attestation"])
    assert verify_attestation_fingerprint(private, keyring={"v1": KEY_V1})
    issued = next(row for row in evidence if row["record_kind"] == "issuance_evidence")
    assert issued["attestation"] == private.to_evidence_dict()
    assert issued["source_id"] == "issuer"
    assert issued["attestation"]["issued_at_utc"] == "1970-01-01T00:16:40+00:00"
    assert private.token_id not in json.dumps(evidence, default=str)
    assert credential["access_token"] not in json.dumps(evidence, default=str) + str(registry)
    assert registry[0]["token_hash"] not in json.dumps(evidence, default=str)
    reference = issued["authorization_reference"]
    expected = rows(lab, "EXPECTED_TABLE")[0]
    assert reference["canonical_hash"] == expected["authorization_hash"]
    assert reference["native_id"] == payload["action_id"]
    assert reference["table_arn"] == lab["db"].Table("EXPECTED_TABLE").table_arn


def test_provider_uses_own_bearer_lookup_and_preserves_distinct_replay_receipts(lab):
    payload = authorize(lab)
    credential = demo.issuer(payload, None)
    event = {
        **payload,
        **credential,
        "credential_fingerprint": "a" * 64,
        "fingerprint_key_version": "v999",
        "token_id": str(uuid4()),
        "source_id": "gateway",
    }
    first = demo.saas(event, None)
    second = demo.saas(event, None)
    assert first["status"] == second["status"] == "success"
    a, b = audit(lab, first), audit(lab, second)
    private = IssuanceAttestation.parse(rows(lab, "TOKEN_TABLE")[0]["private_attestation"])
    assert (
        a["credential_fingerprint"] == b["credential_fingerprint"] == private.credential_fingerprint
    )
    assert a["fingerprint_key_version"] == "v1"
    assert a["source_id"] == "provider"
    assert a["provider_request_id"] != b["provider_request_id"]
    assert a["issuance_id"] == b["issuance_id"] == private.issuance_id
    assert "invocation_id" not in a
    assert "does not establish application execution" in a["binding_uncertainty"]


def test_duplicate_issuer_request_never_creates_another_credential(lab):
    payload = authorize(lab)
    assert "access_token" in demo.issuer(payload, None)
    with patch.object(binding.secrets, "token_urlsafe") as mint:
        assert demo.issuer(payload, None) == {"error": "issuance_already_recorded"}
        mint.assert_not_called()
    assert len(rows(lab, "TOKEN_TABLE")) == 1
    assert len(rows(lab, "ISSUANCE_TABLE")) == 2


def test_missing_gateway_authorization_does_not_persist_any_issuance(lab):
    payload = {"action_id": str(uuid4()), "operation": demo.OPERATION, "filename": demo.FILENAME}
    assert demo.issuer(payload, None) == {"error": "not_authorized"}
    assert not rows(lab, "TOKEN_TABLE") and not rows(lab, "ISSUANCE_TABLE")


@pytest.mark.parametrize("value", [None, "", 1, "not-a-uuid"])
def test_invalid_action_requests_never_create_credential_bindings(lab, value):
    result = demo.issuer(
        {"action_id": value, "operation": demo.OPERATION, "filename": demo.FILENAME}, None
    )
    assert result == {"error": "invalid_action"}
    assert not rows(lab, "TOKEN_TABLE") and not rows(lab, "ISSUANCE_TABLE")


@pytest.mark.parametrize(
    "change",
    [
        {"source_id": "app"},
        {"actor_pseudonym": "a" * 64},
        {"resource_pseudonym": "b" * 64},
        {"identity_key_version": "v9"},
        {"authorization_hash": "a" * 64},
        {"event_type": "APP_INTENT"},
        {"authorizing_principal_pseudonym": "0" * 64},
        {"authorization_expires_at": 1000},
        {"authorized_at": 1001},
    ],
)
def test_gateway_snapshot_mismatch_or_closed_window_cannot_issue(lab, change):
    payload = authorize(lab)
    original = rows(lab, "EXPECTED_TABLE")[0]
    lab["db"].Table("EXPECTED_TABLE").put_item(Item={**original, **change})
    assert "access_token" not in demo.issuer(payload, None)
    assert not rows(lab, "TOKEN_TABLE") and not rows(lab, "ISSUANCE_TABLE")


def test_legacy_authorization_cannot_be_upgraded_by_app_claims(lab):
    action_id = str(uuid4())
    legacy = {
        "action_id": action_id,
        "operation": demo.OPERATION,
        "filename": demo.FILENAME,
        "authorized_at": NOW,
        "authorization_expires_at": NOW + 300,
        "event_type": "EXPECTED_ACTION",
        "expires_at": NOW + 86400,
    }
    lab["db"].Table("EXPECTED_TABLE").put_item(Item=legacy)
    result = demo.issuer(
        {**legacy, "actor_pseudonym": "a" * 64, "credential_fingerprint": "b" * 64}, None
    )
    assert "access_token" not in result
    assert not rows(lab, "TOKEN_TABLE")


def test_transaction_rechecks_snapshot_fields_after_independent_read(lab):
    payload = authorize(lab)
    original_api = BaseClient._make_api_call

    def mutate_then_call(client, operation, params):
        if operation == "TransactWriteItems":
            gateway = rows(lab, "EXPECTED_TABLE")[0]
            # Keep the old hash to prove that comparing only the hash would be unsafe.
            lab["db"].Table("EXPECTED_TABLE").put_item(Item={**gateway, "filename": "other.pdf"})
        return original_api(client, operation, params)

    with patch.object(BaseClient, "_make_api_call", new=mutate_then_call):
        assert demo.issuer(payload, None) == {"error": "issuance_not_committed"}
    assert not rows(lab, "TOKEN_TABLE") and not rows(lab, "ISSUANCE_TABLE")


def test_attestation_collision_rolls_back_registry_and_claim(lab):
    payload = authorize(lab)
    token_id, issuance_id = str(uuid4()), str(uuid4())
    lab["db"].Table("ISSUANCE_TABLE").put_item(
        Item={"issuance_id": issuance_id, "keep": "original"}
    )
    with patch.object(binding, "uuid4", side_effect=[token_id, issuance_id]):
        assert demo.issuer(payload, None) == {"error": "issuance_not_committed"}
    assert not rows(lab, "TOKEN_TABLE")
    assert rows(lab, "ISSUANCE_TABLE") == [{"issuance_id": issuance_id, "keep": "original"}]


def test_registry_collision_rolls_back_all_evidence_writes(lab):
    payload = authorize(lab)
    bearer = "synthetic-collision-fixture-only"
    lookup = hashlib.sha256(bearer.encode()).hexdigest()
    lab["db"].Table("TOKEN_TABLE").put_item(Item={"token_hash": lookup, "keep": "original"})
    with patch.object(binding.secrets, "token_urlsafe", return_value=bearer):
        assert demo.issuer(payload, None) == {"error": "issuance_not_committed"}
    assert rows(lab, "TOKEN_TABLE") == [{"token_hash": lookup, "keep": "original"}]
    assert not rows(lab, "ISSUANCE_TABLE")


@pytest.mark.parametrize("commit_first", [False, True])
def test_timeout_preserves_indeterminate_outcome_and_never_returns_bearer(lab, commit_first):
    payload = authorize(lab)
    original_api = BaseClient._make_api_call

    def timeout(client, operation, params):
        if operation == "TransactWriteItems":
            if commit_first:
                original_api(client, operation, params)
            raise ReadTimeoutError(endpoint_url="https://fixture.invalid")
        return original_api(client, operation, params)

    with patch.object(BaseClient, "_make_api_call", new=timeout):
        assert demo.issuer(payload, None) == {"error": "issuance_outcome_unknown"}
    assert len(rows(lab, "TOKEN_TABLE")) == int(commit_first)
    assert len(rows(lab, "ISSUANCE_TABLE")) == 2 * int(commit_first)
    if commit_first:
        assert demo.issuer(payload, None) == {"error": "issuance_already_recorded"}


def test_racing_duplicate_issuance_cannot_commit_twice(lab):
    payload = authorize(lab)
    original_api = BaseClient._make_api_call
    entered = False
    winner = []

    def race(client, operation, params):
        nonlocal entered
        if operation == "TransactWriteItems" and not entered:
            entered = True
            winner.append(demo.issuer(payload, None))
        return original_api(client, operation, params)

    with patch.object(BaseClient, "_make_api_call", new=race):
        assert demo.issuer(payload, None) == {"error": "issuance_already_recorded"}
    assert "access_token" in winner[0]
    assert len(rows(lab, "TOKEN_TABLE")) == 1 and len(rows(lab, "ISSUANCE_TABLE")) == 2


@pytest.mark.parametrize("presented", [None, "", "unknown-credential-fixture", 123, "x" * 257])
def test_unknown_or_malformed_credentials_are_denied_and_unbound(lab, presented):
    payload = authorize(lab)
    event = {
        **payload,
        "access_token": presented,
        "credential_fingerprint": "a" * 64,
        "fingerprint_key_version": "v1",
    }
    result = demo.saas(event, None)
    record = audit(lab, result)
    assert result["status"] == "denied" and record["reason_code"] == "unknown_credential"
    for field in (
        "credential_fingerprint",
        "fingerprint_key_version",
        "issuance_id",
        "authorized_action_id",
        "actor_pseudonym",
        "authorization_reference",
    ):
        assert record[field] is None


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"action_id": str(uuid4())}, "action_mismatch"),
        ({"operation": "records:export"}, "operation_mismatch"),
        ({"filename": "private-request-value"}, "resource_mismatch"),
    ],
)
def test_denied_attempts_preserve_known_binding_without_rewriting_request(lab, change, reason):
    payload = authorize(lab)
    credential = demo.issuer(payload, None)
    result = demo.saas({**payload, **credential, **change}, None)
    record = audit(lab, result)
    assert result["status"] == "denied" and record["reason_code"] == reason
    assert record["credential_fingerprint"] is not None
    assert record["authorized_action_id"] == payload["action_id"]
    if reason == "action_mismatch":
        assert (
            record["requested_action_id"] == change["action_id"] != record["authorized_action_id"]
        )
    assert "private-request-value" not in json.dumps(record, default=str)


@pytest.mark.parametrize("state", ["expired", "revoked", "not_yet_valid"])
def test_known_denied_credentials_do_not_become_successful_evidence(lab, state):
    payload = authorize(lab)
    credential = demo.issuer(payload, None)
    moment = NOW + 300 if state == "expired" else NOW - 1 if state == "not_yet_valid" else NOW
    if state == "revoked":
        row = rows(lab, "TOKEN_TABLE")[0]
        lab["db"].Table("TOKEN_TABLE").put_item(Item={**row, "revoked": True})
    with patch.object(demo.time, "time", return_value=moment):
        record = audit(lab, demo.saas({**payload, **credential}, None))
    assert record["outcome"] == "denied" and record["reason_code"] == state
    assert record["credential_fingerprint"] is not None


def test_rotation_keeps_existing_credential_version_and_provider_needs_no_secret(lab):
    first_action = authorize(lab)
    first = demo.issuer(first_action, None)
    rotated = {"active_version": "v2", "keys": {"v2": base64.b64encode(KEY_V2).decode()}}
    lab["secrets"].put_secret_value(
        SecretId="fixture-credentials", SecretString=json.dumps(rotated)
    )
    second_action = authorize(lab)
    second = demo.issuer(second_action, None)
    with patch.object(
        binding, "_secret", side_effect=AssertionError("provider must not read HMAC keys")
    ):
        a = audit(lab, demo.saas({**first_action, **first}, None))
        b = audit(lab, demo.saas({**second_action, **second}, None))
    assert a["fingerprint_key_version"] == "v1" and b["fingerprint_key_version"] == "v2"
    assert a["credential_fingerprint"] != b["credential_fingerprint"]
    assert a["outcome"] == b["outcome"] == "success"
    for row in rows(lab, "TOKEN_TABLE"):
        private = IssuanceAttestation.parse(row["private_attestation"])
        assert verify_attestation_fingerprint(private, keyring={"v1": KEY_V1, "v2": KEY_V2})


@pytest.mark.parametrize(
    "value",
    [
        {"active_version": "v9", "keys": {"v1": base64.b64encode(KEY_V1).decode()}},
        {"active_version": "v1", "keys": {"v1": base64.b64encode(b"short").decode()}},
        {"active_version": "v1", "keys": {"v1": "not-base64!!"}},
    ],
)
def test_invalid_key_configuration_fails_closed_without_fallback(lab, value):
    payload = authorize(lab)
    lab["secrets"].put_secret_value(SecretId="fixture-credentials", SecretString=json.dumps(value))
    assert demo.issuer(payload, None) == {"error": "evidence_configuration_unavailable"}
    assert not rows(lab, "TOKEN_TABLE") and not rows(lab, "ISSUANCE_TABLE")


def test_gateway_configuration_failure_happens_before_writes_or_app_invocation(lab):
    lab["secrets"].put_secret_value(SecretId="fixture-identity", SecretString="invalid-json")
    with patch.object(demo, "call") as invoke:
        assert demo.authorization(request(), None)["statusCode"] == 503
        invoke.assert_not_called()
    assert not rows(lab, "EXPECTED_TABLE")


def test_failed_audit_never_returns_success_and_redacts_sdk_error(lab, caplog):
    payload = authorize(lab)
    credential = demo.issuer(payload, None)
    original_api = BaseClient._make_api_call
    private_fixture = "private-failure-value"

    def failure(client, operation, params):
        if operation == "PutItem" and params.get("TableName") == "AUDIT_TABLE":
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": private_fixture}}, operation
            )
        return original_api(client, operation, params)

    with patch.object(BaseClient, "_make_api_call", new=failure):
        result = demo.saas({**payload, **credential}, None)
    assert result == {"status": "unavailable", "error": "provider_evidence_unavailable"}
    assert private_fixture not in json.dumps(result) + caplog.text
    assert not rows(lab, "AUDIT_TABLE")


def test_corrupt_or_legacy_registry_never_invents_binding_or_leaks_unknown_fields(lab):
    payload = authorize(lab)
    credential = demo.issuer(payload, None)
    row = rows(lab, "TOKEN_TABLE")[0]
    reference = {**row["authorization_reference"], "unexpected": "private-ref-value"}
    lab["db"].Table("TOKEN_TABLE").put_item(Item={**row, "authorization_reference": reference})
    record = audit(lab, demo.saas({**payload, **credential}, None))
    assert record["outcome"] == "denied" and record["credential_fingerprint"] is None
    assert record["authorization_reference"] is None
    assert "private-ref-value" not in json.dumps(record, default=str)


def test_full_suppressed_intent_flow_and_export_privacy(lab, monkeypatch, caplog):
    monkeypatch.setenv("FOUR_STAGE_LAB_ENABLED", "true")
    private_bearer = "private-synthetic-bearer-fixture-only"
    private_id = str(uuid4())

    def dispatch(name, payload):
        if name == "APP_FUNCTION":
            return demo.app(
                {**payload, "suppress_app_intent": True},
                SimpleNamespace(aws_request_id="app-request"),
            )
        if name == "ISSUER_FUNCTION":
            with patch.object(binding, "uuid4", side_effect=[private_id, uuid4()]):
                return demo.issuer(payload, None)
        return demo.saas(payload, None)

    with (
        patch.object(demo, "call", side_effect=dispatch),
        patch.object(binding.secrets, "token_urlsafe", return_value=private_bearer),
    ):
        response = demo.authorization(request(), SimpleNamespace(aws_request_id="gateway-request"))
    assert response["statusCode"] == 200
    public = (
        json.dumps(response)
        + json.dumps(rows(lab, "ISSUANCE_TABLE"), default=str)
        + json.dumps(rows(lab, "AUDIT_TABLE"), default=str)
        + caplog.text
    )
    registry = rows(lab, "TOKEN_TABLE")[0]
    for private in (
        private_bearer,
        private_id,
        registry["token_hash"],
        base64.b64encode(KEY_V1).decode(),
    ):
        assert private not in public
    assert "APP_INTENT" not in caplog.text
    assert "invocation_id" not in json.dumps(rows(lab, "AUDIT_TABLE"), default=str)


def test_phase_b_parser_rejects_new_records_instead_of_silently_upgrading_them(lab):
    payload = authorize(lab)
    credential = demo.issuer(payload, None)
    record = audit(lab, demo.saas({**payload, **credential}, None))
    source_arn = lab["db"].Table("AUDIT_TABLE").table_arn
    result = normalize(
        [
            CollectedRecord(
                source_arn, record["provider_request_id"], "1970-01-01T00:16:40+00:00", record
            )
        ],
        {source_arn: "provider"},
    )
    assert not result.observations and result.issues[0].reason_code == "INVALID_SOURCE_RECORD"


def test_expiry_is_resampled_after_slow_configuration_or_registry_work(lab):
    payload = authorize(lab)
    original_persist = binding._persist

    def delayed(*args):
        with patch.object(demo.time, "time", return_value=NOW + 300):
            return original_persist(*args)

    with patch.object(binding, "_persist", side_effect=delayed):
        assert demo.issuer(payload, None) == {"error": "authorization_expired_or_not_yet_valid"}
    assert not rows(lab, "TOKEN_TABLE") and not rows(lab, "ISSUANCE_TABLE")


def test_full_normal_flow_keeps_gateway_context_distinct_from_app_claim(lab, caplog):
    def dispatch(name, payload):
        if name == "APP_FUNCTION":
            return demo.app(payload, SimpleNamespace(aws_request_id="app-request"))
        return {"ISSUER_FUNCTION": demo.issuer, "SAAS_FUNCTION": demo.saas}[name](payload, None)

    with patch.object(demo, "call", side_effect=dispatch), caplog.at_level("INFO"):
        output = demo.authorization(request(), SimpleNamespace(aws_request_id="gateway-request"))
    assert output["statusCode"] == 200
    intent = next(
        json.loads(r.getMessage()) for r in caplog.records if "APP_INTENT" in r.getMessage()
    )
    assert intent["invocation_id"] == "app-request"
    assert rows(lab, "EXPECTED_TABLE")[0]["gateway_request_id"] == "gateway-request"
    assert "invocation_id" not in rows(lab, "AUDIT_TABLE")[0]
    for row in rows(lab, "TOKEN_TABLE"):
        assert row["private_attestation"]["token_id"] not in caplog.text
        assert row["token_hash"] not in caplog.text
        assert row["private_attestation"]["credential_fingerprint"] not in caplog.text


def test_changed_authorization_revision_conflicts_with_existing_issuance_claim(lab):
    payload = authorize(lab)
    assert "access_token" in demo.issuer(payload, None)
    snapshot = rows(lab, "EXPECTED_TABLE")[0]
    snapshot.pop("authorization_hash")
    for key in ("authorized_at", "authorization_expires_at", "expires_at"):
        snapshot[key] = int(snapshot[key])
    snapshot["authorization_revision"] = str(uuid4())
    lab["db"].Table("EXPECTED_TABLE").put_item(
        Item={**snapshot, "authorization_hash": digest(snapshot)}
    )
    assert demo.issuer(payload, None) == {"error": "issuance_conflict"}
    assert len(rows(lab, "TOKEN_TABLE")) == 1 and len(rows(lab, "ISSUANCE_TABLE")) == 2


def test_c2_app_rejects_legacy_issuer_response_before_provider_call(lab):
    payload = authorize(lab)
    with patch.object(
        demo, "call", return_value={"access_token": "synthetic-private-fixture"}
    ) as call:
        assert demo.app(payload, None) == {"status": "unavailable"}
    assert [args.args[0] for args in call.call_args_list] == ["ISSUER_FUNCTION"]


def test_invalid_mode_never_falls_back_or_calls_services(lab, monkeypatch):
    monkeypatch.setenv("FOUR_STAGE_EVIDENCE_MODE", "typo")
    with patch.object(demo, "call") as invoke, patch.object(demo, "emit_intent") as emit:
        with pytest.raises(ValueError, match="unsupported four-stage evidence mode"):
            demo.app({}, None)
        invoke.assert_not_called()
        emit.assert_not_called()


def test_registry_read_failure_is_unavailable_instead_of_a_false_unknown_credential(lab):
    payload = authorize(lab)
    credential = demo.issuer(payload, None)
    original_api = BaseClient._make_api_call

    def read_failure(client, operation, params):
        if operation == "GetItem" and params.get("TableName") == "TOKEN_TABLE":
            raise ReadTimeoutError(endpoint_url="https://fixture.invalid")
        return original_api(client, operation, params)

    with patch.object(BaseClient, "_make_api_call", new=read_failure):
        result = demo.saas({**payload, **credential}, None)
    assert result == {"status": "unavailable", "error": "provider_evidence_unavailable"}
    assert not rows(lab, "AUDIT_TABLE")


@pytest.mark.parametrize("flag", [None, "false", 0])
def test_unknown_revocation_state_is_not_reported_as_observed_revocation(lab, flag):
    payload = authorize(lab)
    credential = demo.issuer(payload, None)
    row = rows(lab, "TOKEN_TABLE")[0]
    if flag is None:
        row.pop("revoked")
    else:
        row["revoked"] = flag
    lab["db"].Table("TOKEN_TABLE").put_item(Item=row)
    record = audit(lab, demo.saas({**payload, **credential}, None))
    assert record["reason_code"] == "unverifiable_registry_record"
    assert record["outcome"] == "denied" and record["credential_fingerprint"] is None


def test_slow_provider_lookup_resamples_clock_and_keeps_original_receive_time(lab):
    payload = authorize(lab)
    credential = demo.issuer(payload, None)
    clock = [NOW]
    original_api = BaseClient._make_api_call

    def slow_lookup(client, operation, params):
        result = original_api(client, operation, params)
        if operation == "GetItem" and params.get("TableName") == "TOKEN_TABLE":
            clock[0] = NOW + 300
        return result

    with (
        patch.object(demo.time, "time", side_effect=lambda: clock[0]),
        patch.object(BaseClient, "_make_api_call", new=slow_lookup),
    ):
        record = audit(lab, demo.saas({**payload, **credential}, None))
    assert record["outcome"] == "denied" and record["reason_code"] == "expired"
    assert record["request_received_at_utc"] == "1970-01-01T00:16:40+00:00"
    assert record["event_time_utc"] == "1970-01-01T00:21:40+00:00"


def test_issuance_time_is_sampled_after_key_loading_without_changing_authorization_time(lab):
    payload = authorize(lab)
    clock = [NOW]
    original_key = binding._credential_key

    def delayed_key():
        result = original_key()
        clock[0] = NOW + 1
        return result

    with (
        patch.object(demo.time, "time", side_effect=lambda: clock[0]),
        patch.object(binding, "_credential_key", side_effect=delayed_key),
    ):
        assert "access_token" in demo.issuer(payload, None)
    evidence = next(
        row for row in rows(lab, "ISSUANCE_TABLE") if row["record_kind"] == "issuance_evidence"
    )
    assert evidence["request_received_at_utc"] == "1970-01-01T00:16:40+00:00"
    assert evidence["attestation"]["issued_at_utc"] == "1970-01-01T00:16:41+00:00"
    assert evidence["authorization_reference"]["authorized_at_utc"] == "1970-01-01T00:16:40+00:00"
