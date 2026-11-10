"""Offline C4 producer, independent observation and unchanged-engine boundary tests."""

import base64
import json
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import uuid4

import boto3
import pytest
from botocore.exceptions import ClientError
from test_four_stage_binding import lab as lab
from test_four_stage_binding import request
from test_four_stage_collection import collection as collection
from test_four_stage_collection import config, state_rows

from sealed_telemetry import four_stage as demo
from sealed_telemetry import four_stage_c4_iber, four_stage_health
from sealed_telemetry.four_stage_c3_schema import InvalidRecord, normalize, plain
from sealed_telemetry.four_stage_collection import CollectionError, Collector, Source
from sealed_telemetry.schema import timestamp

NOW = "1970-01-01T00:16:41+00:00"


@pytest.fixture
def c4(collection, monkeypatch):
    monkeypatch.setenv("FOUR_STAGE_CONTEXT_MODE", "c4")
    boto3.client("secretsmanager").create_secret(
        Name="fixture-context",
        SecretString=json.dumps(
            {
                "active_version": "v1",
                "keys": {"v1": base64.b64encode(bytes(range(64, 96))).decode()},
            }
        ),
    )
    monkeypatch.setenv("C4_CONTEXT_SECRET", "fixture-context")
    conf = config(collection)
    db = collection["lab"]["db"]
    sources = list(conf.sources)
    for role, variable, key in (
        ("gateway", "C4_GATEWAY_TABLE", "record_id"),
        ("app", "C4_APP_TABLE", "record_id"),
        ("provider", "C4_PROVIDER_TABLE", "provider_request_id"),
        ("health", "C4_HEALTH_TABLE", "event_id"),
    ):
        db.create_table(
            TableName=variable,
            BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}],
            KeySchema=[{"AttributeName": key, "KeyType": "HASH"}],
        )
        monkeypatch.setenv(variable, variable)
        sources.append(Source(role, "c4", db.Table(variable).table_arn, key))
    functions = tuple(
        (role, "arn:aws:lambda:ap-south-1:123456789012:function:c4-" + role)
        for role in ("gateway", "app", "provider", "collector")
    )
    conf = replace(conf, sources=tuple(sources), health_functions=functions)
    ids = {role: str(uuid4()) for role in ("gateway", "app", "provider")}
    return {**collection, "config": conf, "ids": ids, "db": db}


def flow(c4, event=None):
    def route(function, payload):
        if function == "APP_FUNCTION":
            return demo.app(payload, SimpleNamespace(aws_request_id=c4["ids"]["app"]))
        if function == "ISSUER_FUNCTION":
            return demo.issuer(payload, None)
        assert function == "SAAS_FUNCTION"
        return demo.saas(payload, SimpleNamespace(aws_request_id=c4["ids"]["provider"]))

    event = event or request()
    event["requestContext"]["requestId"] = "actual-api-gateway-id="
    with patch.object(demo, "call", side_effect=route):
        return demo.authorization(event, SimpleNamespace(aws_request_id=c4["ids"]["gateway"]))


def health(c4, change=None):
    session = MagicMock()
    functions = dict(c4["config"].health_functions)
    lambdas, metrics = MagicMock(), MagicMock()
    session.client.side_effect = lambda service, **kwargs: (
        lambdas if service == "lambda" else metrics
    )
    lambdas.get_function_configuration.side_effect = lambda **kwargs: {
        "FunctionArn": kwargs["FunctionName"],
        "State": "Active",
        "LastUpdateStatus": "Successful",
    }
    metrics.get_metric_statistics.side_effect = lambda **kwargs: {
        "Datapoints": [
            {
                "Timestamp": timestamp("1970-01-01T00:16:40+00:00"),
                "Sum": 1 if kwargs["MetricName"] == "Invocations" else 0,
            }
        ]
    }
    records = four_stage_health.observe(functions, NOW, session)
    for record in records:
        if change:
            change(record)
        c4["db"].Table("C4_HEALTH_TABLE").put_item(Item=record)
    return records, session


def source_rows(c4, name):
    return plain(c4["db"].Table(name).scan()["Items"])


def test_real_runtime_identities_are_distinct_and_complete_evidence_enters_unchanged_iber(c4):
    assert flow(c4)["statusCode"] == 200
    health(c4)
    with patch.object(
        four_stage_c4_iber, "reconcile", wraps=four_stage_c4_iber.reconcile
    ) as engine:
        result = Collector(c4["config"], c4["session"]).reconcile(NOW)
    assert result["ready"], result["blockers"]
    assert result["submitted_count"] == 3
    assert result["decisions"][0]["state"] == "CONSISTENT"
    assert {e.invocation_id for e in engine.call_args.args[0]} == {c4["ids"]["app"]}
    gateway = next(
        r
        for r in source_rows(c4, "C4_GATEWAY_TABLE")
        if r["record_kind"] == "authorization_context"
    )
    assert gateway["api_gateway_request_id"] == "actual-api-gateway-id="
    assert gateway["gateway_lambda_invocation_id"] == c4["ids"]["gateway"]
    provider = next(
        r for r in source_rows(c4, "C4_PROVIDER_TABLE") if r["record_kind"] == "provider_context"
    )
    assert provider["provider_lambda_invocation_id"] == c4["ids"]["provider"]
    assert provider["provider_request_id"] != c4["ids"]["provider"]
    assert len(result["admission_manifest"]) == 3
    assert not result["coverage_complete"] and not result["application_execution_proven"]


@pytest.mark.parametrize(
    "missing", ["C4_APP_TABLE", "C4_PROVIDER_TABLE", "C4_GATEWAY_TABLE", "C4_HEALTH_TABLE"]
)
def test_missing_or_delayed_records_are_retained_and_reconciled_on_later_batch(c4, missing):
    flow(c4)
    health(c4)
    target = c4["db"].Table(missing)
    key = target.key_schema[0]["AttributeName"]
    records = source_rows(c4, missing)
    for record in records:
        target.delete_item(Key={key: record[key]})
    first = Collector(c4["config"], c4["session"]).reconcile(NOW)
    assert not first["ready"] and first["submitted_count"] == 0
    for record in records:
        target.put_item(Item=record)
    second = Collector(c4["config"], c4["session"]).reconcile(NOW)
    assert second["ready"], second["blockers"]
    assert source_rows(c4, missing) == records


@pytest.mark.parametrize(
    "kind,field,value",
    [
        ("application_intent", "app_invocation_id", str(uuid4())),
        ("application_intent", "run_id", str(uuid4())),
        ("application_intent", "authorization_hash", "f" * 64),
        ("application_credential_observation", "credential_fingerprint", "e" * 64),
        ("application_credential_observation", "fingerprint_key_version", "v99"),
    ],
)
def test_tampered_source_context_never_admits_a_partial_subset(c4, kind, field, value):
    flow(c4)
    health(c4)
    record = next(r for r in source_rows(c4, "C4_APP_TABLE") if r["record_kind"] == kind)
    c4["db"].Table("C4_APP_TABLE").put_item(Item={**record, field: value})
    result = Collector(c4["config"], c4["session"]).reconcile(NOW)
    assert not result["ready"] and result["submitted_count"] == 0


def test_repeated_collection_deduplicates_without_replacing_source_times(c4):
    flow(c4)
    health(c4)
    collector = Collector(c4["config"], c4["session"])
    first = collector.reconcile(NOW)
    rows = [row for row in state_rows(c4, c4["config"]) if row["kind"] == "current"]
    assert Collector(c4["config"], c4["session"]).reconcile(NOW)["decisions"] == first["decisions"]
    assert rows == [row for row in state_rows(c4, c4["config"]) if row["kind"] == "current"]


def test_retried_application_has_a_real_new_id_and_no_replacement_credential(c4):
    flow(c4)
    health(c4)
    action = source_rows(c4, "EXPECTED_TABLE")[0]
    new_id = str(uuid4())
    with patch.object(demo, "call", side_effect=lambda _, payload: demo.issuer(payload, None)):
        result = demo.app(action, SimpleNamespace(aws_request_id=new_id))
    assert result["status"] == "unavailable"
    assert result["app_invocation_id"] == new_id
    intents = [
        r for r in source_rows(c4, "C4_APP_TABLE") if r["record_kind"] == "application_intent"
    ]
    assert len(intents) == 2 and len(source_rows(c4, "TOKEN_TABLE")) == 1
    assert not Collector(c4["config"], c4["session"]).reconcile(NOW)["ready"]


def test_repeated_signed_provider_request_cannot_create_a_second_operation(c4):
    captured = {}

    def route(function, payload):
        if function == "APP_FUNCTION":
            return demo.app(payload, SimpleNamespace(aws_request_id=c4["ids"]["app"]))
        if function == "ISSUER_FUNCTION":
            return demo.issuer(payload, None)
        captured.update(payload)
        return demo.saas(payload, SimpleNamespace(aws_request_id=c4["ids"]["provider"]))

    with patch.object(demo, "call", side_effect=route):
        demo.authorization(request(), SimpleNamespace(aws_request_id=c4["ids"]["gateway"]))
    repeated = demo.saas(captured, SimpleNamespace(aws_request_id=str(uuid4())))
    assert repeated == {"status": "unavailable", "error": "CONTEXT_REQUEST_ALREADY_CLAIMED"}
    health(c4)
    result = Collector(c4["config"], c4["session"]).reconcile(NOW)
    assert result["ready"] and result["submitted_count"] == 3
    assert len(source_rows(c4, "AUDIT_TABLE")) == 1


def test_spoofed_provider_context_locator_remains_unbound(c4):
    captured = {}

    def route(function, payload):
        if function == "APP_FUNCTION":
            return demo.app(payload, SimpleNamespace(aws_request_id=c4["ids"]["app"]))
        if function == "ISSUER_FUNCTION":
            return demo.issuer(payload, None)
        captured.update(payload)
        return demo.saas(
            {**payload, "app_invocation_id": str(uuid4())},
            SimpleNamespace(aws_request_id=c4["ids"]["provider"]),
        )

    with patch.object(demo, "call", side_effect=route):
        demo.authorization(request(), SimpleNamespace(aws_request_id=c4["ids"]["gateway"]))
    assert source_rows(c4, "C4_PROVIDER_TABLE")[0]["verified_app_invocation_id"] is None
    health(c4)
    assert not Collector(c4["config"], c4["session"]).reconcile(NOW)["ready"]


def test_unknown_credential_never_gains_context_from_caller_ids(c4):
    flow(c4)
    result = demo.saas(
        {
            "access_token": "unknown-synthetic-credential",
            "action_id": str(uuid4()),
            "app_invocation_id": c4["ids"]["app"],
        },
        SimpleNamespace(aws_request_id=str(uuid4())),
    )
    assert result["status"] == "denied"
    records = source_rows(c4, "C4_PROVIDER_TABLE")
    assert any(
        record.get("verified_app_invocation_id") is None
        for record in records
        if record["record_kind"] == "provider_context"
    )
    health(c4)
    assert not Collector(c4["config"], c4["session"]).reconcile(NOW)["ready"]


def test_no_runtime_invocation_id_is_invented(c4):
    with patch.object(demo, "call") as call:
        assert demo.app({"action_id": str(uuid4())}, None)["status"] == "unavailable"
        call.assert_not_called()
    assert source_rows(c4, "C4_APP_TABLE") == []


@pytest.mark.parametrize("state", ["unhealthy", "unknown", "stale", "missing", "wrong_function"])
def test_nonpositive_health_cannot_be_promoted_to_ready(c4, state):
    flow(c4)

    def change(record):
        if state == "unhealthy":
            record["function_state"] = "Failed"
            record["source_health"] = "unhealthy"
        elif state == "unknown":
            record["metrics"] = {}
            record["source_health"] = "unknown"
        elif state == "stale":
            record["event_time_utc"] = "1970-01-01T00:10:00+00:00"
            record["metrics"] = {}
            record["source_health"] = "unknown"
        elif state == "wrong_function":
            record["function_arn"] += "-wrong"

    if state != "missing":
        health(c4, change)
    result = Collector(c4["config"], c4["session"]).reconcile(NOW)
    assert not result["ready"] and result["submitted_count"] == 0


def test_independent_observer_missing_datapoints_and_errors_do_not_become_success(c4):
    records, session = health(c4)
    client = session.client("cloudwatch")
    client.get_metric_statistics.side_effect = lambda **kwargs: {"Datapoints": []}
    assert {
        r["source_health"]
        for r in four_stage_health.observe(dict(c4["config"].health_functions), NOW, session)
    } == {"unknown"}
    client.get_metric_statistics.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "private fixture"}}, "GetMetricStatistics"
    )
    observations = four_stage_health.observe(dict(c4["config"].health_functions), NOW, session)
    assert {r["source_health"] for r in observations} == {"unknown"}
    assert "private fixture" not in json.dumps(observations)


def test_privacy_and_original_timestamps_survive_full_c4_collection(c4, caplog):
    flow(c4)
    health(c4)
    result = Collector(c4["config"], c4["session"]).reconcile(NOW)
    exported = (
        json.dumps(result) + json.dumps(state_rows(c4, c4["config"]), default=str) + caplog.text
    )
    registry = source_rows(c4, "TOKEN_TABLE")[0]
    assert registry["token_hash"] not in exported
    assert registry["private_attestation"]["token_id"] not in exported
    assert "access_token" not in exported and "key_b64" not in exported
    assert {r["event_time_utc"] for r in result["bindings"]} == {"1970-01-01T00:16:40+00:00"}


def test_missing_intent_write_prevents_issuance_and_operation(c4):
    flow(c4)
    target = source_rows(c4, "EXPECTED_TABLE")[0]
    with (
        patch(
            "sealed_telemetry.four_stage_context.append",
            side_effect=ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "private fixture"}}, "PutItem"
            ),
        ),
        patch.object(demo, "call") as call,
    ):
        result = demo.app(target, SimpleNamespace(aws_request_id=str(uuid4())))
        assert result["status"] == "unavailable"
        call.assert_not_called()


def test_health_and_config_spoofing_is_rejected(c4):
    flow(c4)
    health(c4)
    record = source_rows(c4, "C4_HEALTH_TABLE")[0]
    with pytest.raises(InvalidRecord):
        normalize(
            "health",
            "c4",
            "configured-resource",
            record["event_id"],
            {**record, "source_health": "unknown"},
        )
    with pytest.raises(CollectionError, match="INVALID_C4_CONFIGURATION"):
        Collector(replace(c4["config"], health_functions=()), c4["session"])


@pytest.mark.parametrize("proof", [None, "0" * 64, "malformed"])
def test_known_credential_and_app_id_without_valid_signature_cannot_bind_context(c4, proof):
    def route(function, payload):
        if function == "APP_FUNCTION":
            return demo.app(payload, SimpleNamespace(aws_request_id=c4["ids"]["app"]))
        if function == "ISSUER_FUNCTION":
            return demo.issuer(payload, None)
        return demo.saas(
            {**payload, "context_signature": proof},
            SimpleNamespace(aws_request_id=c4["ids"]["provider"]),
        )

    with patch.object(demo, "call", side_effect=route):
        demo.authorization(request(), SimpleNamespace(aws_request_id=c4["ids"]["gateway"]))
    records = source_rows(c4, "C4_PROVIDER_TABLE")
    assert len(records) == 1 and records[0]["verified_app_invocation_id"] is None
    health(c4)
    assert not Collector(c4["config"], c4["session"]).reconcile(NOW)["ready"]


@pytest.mark.parametrize("retain", [True, False])
def test_context_key_rotation_verifies_retained_version_and_rejects_removed_key(c4, retain):
    def route(function, payload):
        if function == "APP_FUNCTION":
            return demo.app(payload, SimpleNamespace(aws_request_id=c4["ids"]["app"]))
        if function == "ISSUER_FUNCTION":
            return demo.issuer(payload, None)
        keys = {"v2": base64.b64encode(bytes(range(96, 128))).decode()}
        if retain:
            keys["v1"] = base64.b64encode(bytes(range(64, 96))).decode()
        boto3.client("secretsmanager").put_secret_value(
            SecretId="fixture-context",
            SecretString=json.dumps({"active_version": "v2", "keys": keys}),
        )
        return demo.saas(payload, SimpleNamespace(aws_request_id=c4["ids"]["provider"]))

    with patch.object(demo, "call", side_effect=route):
        demo.authorization(request(), SimpleNamespace(aws_request_id=c4["ids"]["gateway"]))
    health(c4)
    result = Collector(c4["config"], c4["session"]).reconcile(NOW)
    assert result["ready"] is retain
    provider = next(
        r for r in source_rows(c4, "C4_PROVIDER_TABLE") if r["record_kind"] == "provider_context"
    )
    assert provider["context_key_version"] == ("v1" if retain else None)


def test_orphan_provider_claim_after_action_failure_remains_incomplete(c4):
    from sealed_telemetry import four_stage_binding

    with patch.object(four_stage_binding, "provider", return_value={"status": "unavailable"}):
        flow(c4)
    assert len(source_rows(c4, "C4_PROVIDER_TABLE")) == 1
    assert source_rows(c4, "AUDIT_TABLE") == []
    health(c4)
    result = Collector(c4["config"], c4["session"]).reconcile(NOW)
    assert not result["ready"] and "UNMATCHED_SUPPORTING_EVIDENCE" in result["blockers"]


@pytest.mark.parametrize("change", ["old", "future", "misaligned", "zero_activity", "errors"])
def test_independent_health_measurement_boundaries(c4, change):
    records, _ = health(c4)
    record = records[0]
    if change in {"old", "future"}:
        for metric in record["metrics"].values():
            metric["timestamp"] = (
                "1970-01-01T00:10:00+00:00" if change == "old" else "1970-01-01T00:20:00+00:00"
            )
    elif change == "misaligned":
        record["metrics"]["Errors"]["timestamp"] = "1970-01-01T00:16:39+00:00"
    elif change == "zero_activity":
        record["metrics"]["Invocations"]["sum"] = 0
    else:
        record["metrics"]["Errors"]["sum"] = 1
    assert four_stage_health.classify(record, NOW) == (
        "unhealthy" if change == "errors" else "unknown"
    )


def test_independently_recorded_duplicate_operation_cannot_be_silently_dropped(c4):
    flow(c4)
    health(c4)
    # A real extra C2 provider observation without authenticated C4 context stays incomplete.
    from sealed_telemetry.four_stage_binding import provider

    provider({"action_id": str(uuid4())}, 1000)
    result = Collector(c4["config"], c4["session"]).reconcile(NOW)
    assert len(source_rows(c4, "AUDIT_TABLE")) == 2
    assert not result["ready"] and result["submitted_count"] == 0


@pytest.mark.parametrize("phase", ["claim", "sidecar"])
def test_indeterminate_provider_context_persistence_never_retries_action(c4, phase):
    from botocore.exceptions import ReadTimeoutError

    from sealed_telemetry import four_stage_context

    original = four_stage_context.append

    def fail(db, variable, record, key):
        original(db, variable, record, key)
        target = "context_request_claim" if phase == "claim" else "provider_context"
        if record.get("record_kind") == target:
            raise ReadTimeoutError(endpoint_url="https://dynamodb.mock.invalid")

    with patch.object(four_stage_context, "append", side_effect=fail):
        assert flow(c4)["statusCode"] == 502
    assert len(source_rows(c4, "AUDIT_TABLE")) == (0 if phase == "claim" else 1)
    health(c4)
    result = Collector(c4["config"], c4["session"]).reconcile(NOW)
    # A committed sidecar can be recovered independently even if the app saw a timeout.
    assert result["ready"] is (phase == "sidecar")
