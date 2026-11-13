"""C3 read-through collection, persistent quarantine and unchanged-engine boundary tests."""

import json
from dataclasses import asdict, replace
from unittest.mock import patch
from uuid import uuid4

import boto3
import pytest
from botocore.client import BaseClient
from botocore.exceptions import ClientError
from test_four_stage_binding import lab as lab
from test_four_stage_binding import request

from sealed_telemetry import four_stage as demo
from sealed_telemetry import four_stage_collection, four_stage_iber
from sealed_telemetry.four_stage_collection import (
    CollectionError,
    Collector,
    Configuration,
    Ledger,
    Source,
)
from sealed_telemetry.schema import new_event

NOW = "1970-01-01T00:16:41+00:00"


@pytest.fixture
def collection(lab):
    role = boto3.client("iam").create_role(
        RoleName="C3Collector",
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}),
    )["Role"]["Arn"]
    assumed = boto3.client("sts").assume_role(RoleArn=role, RoleSessionName="collector-fixture")[
        "Credentials"
    ]
    session = boto3.Session(
        aws_access_key_id=assumed["AccessKeyId"],
        aws_secret_access_key=assumed["SecretAccessKey"],
        aws_session_token=assumed["SessionToken"],
        region_name="ap-south-1",
    )
    return {"lab": lab, "role": role, "session": session}


def config(collection, canonical=False, mixed=False, state="C3State", **limits):
    db = collection["lab"]["db"]
    db.create_table(
        TableName=state,
        BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[{"AttributeName": "record_id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "record_id", "KeyType": "HASH"}],
    )
    sources = []
    if not canonical or mixed:
        for source, table, key in (
            ("gateway", "EXPECTED_TABLE", "action_id"),
            ("issuer", "ISSUANCE_TABLE", "issuance_id"),
            ("provider", "AUDIT_TABLE", "provider_request_id"),
        ):
            sources.append(Source(source, "c2", db.Table(table).table_arn, key))
    if canonical or mixed:
        for source in ("gateway", "app", "provider", "health"):
            table = "canonical-" + source
            db.create_table(
                TableName=table,
                BillingMode="PAY_PER_REQUEST",
                AttributeDefinitions=[{"AttributeName": "event_id", "AttributeType": "S"}],
                KeySchema=[{"AttributeName": "event_id", "KeyType": "HASH"}],
            )
            sources.append(Source(source, "iber-1", db.Table(table).table_arn, "event_id"))
    return Configuration(collection["role"], db.Table(state).table_arn, tuple(sources), **limits)


def produce(collection, provider=True):
    with patch.object(
        demo, "call", return_value={"status": "success", "provider_request_id": "fixture"}
    ):
        response = demo.authorization(request(), None)
    payload = json.loads(response["body"])
    credential = demo.issuer(payload, None)
    assert "access_token" in credential
    result = demo.saas({**payload, **credential}, None) if provider else None
    return payload, credential, result


def canonical_events(collection, provider=True, health=True, invocation=True):
    fields = {
        "run_id": str(uuid4()),
        "scenario_id": "lab-v1",
        "event_time_utc": "1970-01-01T00:16:40+00:00",
        "actor_pseudonym": "a" * 64,
        "credential_fingerprint": "c" * 64,
        "operation": "files:upload",
        "resource_pseudonym": "b" * 64,
        "invocation_id": str(uuid4()),
        "action_id": str(uuid4()),
    }
    events = [
        new_event("gateway", "EXPECTED_ACTION", **fields),
        new_event("app", "INTENT_CREATED", **fields),
    ]
    if provider:
        events.append(
            new_event(
                "provider",
                "PROVIDER_ACTION",
                **{**fields, "invocation_id": fields["invocation_id"] if invocation else None},
                provider_request_id=str(uuid4()),
            )
        )
    if health:
        for source in ("gateway", "provider", "app", "collector"):
            events.append(
                new_event(
                    "health",
                    "SOURCE_HEALTH",
                    run_id=fields["run_id"],
                    scenario_id="lab-v1",
                    event_time_utc=fields["event_time_utc"],
                    actor_pseudonym="security-monitor",
                    credential_fingerprint="0" * 64,
                    operation="health:check",
                    resource_pseudonym="lab-telemetry",
                    health_for_source=source,
                    source_health="healthy",
                )
            )
    db = collection["lab"]["db"]
    for event in events:
        db.Table("canonical-" + event.source_id).put_item(Item=event.to_dict())
    return events


def test_actual_c2_records_have_verified_references_but_remain_incomplete(collection):
    conf = config(collection)
    produce(collection)
    result = Collector(conf, collection["session"]).reconcile(NOW)
    assert not result["ready"] and result["submitted_count"] == 0
    assert result["decisions"] == [] and result["coverage_complete"] is False
    assert all(value is None for value in result["source_health_snapshot"].values())
    assert {r["status"] for r in result["bindings"]} == {
        "REFERENCE_CONSISTENT",
        "BINDING_CONSISTENT",
    }
    gateway = next(r for r in result["bindings"] if r["source_id"] == "gateway")
    assert "invocation_id" in gateway["missing_iber_fields"]
    assert "run_id" in gateway["missing_iber_fields"]


def test_complete_independent_canonical_evidence_calls_existing_engine(collection):
    conf = config(collection, canonical=True)
    canonical_events(collection)
    result = Collector(conf, collection["session"]).reconcile(NOW)
    assert result["ready"] and result["submitted_count"] == 3
    assert [d["state"] for d in result["decisions"]] == ["CONSISTENT"]
    assert not result["coverage_complete"] and not result["application_execution_proven"]


def test_duplicates_and_conflict_quarantine_persist_across_new_collector_instances(collection):
    conf = config(collection)
    payload, _, _ = produce(collection)
    first = Collector(conf, collection["session"]).collect_all(NOW)
    assert first["counts"]["accepted"] == 3 and first["counts"]["ignored"] == 1
    again = Collector(conf, collection["session"]).collect_all(NOW)
    assert again["counts"]["duplicate"] == 3
    table = collection["lab"]["db"].Table("EXPECTED_TABLE")
    original = table.get_item(Key={"action_id": payload["action_id"]})["Item"]
    table.put_item(Item={**original, "source_id": "app"})
    blocked = Collector(conf, collection["session"]).reconcile(NOW)
    assert "QUARANTINED_EVIDENCE" in blocked["blockers"]
    table.put_item(Item=original)
    restored = Collector(conf, collection["session"]).reconcile(NOW)
    assert "QUARANTINED_EVIDENCE" in restored["blockers"]
    assert restored["submitted_count"] == 0


def test_duplicate_source_mapping_is_rejected_before_reading_any_payload(collection):
    conf = config(collection)
    duplicate = replace(conf, sources=conf.sources + (conf.sources[0],))
    with pytest.raises(ValueError, match="AMBIGUOUS"):
        Collector(duplicate, collection["session"])


def state_rows(collection, conf):
    return collection["lab"]["db"].Table(conf.state_table_arn).scan(ConsistentRead=True)["Items"]


def test_unapproved_collector_session_is_rejected_before_state_is_written(collection):
    conf = config(collection)
    with pytest.raises(CollectionError, match="COLLECTOR_IDENTITY_REJECTED"):
        Collector(conf, boto3.Session()).collect_all(NOW)
    assert not state_rows(collection, conf)


def test_same_role_name_under_wrong_configured_path_is_rejected(collection):
    conf = config(collection)
    invalid = replace(
        conf, collector_role_arn=conf.collector_role_arn.replace("role/", "role/not-the-real-path/")
    )
    with pytest.raises(CollectionError, match="COLLECTOR_IDENTITY_REJECTED"):
        Collector(invalid, collection["session"]).collect_all(NOW)
    assert not state_rows(collection, conf)


def test_private_registry_cannot_be_misconfigured_as_an_issuer_evidence_source(collection):
    conf = config(collection)
    token_arn = collection["lab"]["db"].Table("TOKEN_TABLE").table_arn
    invalid = replace(
        conf,
        sources=tuple(
            replace(s, table_arn=token_arn) if s.source_id == "issuer" else s for s in conf.sources
        ),
    )
    produce(collection)
    with pytest.raises(CollectionError, match="SOURCE_RESOURCE_IDENTITY_REJECTED"):
        Collector(invalid, collection["session"]).collect_all(NOW)
    assert not state_rows(collection, conf)


@pytest.mark.parametrize(
    "change",
    [
        {"collector_role_arn": "arn:aws:iam::999999999999:role/C3Collector"},
        {"max_records": 0},
        {"max_pages": 0},
    ],
)
def test_invalid_collection_configuration_fails_closed(collection, change):
    conf = config(collection)
    with pytest.raises(CollectionError):
        Collector(replace(conf, **change), collection["session"])


def test_state_cannot_be_reused_under_a_different_source_policy(collection):
    conf = config(collection)
    produce(collection)
    Collector(conf, collection["session"]).collect_all(NOW)
    before = len(state_rows(collection, conf))
    with pytest.raises(CollectionError, match="STATE_POLICY_MISMATCH"):
        Collector(replace(conf, max_records=999), collection["session"]).collect_all(NOW)
    assert len(state_rows(collection, conf)) == before


@pytest.mark.parametrize("field", ["token_id", "access_token", "token_hash", "private_attestation"])
def test_rejected_private_fields_never_enter_persistent_state_or_diagnostics(
    collection, field, caplog
):
    conf = config(collection)
    produce(collection)
    table = collection["lab"]["db"].Table("ISSUANCE_TABLE")
    item = next(row for row in table.scan()["Items"] if row["record_kind"] == "issuance_evidence")
    private_fixture = "private-producer-field-fixture-only"
    table.put_item(Item={**item, field: private_fixture})
    result = Collector(conf, collection["session"]).reconcile(NOW)
    assert "QUARANTINED_EVIDENCE" in result["blockers"]
    exported = (
        json.dumps(state_rows(collection, conf), default=str) + json.dumps(result) + caplog.text
    )
    assert private_fixture not in exported


def test_successful_exports_exclude_private_credential_material(collection, caplog):
    conf = config(collection)
    _, credential, _ = produce(collection)
    registry = collection["lab"]["db"].Table("TOKEN_TABLE").scan()["Items"][0]
    result = Collector(conf, collection["session"]).reconcile(NOW)
    exported = (
        json.dumps(state_rows(collection, conf), default=str) + json.dumps(result) + caplog.text
    )
    for value in (
        credential["access_token"],
        registry["token_hash"],
        registry["private_attestation"]["token_id"],
    ):
        assert value not in exported
    assert "token_hash" not in exported and '"token_id"' not in exported


@pytest.mark.parametrize(
    "field,value",
    [
        ("fingerprint_key_version", "v2"),
        ("credential_fingerprint", "d" * 64),
        ("actor_pseudonym", "e" * 64),
        # Fixed UUIDv4 preserves the schema-valid mismatch path and stable node IDs.
        ("issuance_id", "00000000-0000-4000-8000-000000000001"),
    ],
)
def test_provider_binding_must_agree_with_independently_collected_issuer(collection, field, value):
    conf = config(collection)
    _, _, receipt = produce(collection)
    table = collection["lab"]["db"].Table("AUDIT_TABLE")
    raw = table.get_item(Key={"provider_request_id": receipt["provider_request_id"]})["Item"]
    table.put_item(Item={**raw, field: value})
    result = Collector(conf, collection["session"]).reconcile(NOW)
    assert not result["ready"] and result["submitted_count"] == 0
    assert {"ISSUER_PROVIDER_BINDING_MISMATCH", "WAITING_FOR_ISSUANCE"} & set(result["blockers"])


def test_issuer_reference_hash_is_checked_against_original_gateway_snapshot(collection):
    conf = config(collection)
    produce(collection)
    table = collection["lab"]["db"].Table("ISSUANCE_TABLE")
    issuer = next(row for row in table.scan()["Items"] if row["record_kind"] == "issuance_evidence")
    issuer["authorization_reference"]["canonical_hash"] = "d" * 64
    table.put_item(Item=issuer)
    result = Collector(conf, collection["session"]).reconcile(NOW)
    assert "GATEWAY_REFERENCE_MISMATCH" in result["blockers"]


@pytest.mark.parametrize("missing", ["gateway", "issuer", "provider"])
def test_delayed_sources_are_retained_and_relinked_without_changing_original_times(
    collection, missing
):
    conf = config(collection)
    produce(collection)
    names = {
        "gateway": ("EXPECTED_TABLE", "action_id"),
        "issuer": ("ISSUANCE_TABLE", "issuance_id"),
        "provider": ("AUDIT_TABLE", "provider_request_id"),
    }
    name, key = names[missing]
    table = collection["lab"]["db"].Table(name)
    original = next(
        row for row in table.scan()["Items"] if row.get("record_kind") != "issuance_claim"
    )
    table.delete_item(Key={key: original[key]})
    first = Collector(conf, collection["session"]).reconcile(NOW)
    assert first["submitted_count"] == 0
    table.put_item(Item=original)
    second = Collector(conf, collection["session"]).reconcile("1970-01-01T00:16:42+00:00")
    assert {r["status"] for r in second["bindings"]} == {
        "REFERENCE_CONSISTENT",
        "BINDING_CONSISTENT",
    }
    assert not second["ready"]  # Arrival does not manufacture invocation/context/health.
    assert {r["event_time_utc"] for r in second["bindings"]} == {"1970-01-01T00:16:40+00:00"}
    histories = [row for row in state_rows(collection, conf) if row["record_id"].startswith("a:")]
    assert len(histories) == 2


def test_separate_provider_replays_remain_separate_observations(collection):
    conf = config(collection)
    payload, credential, _ = produce(collection)
    demo.saas({**payload, **credential}, None)
    result = Collector(conf, collection["session"]).reconcile(NOW)
    providers = [r for r in result["bindings"] if r["source_id"] == "provider"]
    assert len(providers) == 2 and len({p["record_id"] for p in providers}) == 2
    assert all(p["status"] == "BINDING_CONSISTENT" for p in providers)
    assert not result["ready"] and not result["application_execution_proven"]


def test_read_access_failure_preserves_old_evidence_and_blocks_reconciliation(collection, caplog):
    conf = config(collection)
    produce(collection)
    Collector(conf, collection["session"]).collect_all(NOW)
    arn = next(s.table_arn for s in conf.sources if s.source_id == "gateway")
    original_api = BaseClient._make_api_call
    private_fixture = "private-sdk-error-fixture"

    def deny(client, operation, params):
        if operation == "Scan" and params.get("TableName") == arn:
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": private_fixture}}, operation
            )
        return original_api(client, operation, params)

    with patch.object(BaseClient, "_make_api_call", new=deny):
        result = Collector(conf, collection["session"]).reconcile(NOW)
    assert "SOURCE_COLLECTION_INCOMPLETE" in result["blockers"]
    assert len([row for row in state_rows(collection, conf) if row["kind"] == "current"]) == 3
    assert private_fixture not in json.dumps(result) + caplog.text


def test_provider_only_subset_cannot_be_submitted_to_iber(collection):
    conf = config(collection, canonical=True)
    events = canonical_events(collection)
    gateway = next(e for e in events if e.source_id == "gateway")
    collection["lab"]["db"].Table("canonical-gateway").delete_item(
        Key={"event_id": gateway.event_id}
    )
    with patch.object(four_stage_iber, "reconcile") as engine:
        result = Collector(conf, collection["session"]).reconcile(NOW)
        engine.assert_not_called()
    assert "PROVIDER_ONLY_COVERAGE_NOT_ESTABLISHED" in result["blockers"]


def test_unrelated_expectation_cannot_mask_provider_only_credential_scope(collection):
    conf = config(collection, canonical=True)
    events = canonical_events(collection)
    gateway = next(e for e in events if e.source_id == "gateway").to_dict()
    gateway["credential_fingerprint"] = "e" * 64
    collection["lab"]["db"].Table("canonical-gateway").put_item(Item=gateway)
    result = Collector(conf, collection["session"]).reconcile(NOW)
    assert "PROVIDER_ONLY_COVERAGE_NOT_ESTABLISHED" in result["blockers"]


def test_incomplete_c2_data_cannot_be_hidden_by_complete_canonical_records(collection):
    conf = config(collection, canonical=True, mixed=True)
    canonical_events(collection)
    produce(collection)
    with patch.object(four_stage_iber, "reconcile") as engine:
        result = Collector(conf, collection["session"]).reconcile(NOW)
        engine.assert_not_called()
    assert "INCOMPLETE_C2_EVIDENCE" in result["blockers"]


@pytest.mark.parametrize("health", [False, True])
def test_missing_or_stale_health_remains_unknown(collection, health):
    conf = config(collection, canonical=True)
    canonical_events(collection, health=health)
    now = "1970-01-01T00:30:00+00:00" if health else NOW
    result = Collector(conf, collection["session"]).reconcile(now)
    assert "SOURCE_HEALTH_UNHEALTHY_OR_UNKNOWN" in result["blockers"]
    assert all(value is None for value in result["source_health_snapshot"].values())


def test_missing_provider_invocation_remains_unknown_and_iber_uses_existing_fallback(collection):
    conf = config(collection, canonical=True)
    events = canonical_events(collection, invocation=False)
    with patch.object(four_stage_iber, "reconcile", wraps=four_stage_iber.reconcile) as engine:
        result = Collector(conf, collection["session"]).reconcile(NOW)
    provider = next(e for e in engine.call_args.args[0] if e.source_id == "provider")
    assert provider.invocation_id is None
    assert provider.event_id == next(e.event_id for e in events if e.source_id == "provider")
    assert result["decisions"][0]["state"] == "INCONCLUSIVE"
    assert result["decisions"][0]["reason_codes"] == ["BOUNDED_FALLBACK_ONLY"]


def test_complete_unmatched_expectation_is_not_dropped_before_late_provider_arrives(collection):
    conf = config(collection, canonical=True)
    events = canonical_events(collection, provider=False)
    collector = Collector(conf, collection["session"])
    first = collector.reconcile(NOW)
    assert first["submitted_count"] == 2 and first["decisions"][0]["state"] == "PENDING"
    fields = next(e.to_dict() for e in events if e.source_id == "gateway")
    fields.update(
        event_id=str(uuid4()),
        source_id="provider",
        event_type="PROVIDER_ACTION",
        provider_request_id=str(uuid4()),
    )
    collection["lab"]["db"].Table("canonical-provider").put_item(Item=fields)
    second = Collector(conf, collection["session"]).reconcile("1970-01-01T00:16:42+00:00")
    assert second["decisions"][0]["state"] == "CONSISTENT"
    assert (
        len([row for row in state_rows(collection, conf) if row["record_id"].startswith("a:")]) == 2
    )


def test_capacity_limit_blocks_partial_scan_prefix(collection):
    conf = config(collection, canonical=True, max_records=3)
    canonical_events(collection)
    with patch.object(four_stage_iber, "reconcile") as engine:
        with pytest.raises(CollectionError, match="STATE_CAPACITY_EXCEEDED"):
            Collector(conf, collection["session"]).reconcile(NOW)
        engine.assert_not_called()


@pytest.mark.parametrize("kind", ["body", "provenance"])
def test_persisted_state_tampering_is_not_trusted(collection, kind):
    conf = config(collection)
    produce(collection)
    collector = Collector(conf, collection["session"])
    collector.collect_all(NOW)
    state = collection["lab"]["db"].Table(conf.state_table_arn)
    row = next(r for r in state_rows(collection, conf) if r["kind"] == "current")
    body = json.loads(row["body"])
    if kind == "body":
        body["normalized"]["event_time_utc"] = "1970-01-01T00:16:39+00:00"
    else:
        body["receipt"]["collector_role_arn"] = "arn:aws:iam::123456789012:role/not-authorized"
    row["body"] = json.dumps(body)
    state.put_item(Item=row)
    with pytest.raises(CollectionError, match="STATE_INTEGRITY_FAILURE|STATE_PROVENANCE_MISMATCH"):
        Collector(conf, collection["session"]).reconcile(NOW)


def test_reconciliation_result_cannot_publish_against_a_changed_ledger_revision(collection):
    conf = config(collection, canonical=True)
    canonical_events(collection)
    original = Ledger.assessment

    def race(ledger, revision, body):
        ledger.table.update_item(
            Key={"record_id": "CONTROL"},
            UpdateExpression="ADD revision :one",
            ExpressionAttributeValues={":one": 1},
        )
        return original(ledger, revision, body)

    with patch.object(Ledger, "assessment", new=race):
        with pytest.raises(CollectionError, match="STATE_CHANGED_BEFORE_ASSESSMENT"):
            Collector(conf, collection["session"]).reconcile(NOW)
    assert Collector(conf, collection["session"]).latest_assessment(NOW) is None


def test_late_conflict_invalidates_previous_assessment_without_erasing_history(collection):
    conf = config(collection, canonical=True)
    events = canonical_events(collection)
    collector = Collector(conf, collection["session"])
    assert collector.reconcile(NOW)["ready"]
    assert collector.latest_assessment(NOW)["ready"]
    provider = next(e.to_dict() for e in events if e.source_id == "provider")
    collection["lab"]["db"].Table("canonical-provider").put_item(
        Item={**provider, "source_id": "app"}
    )
    collector.collect_all(NOW)
    assert collector.latest_assessment(NOW) is None
    assert not collector.reconcile(NOW)["ready"]
    histories = [row for row in state_rows(collection, conf) if row["record_id"].startswith("a:")]
    assert any(json.loads(row["body"])["ready"] for row in histories)
    assert any(not json.loads(row["body"])["ready"] for row in histories)


@pytest.mark.parametrize(
    "change", [{"max_records": True}, {"max_pages": 1.5}, {"collector_role_arn": None}]
)
def test_wrong_configuration_types_are_rejected_explicitly(collection, change):
    conf = config(collection)
    with pytest.raises(CollectionError, match="INVALID_COLLECTION_CONFIGURATION"):
        Collector(replace(conf, **change), collection["session"])


def test_entrypoint_does_not_accept_producer_payloads_or_identity_overrides():
    with patch.object(four_stage_collection, "Collector") as factory:
        for event in (
            {"operation": "collect", "source_id": "gateway"},
            {"records": []},
            {"operation": "arbitrary"},
        ):
            with pytest.raises(CollectionError, match="INVALID_COLLECTION_REQUEST"):
                four_stage_collection.handler(event, None)
        factory.assert_not_called()


def test_entrypoint_uses_trusted_runtime_configuration_and_authenticated_reads(
    collection, monkeypatch
):
    conf = config(collection)
    produce(collection)
    monkeypatch.setenv("C3_COLLECTION_CONFIG", json.dumps(asdict(conf)))
    with (
        patch.object(four_stage_collection.boto3, "Session", return_value=collection["session"]),
        patch.object(four_stage_collection, "utcnow", return_value=NOW),
    ):
        result = four_stage_collection.handler({"operation": "collect"}, None)
    assert result["counts"]["accepted"] == 3
    assert not result["coverage_complete"]
