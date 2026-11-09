"""Offline contract tests: observed values stay distinct from unsupported bindings."""

import json
from dataclasses import asdict, replace
from decimal import Decimal
from types import SimpleNamespace
from uuid import UUID

import pytest

from scripts.four_stage_attack_local import run
from sealed_telemetry.four_stage import emit_intent
from sealed_telemetry.four_stage_evidence import CollectedRecord, normalize
from sealed_telemetry.reconciliation import reconcile
from sealed_telemetry.schema import Evidence

NOW = "2026-11-09T10:00:00+00:00"
# These are fixture resources, not observations of the deployed account.
GATEWAY = "arn:aws:dynamodb:ap-south-1:000000000000:table/fixture-expected"
PROVIDER = "arn:aws:dynamodb:ap-south-1:000000000000:table/fixture-audit"
APP = "arn:aws:logs:ap-south-1:000000000000:log-group:/fixture/app:log-stream:stream-1"
SOURCES = {GATEWAY: "gateway", PROVIDER: "provider", APP: "app"}


def collected(result):
    records = []
    for group, arn, key in (
        ("expected", GATEWAY, "action_id"),
        ("intents", APP, "event_id"),
        ("audits", PROVIDER, "provider_request_id"),
    ):
        for row in result[group]:
            records.append(CollectedRecord(arn, row[key], NOW, row))
    return records


def test_existing_handler_records_normalize_without_inventing_bindings():
    result = normalize(collected(run()), SOURCES)
    assert not result.issues
    assert [o.event_type for o in result.observations] == [
        "EXPECTED_ACTION",
        "INTENT_CREATED",
        "PROVIDER_ACTION",
    ]
    assert {o.event_time_utc for o in result.observations} == {"1970-01-01T00:16:40+00:00"}
    assert len({o.action_id for o in result.observations}) == 1
    for observation in result.observations:
        UUID(observation.event_id)
        assert observation.credential_fingerprint is None
        assert observation.actor_pseudonym is None
        assert "credential_fingerprint" in observation.missing_iber_fields
        with pytest.raises(ValueError, match="FOUR_STAGE_IBER_CONTRACT_INCOMPLETE"):
            observation.to_evidence()
        with pytest.raises(ValueError):
            Evidence.parse(observation.to_dict(), observation.source_id)
    expected, intent, provider = result.observations
    assert expected.authorization_expires_at_utc == "1970-01-01T00:21:40+00:00"
    assert expected.outcome is intent.outcome is None
    assert provider.outcome == "success"
    assert expected.invocation_id is provider.invocation_id is None
    assert intent.provenance.trust_tier == "untrusted_app_claim"
    assert provider.provenance.trust_tier == "independent_lab_record"


def test_real_app_log_preserves_invocation_only_as_app_claim(caplog):
    with caplog.at_level("INFO"):
        emit_intent({"action_id": "action"}, SimpleNamespace(aws_request_id="actual-app-request"))
    row = json.loads(caplog.records[-1].getMessage())
    item = CollectedRecord(APP, "cloudwatch-native-event", NOW, row)
    observation = normalize([item], SOURCES).observations[0]
    assert observation.invocation_id == "actual-app-request"
    assert observation.producer_event_id == row["event_id"]
    assert observation.event_id != row["event_id"]
    assert observation.provenance.native_id == "cloudwatch-native-event"
    assert observation.provenance.trust_tier == "untrusted_app_claim"


def test_replay_and_denied_attempts_remain_distinct_not_proof_of_theft():
    result = normalize(collected(run(simulate_copy=True)), SOURCES)
    audits = [o for o in result.observations if o.source_id == "provider"]
    assert [o.outcome for o in audits] == ["success", "success", "denied"]
    assert len({o.provider_request_id for o in audits}) == 3
    assert len({o.event_id for o in audits}) == 3
    assert len({o.action_id for o in audits}) == 1
    assert all(o.credential_fingerprint is None for o in audits)
    # No association is upgraded to a credential identity by shared action_id.
    assert all("credential_fingerprint" in o.missing_iber_fields for o in audits)


def test_suppression_and_empty_batches_do_not_manufacture_intent_or_health():
    result = normalize(collected(run(suppress_intent=True)), SOURCES)
    assert {o.source_id for o in result.observations} == {"gateway", "provider"}
    assert not result.issues
    empty = normalize([], SOURCES)
    assert not empty.observations and not empty.issues
    # IBER itself still treats missing health as inconclusive; no health is inferred here.
    assert reconcile([], NOW, {}) == []
    assert not any("source_health" in o.to_dict() for o in result.observations)


def test_independent_sources_and_native_ids_cannot_be_spoofed():
    records = collected(run())
    app = records[1]
    provider = records[2]
    forged = replace(app, payload={**app.payload, "event_type": "PROVIDER_ACTION"})
    unknown = replace(provider, resource_arn=PROVIDER + "-other")
    injected = replace(provider, payload={**provider.payload, "source_id": "gateway"})
    result = normalize([forged, unknown, injected], SOURCES)
    assert not result.observations
    assert [i.reason_code for i in result.issues] == [
        "INVALID_SOURCE_RECORD",
        "UNRECOGNIZED_SOURCE_RESOURCE",
        "INVALID_SOURCE_RECORD",
    ]
    wrong_key = replace(provider, native_id="different-primary-key")
    assert normalize([wrong_key], SOURCES).issues[0].reason_code == "INVALID_SOURCE_RECORD"


def test_duplicate_delivery_is_idempotent_but_payload_conflicts_are_withheld():
    record = collected(run())[2]
    duplicate = replace(record, collected_at_utc="2026-11-09T11:00:00+00:00")
    once = normalize([record], SOURCES)
    twice = normalize([record, duplicate], SOURCES)
    assert once == twice
    conflict = replace(record, payload={**record.payload, "outcome": "denied"})
    for batch in ([record, conflict, record], [conflict, record, conflict]):
        result = normalize(batch, SOURCES)
        assert not result.observations
        assert {i.reason_code for i in result.issues} == {"CONFLICTING_NATIVE_RECORD"}


def test_invalid_variant_also_withholds_native_identity_in_either_order():
    record = collected(run())[2]
    invalid = replace(record, payload={**record.payload, "credential_fingerprint": "a" * 64})
    for batch in ([record, invalid], [invalid, record]):
        result = normalize(batch, SOURCES)
        assert not result.observations
        assert "INVALID_SOURCE_RECORD" in {i.reason_code for i in result.issues}


def test_app_claimed_ids_cannot_collide_with_provider_or_another_log_event():
    records = collected(run())
    provider = records[2]
    app = replace(records[1], payload={**records[1].payload, "event_id": provider.native_id})
    another_log_event = replace(app, native_id="another-log-event")
    result = normalize([provider, app, another_log_event], SOURCES)
    assert len(result.observations) == len({o.event_id for o in result.observations}) == 3


@pytest.mark.parametrize("value", [True, 1000.0, "1000", -1, Decimal("1000.5"), Decimal("NaN")])
def test_invalid_timestamp_never_defaults_to_collection_time(value):
    record = collected(run())[2]
    result = normalize([replace(record, payload={**record.payload, "recorded_at": value})], SOURCES)
    assert not result.observations
    assert result.issues[0].reason_code == "INVALID_SOURCE_RECORD"


def test_decimal_dynamodb_timestamps_are_lossless_and_collection_time_is_separate():
    record = collected(run())[2]
    raw = {k: Decimal(v) if type(v) is int else v for k, v in record.payload.items()}
    ordinary = normalize([record], SOURCES).observations[0]
    converted = normalize([replace(record, payload=raw)], SOURCES).observations[0]
    assert ordinary == converted
    assert converted.event_time_utc != converted.provenance.collected_at_utc


@pytest.mark.parametrize(
    "change",
    [
        {"outcome": "failure"},
        {"synthetic": False},
        {"synthetic": 1},
        {"event_type": "EXPECTED_ACTION"},
        {"recorded_at": None},
    ],
)
def test_provider_record_requires_observed_shape(change):
    record = collected(run())[2]
    assert normalize([replace(record, payload={**record.payload, **change})], SOURCES).issues


def test_provider_unknown_sentinels_remain_missing_and_never_become_shared_identities():
    record = collected(run())[2]
    row = {**record.payload, "action_id": "unknown", "operation": "unknown", "filename": "unknown"}
    observation = normalize([replace(record, payload=row)], SOURCES).observations[0]
    assert observation.action_id is observation.operation is observation.resource_name is None
    assert "operation" in observation.missing_iber_fields


def test_no_tokens_hashes_or_arbitrary_exception_text_in_output(caplog):
    result = run(simulate_copy=True)
    records = collected(result)
    private = "private-synthetic-value"
    for name in ("access_token", "token_hash", "credential_fingerprint", "actor_pseudonym"):
        bad = replace(records[2], payload={**records[2].payload, name: private})
        rejected = normalize([bad], SOURCES)
        output = json.dumps(asdict(rejected)) + caplog.text
        assert private not in output
        assert name not in output
    clean = json.dumps(asdict(normalize(records, SOURCES)))
    assert "access_token" not in clean and "token_hash" not in clean


def test_authorization_expiry_and_native_key_are_not_reconstructed():
    record = collected(run())[0]
    for change in ({"authorization_expires_at": 1000}, {"action_id": "different"}):
        assert normalize([replace(record, payload={**record.payload, **change})], SOURCES).issues


@pytest.mark.parametrize(
    "arn,source",
    [
        (PROVIDER + "*", "provider"),
        (GATEWAY + "/stream/123", "gateway"),
        (PROVIDER, "app"),
        (PROVIDER, "issuer"),
        ("not-an-arn", "gateway"),
        ("arn:aws:logs:ap-south-1:000000000000:log-group:/fixture/app", "app"),
    ],
)
def test_source_configuration_requires_exact_expected_resource_type(arn, source):
    with pytest.raises(ValueError):
        normalize([], {arn: source})


def test_bounded_batch_and_bad_collection_timestamp():
    record = collected(run())[2]
    with pytest.raises(ValueError, match="batch exceeds"):
        normalize([record] * 1001, SOURCES)
    assert normalize([replace(record, collected_at_utc="2026-11-09")], SOURCES).issues


def test_inputs_are_not_mutated_and_late_delivery_keeps_event_identity():
    records = collected(run())
    before = json.dumps([dict(r.payload) for r in records], sort_keys=True)
    first = normalize(records, SOURCES)
    delayed = normalize(
        [replace(r, collected_at_utc="2026-11-10T10:00:00+00:00") for r in records], SOURCES
    )
    assert [o.event_id for o in first.observations] == [o.event_id for o in delayed.observations]
    assert [o.event_time_utc for o in first.observations] == [
        o.event_time_utc for o in delayed.observations
    ]
    assert json.dumps([dict(r.payload) for r in records], sort_keys=True) == before
