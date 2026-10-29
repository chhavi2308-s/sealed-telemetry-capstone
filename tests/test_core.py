import json
import secrets
from dataclasses import replace
from uuid import uuid4

import pytest

from sealed_telemetry.lab import SCENARIOS, run_scenario
from sealed_telemetry.provider import Provider
from sealed_telemetry.reconciliation import Policy, reconcile
from sealed_telemetry.response import contain
from sealed_telemetry.schema import new_event
from sealed_telemetry.storage import Ledger

NOW = "2026-10-26T10:00:00+00:00"
LATER = "2026-10-26T10:00:50+00:00"
HEALTH = {"gateway": True, "provider": True, "app": True}


def event(source="gateway", kind="EXPECTED_ACTION", **changes):
    fields = dict(
        run_id="run",
        scenario_id="lab",
        event_time_utc=NOW,
        actor_pseudonym="actor",
        credential_fingerprint="a" * 64,
        operation="read",
        resource_pseudonym="synthetic",
        invocation_id="inv",
        action_id="act",
    )
    fields.update(changes)
    return new_event(source, kind, **fields)


def test_source_spoof_duplicate_and_conflict(tmp_path):
    ledger = Ledger(tmp_path / "security.sqlite")
    raw = event().to_dict()
    with pytest.raises(ValueError, match="source identity"):
        ledger.ingest(raw, "app")
    receipt = ledger.ingest(raw, "gateway", NOW)
    assert ledger.ingest(raw, "gateway", LATER) == receipt
    with pytest.raises(ValueError, match="reused"):
        ledger.ingest({**raw, "operation": "export"}, "gateway")
    assert len(ledger.events("run")) == 1
    assert ledger.verify("run")
    ledger.close()


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": "2"},
        {"bearer_token": "secret"},
        {"event_time_utc": "2026-10-26"},
        {"event_id": "not-uuid"},
        {"invocation_id": None},
        {"operation": "a" * 17000},
        {"event_type": "PROVIDER_ACTION"},
        {"outcome": "stolen"},
    ],
)
def test_reject_invalid(change, tmp_path):
    ledger = Ledger(tmp_path / "security.sqlite")
    with pytest.raises((ValueError, TypeError)):
        ledger.ingest({**event().to_dict(), **change}, "gateway")
    ledger.close()


def test_provider_security_and_verified_response(tmp_path):
    p = Provider(tmp_path / "provider.sqlite", secrets.token_bytes(32))
    token, _ = p.issue(NOW)
    assert p.call(token, NOW, "r", "s")["status"] == 200
    assert p.call(token, NOW, "r", "s", operation="records:export")["status"] == 403
    assert p.call(token, "2026-10-26T11:00:00+00:00", "r", "s")["status"] == 403
    other, _ = p.issue(NOW, audience="wrong")
    assert p.call(other, NOW, "r", "s")["status"] == 403
    assert p.call("invalid", NOW, "r", "s")["status"] == 403
    assert contain(p, token, NOW, "r", "s")["status"] == "approval_required"
    assert contain(p, token, NOW, "r", "s", True, True)["status"] == "unverified"
    assert contain(p, token, NOW, "r", "s", True)["status"] == "verified"
    assert p.call(token, NOW, "r", "s")["status"] == 403
    fresh, _ = p.issue(NOW)
    assert p.call(fresh, NOW, "r", "s")["status"] == 200
    bodies = " ".join(r[0] for r in p.db.execute("SELECT body FROM outbox"))
    assert token not in bodies and fresh not in bodies
    p.close()


def test_outbox_recovery(tmp_path):
    p = Provider(tmp_path / "provider.sqlite", secrets.token_bytes(32))
    token, _ = p.issue(NOW)
    p.call(token, NOW, "run", "lab")
    ledger = Ledger(tmp_path / "security.sqlite")
    assert p.deliver(ledger, NOW) == 1
    assert p.deliver(ledger, LATER) == 0
    assert len(ledger.events("run")) == 1
    p.close()
    ledger.close()


def test_late_revisions_and_sweep_idempotency(tmp_path):
    ledger = Ledger(tmp_path / "security.sqlite")
    expected = event()
    intent = event("app", "INTENT_CREATED")
    obs = event("provider", "PROVIDER_ACTION", provider_request_id="request")
    first = reconcile([expected], NOW, HEALTH)[0]
    second = reconcile([expected], LATER, HEALTH)[0]
    third = reconcile([expected, intent, obs], LATER, HEALTH)[0]
    assert [first["state"], second["state"], third["state"]] == [
        "PENDING",
        "INCONCLUSIVE",
        "CONSISTENT",
    ]
    ledger.append_decision(first)
    ledger.append_decision(second)
    ledger.append_decision(second)
    assert len(ledger.history(first["case_id"])) == 2
    ledger.close()


def test_ambiguity_and_concurrent_invocations():
    exp = event()
    obs = event("provider", "PROVIDER_ACTION", provider_request_id="request")
    intent = event("app", "INTENT_CREATED")
    duplicate_exp = replace(exp, event_id=str(uuid4()))
    assert reconcile([exp, duplicate_exp, obs, intent], LATER, HEALTH)[0]["state"] == "INCONCLUSIVE"
    exp2 = replace(exp, event_id=str(uuid4()), invocation_id="inv2", action_id="act2")
    obs2 = replace(
        obs,
        event_id=str(uuid4()),
        invocation_id="inv2",
        action_id="act2",
        provider_request_id="request2",
    )
    intent2 = replace(intent, event_id=str(uuid4()), invocation_id="inv2", action_id="act2")
    assert all(
        d["state"] == "CONSISTENT"
        for d in reconcile([exp, exp2, obs, obs2, intent, intent2], LATER, HEALTH)
    )


def test_replay_without_invocation_and_unknown_health():
    exp, intent = event(), event("app", "INTENT_CREATED")
    obs = event("provider", "PROVIDER_ACTION", provider_request_id="request")
    replay = replace(
        obs, event_id=str(uuid4()), invocation_id=None, action_id=None, provider_request_id="replay"
    )
    findings = reconcile([exp, intent, obs, replay], LATER, HEALTH)
    assert sorted(f["state"] for f in findings) == ["CONSISTENT", "SUSPICIOUS"]
    assert all(f["state"] == "INCONCLUSIVE" for f in reconcile([obs, replay], LATER, {}))
    assert reconcile([replay], NOW, HEALTH)[0]["state"] == "PENDING"
    assert reconcile([replay], LATER, HEALTH, Policy(gateway_deadline=100))[0]["state"] == "PENDING"


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_end_to_end_scenarios(scenario, tmp_path):
    result = run_scenario(tmp_path / scenario, scenario, NOW)
    states = [d["state"] for d in result["decisions"]]
    if scenario in {"normal", "duplicate", "out-of-order", "bulk", "delayed-audit"}:
        assert set(states) == {"CONSISTENT"}
    if scenario in {"replay-suppression", "response-failure"}:
        assert "SUSPICIOUS" in states
    if scenario in {"benign-log-failure", "collector-outage", "provider-outage", "clock-skew"}:
        assert "SUSPICIOUS" not in states and "CORROBORATED_SUSPECTED_ABUSE" not in states
    assert result["integrity_valid"] == (scenario != "tampering")
    output = json.loads((tmp_path / scenario / "report.json").read_text())
    assert output["mode"] == "local"


def test_health_staleness(tmp_path):
    ledger = Ledger(tmp_path / "security.sqlite")
    ledger.set_health("provider", True, NOW)
    assert ledger.health(LATER)["provider"]
    assert not ledger.health("2026-10-26T10:10:00+00:00")["provider"]
    ledger.close()


def test_reused_authorization_can_be_benign_retry():
    exp = event()
    first = event("provider", "PROVIDER_ACTION", provider_request_id="first")
    replay = replace(first, event_id=str(uuid4()), provider_request_id="second")
    ds = reconcile([exp, first, replay], LATER, HEALTH)
    assert {d["state"] for d in ds} == {"INCONCLUSIVE"}
    assert all(d["response_policy"] == "approval_required" for d in ds)


def test_run_metadata_cannot_hide_external_replay():
    exp = event()
    obs = event("provider", "PROVIDER_ACTION", provider_request_id="legitimate")
    replay = replace(
        obs,
        run_id="external-provider-run",
        event_id=str(uuid4()),
        invocation_id=None,
        action_id=None,
        provider_request_id="replay",
    )
    ds = reconcile([exp, obs, replay], LATER, HEALTH)
    assert any(d["run_id"] == "external-provider-run" and d["state"] == "SUSPICIOUS" for d in ds)


def test_containment_recovery_scenario(tmp_path):
    result = run_scenario(tmp_path / "response", "containment-recovery", NOW)
    assert result["response"]["status"] == "verified"
    assert result["response"]["recovery"] == "verified"
    assert result["integrity_valid"]


def test_integration_disable_and_restore(tmp_path):
    provider = Provider(tmp_path / "provider.sqlite", secrets.token_bytes(32))
    token, _ = provider.issue(NOW)
    assert provider.call(token, NOW, "run", "lab")["status"] == 200
    provider.set_integration(False)
    assert provider.call(token, NOW, "run", "lab")["status"] == 403
    provider.set_integration(True)
    assert provider.call(token, NOW, "run", "lab")["status"] == 200
    provider.close()


@pytest.mark.parametrize("value", [-1, float("nan"), float("inf"), "15", True])
def test_invalid_deadline_policy_rejected(value):
    with pytest.raises(ValueError):
        Policy(provider_deadline=value)


def test_corroboration_requires_independently_verified_revocation():
    revoked = event(
        "responder",
        "RESPONSE_ACTION",
        operation="token:revoke:verify",
        invocation_id=None,
        action_id=None,
    )
    obs = event(
        "provider",
        "PROVIDER_ACTION",
        provider_request_id="after-revoke",
        event_time_utc=LATER,
        invocation_id=None,
        action_id=None,
    )
    ds = reconcile([revoked, obs], LATER, HEALTH)
    assert ds[0]["state"] == "CORROBORATED_SUSPECTED_ABUSE"
    assert set(ds[0]["correlated_event_ids"]) == {revoked.event_id, obs.event_id}
    close = replace(obs, event_time_utc="2026-10-26T10:00:10+00:00")
    assert reconcile([revoked, close], LATER, HEALTH)[0]["state"] != "CORROBORATED_SUSPECTED_ABUSE"


def test_export_containment_verifies_the_authorized_operation(tmp_path):
    from unittest.mock import patch

    provider = Provider(tmp_path / "provider.sqlite", secrets.token_bytes(32))
    token, _ = provider.issue(NOW, scope="records:export")
    with patch.object(provider, "call", wraps=provider.call) as call:
        assert contain(provider, token, NOW, "run", "lab", approved=True)["status"] == "verified"
        assert call.call_args.kwargs["operation"] == "records:export"
    provider.close()


def test_source_namespaced_local_ids_do_not_allow_app_to_block_provider(tmp_path):
    from dataclasses import replace

    from sealed_telemetry.storage import Ledger

    ledger = Ledger(tmp_path / "ledger.sqlite")
    try:
        app_claim = event("app", "INTENT_CREATED")
        observed = replace(
            event("provider", "PROVIDER_ACTION", provider_request_id="provider"),
            event_id=app_claim.event_id,
        )
        ledger.ingest(app_claim.to_dict(), "app")
        ledger.ingest(observed.to_dict(), "provider")
        assert len(ledger.events(app_claim.run_id)) == 2
        assert ledger.verify(app_claim.run_id)
    finally:
        ledger.close()
