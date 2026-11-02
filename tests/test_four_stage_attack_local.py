"""Offline regression tests. Tokens remain inside the harness closure."""

import json
from unittest.mock import patch

import pytest

from scripts.four_stage_attack_local import run
from sealed_telemetry import four_stage as demo
from sealed_telemetry.four_stage_analysis import analyze


def test_default_legitimate_and_copy_disabled():
    result = run()
    assert result["application_completed"]
    assert not result["token_copy_enabled"]
    assert not result["replay_after_completion"]
    assert len(result["audits"]) == len(result["intents"]) == 1
    assert result["findings"][0]["category"] == "AUTHORIZED"


def test_post_invocation_replay_and_unauthorized_invoice():
    result = run(simulate_copy=True)
    assert result["replay_after_completion"]
    assert [a["outcome"] for a in result["audits"]] == ["success", "success", "denied"]
    assert len({a["provider_request_id"] for a in result["audits"]}) == 3
    assert [f["category"] for f in result["findings"]] == [
        "SUSPICIOUS_REPLAY",
        "SUSPICIOUS_REPLAY",
        "UNAUTHORIZED_ACTION",
    ]


def test_suppression_preserves_provider_audit():
    result = run(simulate_copy=True, suppress_intent=True)
    assert not result["intents"]
    assert len(result["audits"]) == 3
    assert "APP_INTENT_MISSING" in result["findings"][0]["reason_codes"]


def test_suppression_disabled_by_default_and_intent_safe(caplog):
    event = {"action_id": "local", "suppress_app_intent": True}
    with patch.dict(demo.os.environ, {}, clear=True), patch.object(demo, "call") as call:
        call.return_value = {"status": "success", "provider_request_id": "p", "access_token": "x"}
        with patch.object(demo, "emit_intent") as emit:
            demo.app(event, None)
            emit.assert_called_once()
    with caplog.at_level("INFO"):
        demo.emit_intent({"action_id": "local", "untrusted_field": "omit-this"}, None)
    assert "APP_INTENT" in caplog.text
    assert "omit-this" not in caplog.text


def test_audit_failure_has_no_success():
    with patch.object(demo, "table") as db:
        db.return_value.get_item.return_value = {}
        db.return_value.put_item.side_effect = RuntimeError("local storage unavailable")
        with pytest.raises(RuntimeError, match="local storage unavailable"):
            demo.saas({}, None)


def test_duplicate_retry_delayed_and_missing_evidence():
    result = run()
    e, i, a = result["expected"], result["intents"], result["audits"]
    assert analyze(e, i, a + a, now=1010, complete=True)[0]["category"] == "AUTHORIZED"
    assert analyze([], [], a, now=1001)[0]["category"] == "INCONCLUSIVE"
    assert analyze([], [], a, now=1010, complete=True)[0]["category"] == "UNAUTHORIZED_ACTION"
    assert analyze(e, [], a, now=1010, complete=True)[0]["category"] == "INCONCLUSIVE"
    assert analyze(e, i, [], now=1010, complete=True)[0]["category"] == "INCONCLUSIVE"
    second = {**a[0], "provider_request_id": "retry"}
    finding = analyze(e, i, a + [second], now=1010, complete=True)[0]
    assert finding["category"] == "SUSPICIOUS_REPLAY"
    assert "RETRY_OR_REPLAY_UNRESOLVED" in finding["reason_codes"]
    conflict = {**a[0], "outcome": "denied"}
    assert analyze(e, i, a + [conflict], now=1010, complete=True)[0]["category"] == "INCONCLUSIVE"


def test_token_not_in_logs_reports_or_transport_outputs(caplog):
    # A fixed mock value stays private to this test; failures disclose only booleans.
    private = "local-disposable-test-value-only"
    with patch.object(demo.secrets, "token_urlsafe", return_value=private):
        result = run(simulate_copy=True, suppress_intent=True)
    assert bool(private not in json.dumps(result) + caplog.text)
    assert "access_token" not in json.dumps(result)
    assert "token_hash" not in json.dumps(result)
