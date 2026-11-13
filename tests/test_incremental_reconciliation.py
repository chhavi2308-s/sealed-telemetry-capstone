"""Local late-evidence/revision behavior; no AWS event-driven pipeline is implied."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import pytest

from sealed_telemetry.reconciliation import Policy
from sealed_telemetry.schema import Evidence
from sealed_telemetry.storage import Ledger

BASE = datetime(2026, 11, 13, 12, 0, tzinfo=UTC)
RUN = "incremental-run"


def evidence(
    index: str, source: str, event_type: str, seconds: int = 0, **changes: Any
) -> Evidence:
    raw: dict[str, Any] = {
        "event_id": str(uuid5(NAMESPACE_URL, f"incremental:{index}")),
        "run_id": RUN,
        "scenario_id": "incremental",
        "source_id": source,
        "event_type": event_type,
        "event_time_utc": (BASE + timedelta(seconds=seconds)).isoformat(),
        "actor_pseudonym": "actor",
        "credential_fingerprint": "b" * 64,
        "operation": "files:upload",
        "resource_pseudonym": "invoice",
        "invocation_id": "invocation-1",
        "action_id": "action-1",
        "provider_request_id": "provider-1" if event_type == "PROVIDER_ACTION" else None,
    }
    raw.update(changes)
    return Evidence(**raw)


def configured_ledger(path: Path) -> Ledger:
    ledger = Ledger(path)
    for source in ("gateway", "provider", "app"):
        ledger.set_health(source, True, BASE.isoformat())
    return ledger


def test_late_evidence_creates_one_decision_revision_and_preserves_history(tmp_path: Path) -> None:
    ledger = configured_ledger(tmp_path / "incremental.sqlite")
    provider = evidence("provider", "provider", "PROVIDER_ACTION")
    ledger.ingest(provider.to_dict(), "provider", BASE.isoformat())
    first = ledger.reconcile_run(RUN, (BASE + timedelta(seconds=5)).isoformat())
    assert first[0]["state"] == "PENDING" and first[0]["revision"] == 1

    expected = evidence("expected", "gateway", "EXPECTED_ACTION")
    intent = evidence("intent", "app", "INTENT_CREATED")
    ledger.ingest(expected.to_dict(), "gateway", BASE.isoformat())
    ledger.ingest(intent.to_dict(), "app", BASE.isoformat())
    second = ledger.reconcile_run(RUN, (BASE + timedelta(seconds=6)).isoformat())
    provider_decision = next(row for row in second if row["case_id"] == first[0]["case_id"])
    assert provider_decision["state"] == "CONSISTENT"
    assert provider_decision["revision"] == 2
    history = ledger.history(first[0]["case_id"])
    assert [row["state"] for row in history] == ["PENDING", "CONSISTENT"]
    assert ledger.reconcile_run(RUN, (BASE + timedelta(seconds=7)).isoformat()) == second


def test_health_change_revises_but_does_not_replace_prior_decision(tmp_path: Path) -> None:
    ledger = configured_ledger(tmp_path / "health.sqlite")
    expected = evidence("expected", "gateway", "EXPECTED_ACTION")
    intent = evidence("intent", "app", "INTENT_CREATED")
    provider = evidence("provider", "provider", "PROVIDER_ACTION")
    for event in (expected, intent, provider):
        ledger.ingest(event.to_dict(), event.source_id, BASE.isoformat())
    initial = ledger.reconcile_run(RUN, (BASE + timedelta(seconds=5)).isoformat())
    assert initial[0]["state"] == "CONSISTENT"
    ledger.set_health("provider", False, (BASE + timedelta(seconds=6)).isoformat())
    revised = ledger.reconcile_run(RUN, (BASE + timedelta(seconds=7)).isoformat())
    assert revised[0]["state"] == "INCONCLUSIVE"
    assert revised[0]["reason_codes"] == ["SOURCE_UNHEALTHY_OR_UNKNOWN"]
    assert len(ledger.history(initial[0]["case_id"])) == 2


def test_conflicting_late_evidence_fails_before_reconciliation_state_changes(
    tmp_path: Path,
) -> None:
    ledger = configured_ledger(tmp_path / "conflict.sqlite")
    provider = evidence("provider", "provider", "PROVIDER_ACTION")
    ledger.ingest(provider.to_dict(), "provider", BASE.isoformat())
    baseline = ledger.reconcile_run(RUN, (BASE + timedelta(seconds=5)).isoformat())
    conflicting = evidence(
        "provider",
        "provider",
        "PROVIDER_ACTION",
        operation="files:delete",
    )
    with pytest.raises(ValueError, match="reused with different content"):
        ledger.ingest(conflicting.to_dict(), "provider", BASE.isoformat())
    assert ledger.reconcile_run(RUN, (BASE + timedelta(seconds=6)).isoformat()) == baseline


def test_incremental_bridge_preserves_indexed_exhaustive_decision_equivalence(
    tmp_path: Path,
) -> None:
    ledger = configured_ledger(tmp_path / "equivalence.sqlite")
    expected = evidence("expected", "gateway", "EXPECTED_ACTION")
    duplicate = evidence("duplicate", "gateway", "EXPECTED_ACTION")
    provider = evidence("provider", "provider", "PROVIDER_ACTION")
    for event in (expected, duplicate, provider):
        ledger.ingest(event.to_dict(), event.source_id, BASE.isoformat())
    now = (BASE + timedelta(seconds=5)).isoformat()
    indexed = ledger.reconcile_run(RUN, now, policy=Policy(), candidate_mode="indexed")
    exhaustive = ledger.reconcile_run(RUN, now, policy=Policy(), candidate_mode="exhaustive")
    assert [{key: value for key, value in row.items() if key != "revision"} for row in indexed] == [
        {key: value for key, value in row.items() if key != "revision"} for row in exhaustive
    ]
