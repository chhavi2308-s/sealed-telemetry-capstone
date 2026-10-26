"""Runnable deterministic fault scenarios against real local mock-provider code."""

import secrets
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from sealed_telemetry.provider import Provider
from sealed_telemetry.reconciliation import reconcile
from sealed_telemetry.reporting import report
from sealed_telemetry.schema import canonical, new_event, timestamp, utcnow
from sealed_telemetry.storage import Ledger

SCENARIOS = (
    "normal",
    "replay-suppression",
    "benign-log-failure",
    "delayed-audit",
    "collector-outage",
    "duplicate",
    "out-of-order",
    "expired-token",
    "clock-skew",
    "bulk",
    "provider-outage",
    "response-failure",
    "bound-replay",
    "containment-recovery",
    "tampering",
)


def run_scenario(directory: Path, scenario: str, start: str | None = None) -> dict[str, Any]:
    if scenario not in SCENARIOS:
        raise ValueError("unknown scenario")
    directory.mkdir(parents=True, exist_ok=False)
    now = start or utcnow()
    later = (timestamp(now) + timedelta(seconds=50)).isoformat()
    run_id, invocation_id, action_id = str(uuid4()), str(uuid4()), str(uuid4())
    provider = Provider(directory / "provider.sqlite", secrets.token_bytes(32))
    ledger = Ledger(directory / "security.sqlite")
    try:
        token, fingerprint = provider.issue(now, ttl=1 if scenario == "expired-token" else 300)
        fields = dict(
            run_id=run_id,
            scenario_id="lab-v1",
            event_time_utc=now,
            invocation_id=invocation_id,
            action_id=action_id,
            credential_fingerprint=fingerprint,
            actor_pseudonym="lab-integration",
            operation="records:read",
            resource_pseudonym="synthetic-records",
        )
        expectation = new_event("gateway", "EXPECTED_ACTION", **fields)
        ledger.ingest(expectation.to_dict(), "gateway", now)
        if scenario not in {"replay-suppression", "benign-log-failure"}:
            ledger.ingest(new_event("app", "INTENT_CREATED", **fields).to_dict(), "app", now)
        call_time = later if scenario == "expired-token" else now
        result = provider.call(
            token, call_time, run_id, "lab-v1", invocation_id=invocation_id, action_id=action_id
        )
        attack = scenario in {
            "replay-suppression",
            "response-failure",
            "bound-replay",
            "containment-recovery",
        }
        provider_requests = [result["provider_request_id"]]
        if attack:
            # Separate harness action uses the same exposed disposable credential.
            # No invocation or action ID is fabricated for external activity.
            replay_result = provider.call(
                token,
                now,
                run_id,
                "lab-v1",
                invocation_id=invocation_id if scenario == "bound-replay" else None,
                action_id=action_id if scenario == "bound-replay" else None,
            )
            provider_requests.append(replay_result["provider_request_id"])
        for source in ("app", "gateway", "provider"):
            ledger.set_health(source, scenario != "collector-outage", later)
        if scenario == "provider-outage":
            ledger.set_health("provider", False, later)
        initial = reconcile(ledger.events(run_id), now, ledger.health(now))
        for decision in initial:
            ledger.append_decision(decision)
        if scenario not in {"collector-outage", "provider-outage"}:
            provider.deliver(ledger, later if scenario == "delayed-audit" else now)
        if scenario == "duplicate":
            for event in ledger.events(run_id):
                ledger.ingest(event.to_dict(), event.source_id, later)
        if scenario == "clock-skew":
            # Evaluate before source time; the engine must retain uncertainty.
            later = (timestamp(now) - timedelta(seconds=40)).isoformat()
        if scenario == "bulk":
            for _ in range(20):
                extra = {**fields, "invocation_id": str(uuid4()), "action_id": str(uuid4())}
                ledger.ingest(
                    new_event("gateway", "EXPECTED_ACTION", **extra).to_dict(), "gateway", now
                )
                ledger.ingest(new_event("app", "INTENT_CREATED", **extra).to_dict(), "app", now)
                bulk_result = provider.call(
                    token,
                    now,
                    run_id,
                    "lab-v1",
                    invocation_id=extra["invocation_id"],
                    action_id=extra["action_id"],
                )
                provider_requests.append(bulk_result["provider_request_id"])
            provider.deliver(ledger, now)
        events = ledger.events(run_id)
        if scenario == "out-of-order":
            events.reverse()
        decisions = [
            ledger.append_decision(d) for d in reconcile(events, later, ledger.health(later))
        ]
        response: dict[str, Any] = {"status": "not_requested"}
        if scenario == "response-failure":
            from sealed_telemetry.response import contain

            response = contain(
                provider, token, later, run_id, "lab-v1", approved=True, inject_failure=True
            )
        if scenario == "containment-recovery":
            from sealed_telemetry.response import contain

            response = contain(provider, token, later, run_id, "lab-v1", approved=True)
            provider_requests.append(response["verification_request_id"])
            fresh, fresh_fingerprint = provider.issue(later)
            recovered_fields = {
                **fields,
                "event_time_utc": later,
                "credential_fingerprint": fresh_fingerprint,
                "action_id": str(uuid4()),
                "invocation_id": str(uuid4()),
            }
            for source, kind in (("gateway", "EXPECTED_ACTION"), ("app", "INTENT_CREATED")):
                ledger.ingest(new_event(source, kind, **recovered_fields).to_dict(), source, later)
            recovery = provider.call(
                fresh,
                later,
                run_id,
                "lab-v1",
                invocation_id=recovered_fields["invocation_id"],
                action_id=recovered_fields["action_id"],
            )
            response["recovery"] = "verified" if recovery["status"] == 200 else "unverified"
            provider_requests.append(recovery["provider_request_id"])
            provider.deliver(ledger, later)
            decisions = [
                ledger.append_decision(d)
                for d in reconcile(ledger.events(run_id), later, ledger.health(later))
            ]
        if scenario == "tampering":
            with ledger.db:
                ledger.db.execute(
                    "UPDATE evidence SET raw=replace(raw, 'records:read', 'records:evil')"
                )
        output = {**report(ledger, run_id, decisions), "response": response, "mode": "local"}
        (directory / "report.json").write_bytes(canonical(output))
        # Independent evaluation label written only after detector has completed.
        (directory / "ground-truth.json").write_bytes(
            canonical(
                {
                    "run_id": run_id,
                    "scenario": scenario,
                    "attack": attack,
                    "provider_status": result["status"],
                    "started_at": now,
                    "provider_request_ids": provider_requests,
                    "event_time_mode": "virtual",
                }
            )
        )
        return output
    finally:
        ledger.close()
        provider.close()
