"""Run the real engine on source-attributed synthetic revocation evidence.

This is a deterministic local demonstration, not independent or live evidence.
It constructs the two evidence records supported by the existing reconciliation
contract and verifies that indexed and exhaustive reconciliation agree.
"""

import argparse
import json
from pathlib import Path

from sealed_telemetry.reconciliation import reconcile
from sealed_telemetry.schema import new_event

NOW = "2026-11-12T10:00:50+00:00"
HEALTH = {"gateway": True, "provider": True, "app": True}


def run(output: Path) -> dict[str, object]:
    output.mkdir(parents=True, exist_ok=False)
    fields = {
        "run_id": "esa-corroborated-synthetic-v1",
        "scenario_id": "post-revocation-provider-success",
        "actor_pseudonym": "synthetic-actor",
        "credential_fingerprint": "a" * 64,
        "resource_pseudonym": "synthetic-resource",
        "invocation_id": None,
        "action_id": None,
    }
    revocation = new_event(
        "responder",
        "RESPONSE_ACTION",
        event_time_utc="2026-11-12T10:00:00+00:00",
        operation="token:revoke:verify",
        outcome="success",
        **fields,
    )
    provider = new_event(
        "provider",
        "PROVIDER_ACTION",
        event_time_utc=NOW,
        operation="records:read",
        outcome="success",
        provider_request_id="synthetic-post-revocation-provider-request",
        **fields,
    )
    events = [revocation, provider]
    indexed = reconcile(events, NOW, HEALTH, candidate_mode="indexed")
    exhaustive = reconcile(events, NOW, HEALTH, candidate_mode="exhaustive")
    if indexed != exhaustive:
        raise AssertionError("candidate-mode finding mismatch")
    if not any(item["state"] == "CORROBORATED_SUSPECTED_ABUSE" for item in indexed):
        raise AssertionError("expected existing corroboration rule did not trigger")
    result: dict[str, object] = {
        "scenario": "post-revocation-provider-success",
        "evidence_origin": "synthetic source-attributed fixtures; not independent or live evidence",
        "indexed_exhaustive_equal": True,
        "findings": [
            {
                "state": item["state"],
                "reason_codes": item["reason_codes"],
                "correlated_event_ids": item["correlated_event_ids"],
            }
            for item in indexed
        ],
        "limitations": [
            "No provider accepted an actual post-revocation request in this local fixture.",
            "This demonstrates an existing reconciliation rule, not independent evidence.",
        ],
    }
    output.joinpath("demo.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("benchmarks/esa-corroborated-demo-v1"))
    print(json.dumps(run(parser.parse_args().output), indent=2))
