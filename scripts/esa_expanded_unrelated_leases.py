"""Versioned, seeded unrelated-lease evaluation using the real IBER engine."""

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from sealed_telemetry.evaluation import metrics
from sealed_telemetry.reconciliation import reconcile
from sealed_telemetry.schema import Evidence

VERSION = "esa-expanded-unrelated-leases-v1"
SEEDS = (8201, 8202, 8203)
TRIALS_PER_SCENARIO_SEED = 10
SCENARIOS = ("unrelated_lease_unmatched_provider", "unrelated_lease_benign_control")
BASE = datetime(2026, 11, 12, tzinfo=UTC)
HEALTH = {"gateway": True, "provider": True, "app": True}


def stable_id(label: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"{VERSION}:{label}"))


def evidence(
    label: str,
    source: str,
    event_type: str,
    seconds: int,
    action_id: str,
    invocation_id: str,
) -> Evidence:
    return Evidence(
        event_id=stable_id(f"event:{source}:{label}"),
        run_id=stable_id(f"run:{label.rsplit(':', 1)[0]}"),
        scenario_id=VERSION,
        source_id=source,
        event_type=event_type,
        event_time_utc=(BASE + timedelta(seconds=seconds)).isoformat(),
        actor_pseudonym="expanded-actor",
        credential_fingerprint="a" * 64,
        operation="records:read",
        resource_pseudonym="expanded-resource",
        invocation_id=invocation_id,
        action_id=action_id,
        provider_request_id=stable_id(f"provider:{label}") if source == "provider" else None,
    )


def case_events(scenario: str, seed: int, trial: int) -> list[Evidence]:
    """Return detector inputs only; no label or expected detector outcome is included."""
    prefix = f"{scenario}:{seed}:{trial}"
    leases = [(f"lease-{ordinal}-action", f"lease-{ordinal}-invocation") for ordinal in range(2)]
    events = []
    for ordinal, (action_id, invocation_id) in enumerate(leases):
        lease = f"{prefix}:lease:{ordinal}"
        events.extend(
            [
                evidence(lease, "gateway", "EXPECTED_ACTION", ordinal, action_id, invocation_id),
                evidence(lease, "app", "INTENT_CREATED", ordinal, action_id, invocation_id),
            ]
        )
    if scenario == "unrelated_lease_unmatched_provider":
        events.append(
            evidence(
                f"{prefix}:external",
                "provider",
                "PROVIDER_ACTION",
                10,
                "external-action",
                "external-invocation",
            )
        )
    elif scenario == "unrelated_lease_benign_control":
        for ordinal, (action_id, invocation_id) in enumerate(leases):
            events.append(
                evidence(
                    f"{prefix}:provider:{ordinal}",
                    "provider",
                    "PROVIDER_ACTION",
                    ordinal + 10,
                    action_id,
                    invocation_id,
                )
            )
    else:
        raise ValueError("unknown expanded scenario")
    return events


def ground_truth(scenario: str) -> dict[str, Any]:
    """Independent scenario label, intentionally called after reconciliation."""
    return {
        "attack": scenario == "unrelated_lease_unmatched_provider",
        "scenario": scenario,
        "expected_outcome": (
            "unmatched_provider_suspicious"
            if scenario == "unrelated_lease_unmatched_provider"
            else "all_provider_actions_consistent"
        ),
    }


def outcome(decisions: list[dict[str, Any]]) -> tuple[bool, bool, list[str]]:
    states = [decision["state"] for decision in decisions]
    return (
        any(state in {"SUSPICIOUS", "CORROBORATED_SUSPECTED_ABUSE"} for state in states),
        any(state in {"PENDING", "INCONCLUSIVE"} for state in states),
        states,
    )


def run(output: Path) -> dict[str, Any]:
    output.mkdir(parents=True, exist_ok=False)
    rows = []
    failures = []
    for scenario in SCENARIOS:
        for seed in SEEDS:
            for trial in range(TRIALS_PER_SCENARIO_SEED):
                events = case_events(scenario, seed, trial)
                now = (BASE + timedelta(seconds=120)).isoformat()
                indexed = reconcile(events, now, HEALTH, candidate_mode="indexed")
                exhaustive = reconcile(events, now, HEALTH, candidate_mode="exhaustive")
                if indexed != exhaustive:
                    failures.append(f"{scenario}:{seed}:{trial}:candidate-mode mismatch")
                prediction, inconclusive, states = outcome(indexed)
                label = ground_truth(scenario)
                if label["attack"] and not prediction:
                    failures.append(f"{scenario}:{seed}:{trial}:unmatched provider was not alerted")
                if not label["attack"] and prediction:
                    failures.append(f"{scenario}:{seed}:{trial}:benign lease control alerted")
                rows.append(
                    {
                        "scenario": scenario,
                        "seed": seed,
                        "trial": trial,
                        "attack": label["attack"],
                        "prediction": prediction,
                        "inconclusive": inconclusive,
                        "finding_states": states,
                        "indexed_exhaustive_equal": indexed == exhaustive,
                    }
                )
    summary = {
        "version": VERSION,
        "seeds": SEEDS,
        "trials_per_scenario_seed": TRIALS_PER_SCENARIO_SEED,
        "scenarios": SCENARIOS,
        "runs": len(rows),
        "scenario_counts": {
            scenario: sum(row["scenario"] == scenario for row in rows) for scenario in SCENARIOS
        },
        "metrics": metrics(rows),
        "mode_equivalence": all(row["indexed_exhaustive_equal"] for row in rows),
        "failures": failures,
        "limitations": (
            "Synthetic deterministic evidence; this supplements rather than changes the "
            "frozen 40-calibration/180-test study."
        ),
    }
    output.joinpath("summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    if failures:
        raise RuntimeError("expanded evaluation recorded failures")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("benchmarks/esa-expanded-unrelated-leases-v1-verified"),
    )
    print(json.dumps(run(parser.parse_args().output), indent=2))


if __name__ == "__main__":
    main()
