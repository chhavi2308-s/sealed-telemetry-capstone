"""Seeded local smoke experiments, with labels joined after detector execution."""

import json
import math
import random
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

from sealed_telemetry.lab import SCENARIOS, run_scenario
from sealed_telemetry.measurements import percentile, reconstruction
from sealed_telemetry.reconciliation import DEFAULT_POLICY, Policy, reconcile
from sealed_telemetry.schema import Evidence, canonical, digest, timestamp


def metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    tp = sum(r["attack"] and r["prediction"] for r in rows)
    fp = sum(not r["attack"] and r["prediction"] for r in rows)
    fn = sum(r["attack"] and not r["prediction"] for r in rows)
    tn = sum(not r["attack"] and not r["prediction"] for r in rows)

    def ratio(n: int, d: int) -> float | None:
        return n / d if d else None

    def wilson(n: int, d: int) -> list[float] | None:
        if not d:
            return None
        p, z = n / d, 1.96
        center = (p + z * z / (2 * d)) / (1 + z * z / d)
        half = z * math.sqrt(p * (1 - p) / d + z * z / (4 * d * d)) / (1 + z * z / d)
        return [max(0, center - half), min(1, center + half)]

    pending_count = sum(bool(r.get("pending", False)) for r in rows)
    inconclusive_count = sum(bool(r.get("inconclusive", False)) for r in rows)
    uncertainty_count = sum(
        bool(r.get("pending", False)) or bool(r.get("inconclusive", False)) for r in rows
    )
    alert_count = sum(bool(r["prediction"]) for r in rows)
    return {
        "n": len(rows),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
        "false_positive_rate": ratio(fp, fp + tn),
        # An alert is a SUSPICIOUS or CORROBORATED_SUSPECTED_ABUSE outcome.
        # PENDING and INCONCLUSIVE remain non-alert uncertainty states.
        "alert_count": alert_count,
        "alert_coverage": ratio(alert_count, len(rows)),
        "pending_count": pending_count,
        "pending_rate": ratio(pending_count, len(rows)),
        "inconclusive_count": inconclusive_count,
        "inconclusive_rate": ratio(inconclusive_count, len(rows)),
        "uncertainty_count": uncertainty_count,
        "uncertainty_rate": ratio(uncertainty_count, len(rows)),
        "recall_wilson_95": wilson(tp, tp + fn),
        "fpr_wilson_95": wilson(fp, fp + tn),
    }


def predictions(
    report: dict[str, Any], policy: Policy = DEFAULT_POLICY
) -> dict[str, tuple[bool, bool, bool]]:
    events = [Evidence.parse(r["event"], r["event"]["source_id"]) for r in report["timeline"]]
    observed = [e for e in events if e.event_type == "PROVIDER_ACTION"]
    intents = [e for e in events if e.event_type == "INTENT_CREATED"]
    findings = report["decisions"]
    now = report.get(
        "evaluated_at", findings[0]["decided_at"] if findings else "2026-10-26T10:01:00+00:00"
    )
    health = findings[0]["source_health_snapshot"] if findings else {}
    integrity = all(
        digest(r["event"]) == r["receipt"]["canonical_hash"] for r in report["timeline"]
    )

    def outcome(ds: list[dict[str, Any]]) -> tuple[bool, bool, bool]:
        return (
            any(d["state"] in {"SUSPICIOUS", "CORROBORATED_SUSPECTED_ABUSE"} for d in ds),
            any(d["state"] == "PENDING" for d in ds),
            any(d["state"] == "INCONCLUSIVE" for d in ds),
        )

    return {
        "app_only": (any(e.outcome == "failure" for e in intents), False, not bool(intents)),
        # Clearly defined weak baseline: missing invocation metadata on successful audit.
        "audit_only": (
            any(e.outcome == "success" and not e.invocation_id for e in observed),
            False,
            not bool(observed),
        ),
        "fixed_missing": (
            any(
                (timestamp(now) - timestamp(e.event_time_utc)).total_seconds() >= 15 for e in events
            )
            and len([e for e in observed if e.outcome == "success"]) != len(intents),
            False,
            not any(
                (timestamp(now) - timestamp(e.event_time_utc)).total_seconds() >= 15 for e in events
            ),
        ),
        "iber": outcome(findings) if integrity else (False, False, True),
        "without_deadlines": outcome(
            reconcile(
                events,
                now,
                health,
                replace(
                    policy, provider_deadline=0, gateway_deadline=0, app_deadline=0, clock_skew=0
                ),
            )
        ),
        "without_binding": outcome(
            reconcile(
                [replace(e, invocation_id="unbound", action_id="unbound") for e in events],
                now,
                health,
                policy,
            )
        ),
        "without_provider": outcome(
            reconcile([e for e in events if e.source_id != "provider"], now, health, policy)
        ),
        "without_integrity": outcome(findings),
    }


def experiment(directory: Path, seed: int, trials: int) -> dict[str, Any]:
    if trials < 1:
        raise ValueError("at least one trial required")
    directory.mkdir(parents=True, exist_ok=False)
    rng = random.Random(seed)  # noqa: S311 -- reproducible order, not security material
    order = [(s, n) for s in SCENARIOS for n in range(trials)]
    rng.shuffle(order)
    rows: list[dict[str, Any]] = []
    reconstruction_rows: list[dict[str, Any]] = []
    run_times: list[float] = []
    for index, (scenario, trial) in enumerate(order):
        target = directory / f"{index:04}-{scenario}-{trial}"
        start = time.perf_counter()
        result = run_scenario(target, scenario, "2026-10-26T10:00:00+00:00")
        elapsed = time.perf_counter() - start
        run_times.append(elapsed)
        outputs = predictions(result)
        label = json.loads((target / "ground-truth.json").read_text())
        reconstruction_rows.append(
            {
                "run_id": result["run_id"],
                **reconstruction(
                    label["provider_request_ids"],
                    [
                        e["event"]["provider_request_id"]
                        for e in result["timeline"]
                        if e["event"]["event_type"] == "PROVIDER_ACTION"
                    ],
                ),
            }
        )
        for detector, (pred, pending, inconclusive) in outputs.items():
            rows.append(
                {
                    "run_id": result["run_id"],
                    "detector": detector,
                    "attack": label["attack"],
                    "prediction": pred,
                    "pending": pending,
                    "inconclusive": inconclusive,
                    "local_runtime_seconds": elapsed,
                }
            )
    summary = {
        "mode": "local_smoke",
        "seed": seed,
        "trials_per_scenario": trials,
        "metrics": {
            d: metrics([r for r in rows if r["detector"] == d])
            for d in sorted({r["detector"] for r in rows})
        },
        "provider_reconstruction": reconstruction_rows,
        "local_harness_runtime_p50_seconds": percentile(run_times, 0.5),
        "local_harness_runtime_p95_seconds": percentile(run_times, 0.95),
        "aws_cost": None,
        "cloud_latency": None,
        "invocation_overhead": None,
        "limitations": "Virtual event times; not calibrated or held-out AWS results",
    }
    (directory / "observations.json").write_bytes(canonical(rows))
    (directory / "summary.json").write_bytes(canonical(summary))
    return summary
