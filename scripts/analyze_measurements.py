"""Summarize supplied live measurements; never convert local timings into AWS results."""

import argparse
import json
import math
from pathlib import Path
from typing import Any

from sealed_telemetry.measurements import percentile


def numeric(value: Any, signed: bool = False) -> float:
    if type(value) not in {int, float} or not math.isfinite(value) or (value < 0 and not signed):
        raise ValueError("finite measurements with explicit units required")
    return float(value)


def analyze(data: dict[str, Any], billing: dict[str, Any] | None = None) -> dict[str, Any]:
    if data.get("mode") != "LIVE_AWS" or not data.get("account") or not data.get("region"):
        raise ValueError(
            "live account/region provenance required; local simulation is not cloud measurement"
        )
    rows = data.get("observations", data.get("scenarios", []))
    if not rows:
        raise ValueError("nonempty live observations required")
    if any(r.get("mode", "LIVE_AWS") != "LIVE_AWS" for r in rows):
        raise ValueError("mixed local/cloud observations forbidden")
    summary = {}
    for name in [
        "client_observed_evidence_seconds",
        "detection_latency_seconds",
        "containment_latency_seconds",
    ]:
        values = [
            numeric(r[name])
            for r in rows
            if r.get(name) is not None
            and (name != "client_observed_evidence_seconds" or r.get("first_report_observed_at"))
        ]
        summary[name] = {
            "n": len(values),
            "missing_or_censored": len(rows) - len(values),
            "p50": percentile(values, 0.5),
            "p95": percentile(values, 0.95),
        }
    pairs: dict[str, dict[bool, dict[str, Any]]] = {}
    for row in rows:
        if row.get("pair_id") is None:
            continue
        if type(row.get("instrumented")) is not bool:
            raise ValueError("explicit paired condition required")
        group = pairs.setdefault(row["pair_id"], {})
        if row["instrumented"] in group:
            raise ValueError("duplicate paired condition")
        group[row["instrumented"]] = row
    deltas = []
    for group in pairs.values():
        if set(group) != {True, False}:
            raise ValueError("incomplete latency pair")
        on, off = group[True], group[False]
        if (
            not on.get("function_arn")
            or not on.get("memory_mb")
            or not on.get("comparison_scope")
            or any(
                on.get(k) != off.get(k) for k in ["function_arn", "memory_mb", "comparison_scope"]
            )
        ):
            raise ValueError("paired environment/scope mismatch")
        deltas.append(numeric(on["duration_ms"]) - numeric(off["duration_ms"]))
    ordered = sorted(deltas)
    summary["paired_overhead_ms"] = {
        "n": len(deltas),
        "mean": sum(deltas) / len(deltas) if deltas else None,
        "p50": ordered[max(0, math.ceil(len(ordered) * 0.5) - 1)] if ordered else None,
        "p95": ordered[max(0, math.ceil(len(ordered) * 0.95) - 1)] if ordered else None,
        "incomplete_pairs": 0,
        "note": "Signed observed differences; negative values are not clamped",
    }
    cost = None
    if billing is not None:
        if (
            billing.get("mode") != "AWS_BILLED_COST"
            or any(billing.get(k) != data[k] for k in ["account", "region"])
            or not billing.get("scope")
        ):
            raise ValueError("matching billed period/project scope required")
        amount = numeric(billing["cost_usd"])
        count = billing["invocations"]
        if type(count) is not int or count < 0:
            raise ValueError("nonnegative invocation count required")
        cost = {
            "total_usd": amount,
            "scope": billing["scope"],
            "per_1000_invocations": amount * 1000 / count if count else None,
        }
    return {
        "mode": "measurement_analysis",
        "account": data["account"],
        "region": data["region"],
        "measurements": summary,
        "billed_cost": cost,
        "limitations": [
            "Input provenance must be independently checked against original AWS evidence",
            "Client evidence waits include network/polling, not native Lambda overhead",
            "Missing values stay null; this is not final AWS acceptance",
        ],
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--observations", type=Path, required=True)
    p.add_argument("--billing", type=Path)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    data = json.loads(args.observations.read_text(encoding="utf-8"))
    billing = json.loads(args.billing.read_text(encoding="utf-8")) if args.billing else None
    args.output.write_text(json.dumps(analyze(data, billing), indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
