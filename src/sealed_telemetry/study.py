"""Scenario-disjoint, benign-only virtual calibration followed by frozen-policy evaluation."""

import argparse
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from sealed_telemetry.holdout import CASES, run
from sealed_telemetry.measurements import calibrate
from sealed_telemetry.reconciliation import Policy
from sealed_telemetry.schema import canonical, digest

CALIBRATION_CASES = ("normal", "delayed", "bulk", "clock-skew")
TEST_CASES = tuple(c for c in CASES if c not in CALIBRATION_CASES) + (
    "replay-suppression",
    "benign-log-failure",
)


def study(directory: Path, trials: int = 5) -> dict[str, Any]:
    if trials < 1:
        raise ValueError("positive trial count required")
    if set(CALIBRATION_CASES) & set(TEST_CASES):
        raise ValueError("scenario split overlaps")
    directory.mkdir(parents=True, exist_ok=False)
    calibration_seeds = [1101, 1102]
    test_seeds = [5101, 5102, 5103]
    protocol = {
        "version": "scenario-disjoint-v1",
        "calibration_cases": CALIBRATION_CASES,
        "test_cases": TEST_CASES,
        "calibration_seeds": calibration_seeds,
        "test_seeds": test_seeds,
        "trials_per_case_seed": trials,
        "quantile": 0.95,
        "margin_seconds": 1,
        "clock_skew_bound_seconds": 30,
        "matching_window_seconds": 60,
        "retune_after_test": False,
        "fixed_comparison_policy": asdict(Policy()),
        "target": "unauthorized OAuth replay",
        "mode": "synthetic_virtual_time",
        "limitations": "Virtual scenario holdout; not blind validation or AWS calibration",
    }
    (directory / "study-protocol.json").write_bytes(canonical(protocol))
    run(directory / "calibration", calibration_seeds, trials, CALIBRATION_CASES)
    inputs = json.loads(
        (directory / "calibration/detector-inputs.json").read_text(encoding="utf-8")
    )
    delays: dict[str, list[float]] = {source: [] for source in ["app", "provider", "gateway"]}
    for record in inputs:
        for arrival in record["arrivals"]:
            source = arrival["event"]["source_id"]
            if source in delays:
                delays[source].append(arrival["received_offset_seconds"])
    calibrated = calibrate(delays, probability=0.95, margin=1)
    policy = Policy(
        app_deadline=calibrated["app"]["deadline_seconds"],
        provider_deadline=calibrated["provider"]["deadline_seconds"],
        gateway_deadline=calibrated["gateway"]["deadline_seconds"],
    )
    frozen = {
        "policy": asdict(policy),
        "calibration": calibrated,
        "calibration_inputs_sha256": digest(inputs),
        "study_protocol_sha256": digest(protocol),
        "warning": "Synthetic transport offsets only; this policy is not AWS calibration",
    }
    (directory / "frozen-policy.json").write_bytes(canonical(frozen))
    result = run(directory / "test", test_seeds, trials, TEST_CASES, policy)
    fixed = run(directory / "fixed-policy-test", test_seeds, trials, TEST_CASES, Policy())
    summary = {
        "study_protocol_sha256": digest(protocol),
        "frozen_policy_sha256": digest(frozen),
        "scenario_sets_disjoint": True,
        "calibration_runs": len(inputs),
        "test": result,
        "fixed_policy_test": fixed,
        "limitations": protocol["limitations"],
    }
    (directory / "summary.json").write_bytes(canonical(summary))
    return summary


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--trials", type=int, default=5)
    args = p.parse_args()
    print(json.dumps(study(args.output, args.trials), indent=2))


if __name__ == "__main__":
    main()
