"""Measurement functions separate observed wall time, virtual lab time and calibration."""

import math
from typing import Any


def percentile(values: list[float], probability: float) -> float | None:
    if not 0 < probability <= 1:
        raise ValueError("percentile must be in (0,1]")
    if not values:
        return None
    if any(not math.isfinite(v) or v < 0 for v in values):
        raise ValueError("non-negative finite measurements required")
    return sorted(values)[max(0, math.ceil(len(values) * probability) - 1)]


def calibrate(
    delays: dict[str, list[float]], probability: float = 0.95, margin: float = 1.0
) -> dict[str, Any]:
    if margin < 0 or not math.isfinite(margin):
        raise ValueError("invalid calibration margin")
    result = {}
    for source, samples in delays.items():
        estimate = percentile(samples, probability)
        if estimate is None:
            raise ValueError("calibration requires healthy source observations")
        result[source] = {
            "deadline_seconds": estimate + margin,
            "sample_count": len(samples),
            "quantile": probability,
            "margin_seconds": margin,
        }
    return result


def reconstruction(expected: list[str], observed: list[str]) -> dict[str, Any]:
    truth, evidence = set(expected), set(observed)
    return {
        "expected": len(truth),
        "observed": len(evidence),
        "matched": len(truth & evidence),
        "completeness": len(truth & evidence) / len(truth) if truth else None,
        "precision": len(truth & evidence) / len(evidence) if evidence else None,
    }
