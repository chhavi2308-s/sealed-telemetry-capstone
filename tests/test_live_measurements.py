import pytest

from scripts.analyze_measurements import analyze


def test_measurements_reject_local_and_preserve_missing_values():
    with pytest.raises(ValueError, match="live"):
        analyze({"mode": "local"})
    result = analyze(
        {
            "mode": "LIVE_AWS",
            "account": "synthetic-fixture",
            "region": "fixture",
            "observations": [{}],
        }
    )
    assert result["billed_cost"] is None
    assert result["measurements"]["detection_latency_seconds"]["p95"] is None


def test_paired_measurements_keep_negative_overhead_and_cost_scope():
    base = {
        "pair_id": "p",
        "function_arn": "synthetic-fixture",
        "memory_mb": 128,
        "comparison_scope": "emitter_only",
    }
    data = {
        "mode": "LIVE_AWS",
        "account": "synthetic-fixture",
        "region": "fixture",
        "observations": [
            {**base, "instrumented": True, "duration_ms": 9},
            {**base, "instrumented": False, "duration_ms": 10},
        ],
    }
    result = analyze(
        data,
        {
            "mode": "AWS_BILLED_COST",
            "account": "synthetic-fixture",
            "region": "fixture",
            "scope": "unit-test fixture, not a measured AWS bill",
            "cost_usd": 2,
            "invocations": 1000,
        },
    )
    assert result["measurements"]["paired_overhead_ms"]["mean"] == -1
    assert result["billed_cost"]["per_1000_invocations"] == 2
