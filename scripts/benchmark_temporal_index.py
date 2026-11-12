"""Reproducible local comparison of IBER candidate modes; no AWS resources."""

import argparse
import json
import statistics
import time
import tracemalloc
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from random import Random
from uuid import NAMESPACE_URL, uuid5

from sealed_telemetry import reconciliation as engine
from sealed_telemetry.schema import Evidence

BASE = datetime(2026, 11, 12, tzinfo=UTC)
HEALTH = {"gateway": True, "provider": True, "app": True}


def event(i, source, kind, seconds, partition, *, action=None, invocation=None):
    return Evidence(
        event_id=str(uuid5(NAMESPACE_URL, f"esa-benchmark:{source}:{kind}:{i}")),
        run_id="esa-benchmark",
        scenario_id="esa",
        source_id=source,
        event_type=kind,
        event_time_utc=(BASE + timedelta(seconds=seconds)).isoformat(),
        actor_pseudonym=f"actor-{partition % 11}",
        credential_fingerprint=f"{partition % 97:064x}",
        operation="records:read" if partition % 2 else "records:export",
        resource_pseudonym=f"resource-{partition % 13}",
        invocation_id=invocation or f"invoke-{i}",
        action_id=action or f"action-{i}",
        provider_request_id=f"provider-{i}" if kind == "PROVIDER_ACTION" else None,
    )


def workload(name, size, seed):
    rng = Random(seed + size)  # noqa: S311 - deterministic corpus only
    expected = []
    if name == "dense":
        expected = [
            event(i, "gateway", "EXPECTED_ACTION", i % 31, 0, action="shared", invocation="shared")
            for i in range(size)
        ]
        observed = [
            replace(
                event(size + i, "provider", "PROVIDER_ACTION", 15, 0),
                action_id=None,
                invocation_id=None,
            )
            for i in range(max(1, size // 4))
        ]
    else:
        for i in range(size):
            partition = i if name == "unrelated" else i % (size // 8 + 1)
            expected.append(
                event(i, "gateway", "EXPECTED_ACTION", rng.randrange(0, 3600), partition)
            )
        observed = []
        for i, exp in enumerate(expected):
            if name == "concurrent":
                observed.append(
                    event(
                        size + i,
                        "provider",
                        "PROVIDER_ACTION",
                        (datetime.fromisoformat(exp.event_time_utc) - BASE).total_seconds(),
                        i % (size // 8 + 1),
                        action=exp.action_id,
                        invocation=exp.invocation_id,
                    )
                )
            elif name == "sparse":
                observed.append(
                    event(
                        size + i,
                        "provider",
                        "PROVIDER_ACTION",
                        (datetime.fromisoformat(exp.event_time_utc) - BASE).total_seconds()
                        + rng.choice((-5, 5)),
                        i % (size // 8 + 1),
                        action=exp.action_id,
                        invocation=exp.invocation_id,
                    )
                )
            else:
                observed.append(event(size + i, "provider", "PROVIDER_ACTION", 7200 + i, size + i))
    intents = [
        event(
            2 * size + i,
            "app",
            "INTENT_CREATED",
            (datetime.fromisoformat(obs.event_time_utc) - BASE).total_seconds(),
            i % (size // 8 + 1),
            action=obs.action_id,
            invocation=obs.invocation_id,
        )
        for i, obs in enumerate(observed)
    ]
    return expected, observed, intents


def measured(fn):
    tracemalloc.start()
    start = time.perf_counter_ns()
    value = fn()
    elapsed = time.perf_counter_ns() - start
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return value, elapsed / 1_000_000, peak


def counted(fn):
    original, calls = engine.matches, 0

    def wrapped(expected, observed, policy):
        nonlocal calls
        calls += 1
        return original(expected, observed, policy)

    engine.matches = wrapped
    try:
        value, elapsed, peak = measured(fn)
    finally:
        engine.matches = original
    return value, elapsed, peak, calls


def median(values):
    return {
        "median_ms": statistics.median(values),
        "min_ms": min(values),
        "max_ms": max(values),
        "stdev_ms": statistics.pstdev(values),
    }


def run(output: Path, repeats=5):
    output.mkdir(parents=True, exist_ok=False)
    rows = []
    for workload_name, sizes in (
        ("sparse", (250, 1000)),
        ("dense", (100, 250)),
        ("concurrent", (250, 1000)),
        ("unrelated", (250, 1000)),
    ):
        for size in sizes:
            expected, observed, intents = workload(workload_name, size, 20261112)
            policy = engine.Policy()
            exhaustive_sets = [
                engine.exhaustive_candidates(expected, obs, policy) for obs in observed
            ]
            build_times, build_peaks = [], []
            lookup_times, lookup_peaks, lookup_calls, candidate_counts = [], [], [], []
            for _ in range(repeats):
                index, build_ms, build_peak = measured(
                    lambda expected=expected: engine.ExpectedActionIndex(expected)
                )
                groups, lookup_ms, lookup_peak, calls = counted(
                    lambda index=index, observed=observed, policy=policy: [
                        index.candidates(obs, policy) for obs in observed
                    ]
                )
                if [[x.event_id for x in group] for group in groups] != [
                    [x.event_id for x in group] for group in exhaustive_sets
                ]:
                    raise AssertionError("candidate-set mismatch")
                build_times.append(build_ms)
                build_peaks.append(build_peak)
                lookup_times.append(lookup_ms)
                lookup_peaks.append(lookup_peak)
                lookup_calls.append(calls)
                candidate_counts.append(sum(map(len, groups)))
            mode = {}
            for candidate_mode in ("indexed", "exhaustive"):
                times, peaks, calls, decisions = [], [], [], None
                for _ in range(repeats):
                    corpus = expected + observed + intents

                    def reconcile_mode(
                        corpus=corpus,
                        policy=policy,
                        candidate_mode=candidate_mode,
                    ):
                        return engine.reconcile(
                            corpus,
                            (BASE + timedelta(seconds=3700)).isoformat(),
                            HEALTH,
                            policy,
                            candidate_mode=candidate_mode,
                        )

                    decisions, elapsed, peak, count = counted(reconcile_mode)
                    times.append(elapsed)
                    peaks.append(peak)
                    calls.append(count)
                mode[candidate_mode] = {
                    "runtime": median(times),
                    "peak_bytes_median": int(statistics.median(peaks)),
                    "predicate_calls_median": int(statistics.median(calls)),
                    "decisions": decisions,
                }
            if mode["indexed"]["decisions"] != mode["exhaustive"]["decisions"]:
                raise AssertionError("finding mismatch")
            rows.append(
                {
                    "workload": workload_name,
                    "size": size,
                    "expected": len(expected),
                    "observed": len(observed),
                    "index_build": {
                        "runtime": median(build_times),
                        "peak_bytes_median": int(statistics.median(build_peaks)),
                        "samples_ms": build_times,
                    },
                    "lookup": {
                        "runtime": median(lookup_times),
                        "peak_bytes_median": int(statistics.median(lookup_peaks)),
                        "predicate_calls_median": int(statistics.median(lookup_calls)),
                        "candidates_returned_median": int(statistics.median(candidate_counts)),
                        "samples_ms": lookup_times,
                    },
                    "indexed": {k: v for k, v in mode["indexed"].items() if k != "decisions"},
                    "exhaustive": {k: v for k, v in mode["exhaustive"].items() if k != "decisions"},
                    "candidate_sets_equal": True,
                    "findings_equal": True,
                }
            )
    output.joinpath("measurements.json").write_text(
        json.dumps({"seed": 20261112, "repeats": repeats, "rows": rows}, indent=2), encoding="utf-8"
    )
    return rows


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("benchmarks/esa-day2-final"))
    print(json.dumps(run(parser.parse_args().output), indent=2))
