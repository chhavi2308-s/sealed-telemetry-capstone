"""Offline Phase 4/5 paired timing; diagnostic graph output never decides findings."""

import argparse
import json
import statistics
import tempfile
import time
import tracemalloc
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from sealed_telemetry.reconciliation import reconcile
from sealed_telemetry.schema import Evidence
from sealed_telemetry.storage import Ledger

NOW = datetime(2026, 11, 13, tzinfo=UTC).isoformat()
HEALTH = {"gateway": True, "provider": True, "app": True}


def item(number: int, source: str, kind: str, bound: bool) -> Evidence:
    suffix = "shared" if bound else str(number)
    return Evidence(
        str(uuid5(NAMESPACE_URL, f"p45:{source}:{kind}:{number}")),
        "p45",
        "offline",
        source,
        kind,
        NOW,
        "actor",
        "a" * 64,
        "files:upload",
        "resource",
        invocation_id="invoke-" + suffix if bound else None,
        action_id="action-" + suffix if bound else None,
        provider_request_id="provider-" + str(number) if kind == "PROVIDER_ACTION" else None,
    )


def measured[T](call: Callable[[], T]) -> tuple[T, float, int]:
    tracemalloc.start()
    started = time.perf_counter_ns()
    result = call()
    elapsed = (time.perf_counter_ns() - started) / 1_000_000
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return result, elapsed, peak


def graph(size: int, repeats: int) -> dict[str, object]:
    expected = [item(i, "gateway", "EXPECTED_ACTION", True) for i in range(size)]
    observed = [item(size + i, "provider", "PROVIDER_ACTION", False) for i in range(size // 4)]
    events = expected + observed
    on: list[float] = []
    off: list[float] = []
    memory: list[int] = []
    for _ in range(repeats):
        left, elapsed, peak = measured(lambda: reconcile(events, NOW, HEALTH))
        right, other, _ = measured(lambda: reconcile(events, NOW, HEALTH, graph_diagnostics=False))
        if left != right:
            raise AssertionError("graph diagnostics changed findings")
        on.append(elapsed)
        off.append(other)
        memory.append(peak)
    return {
        "kind": "graph_enabled_disabled",
        "size": size,
        "repeats": repeats,
        "findings_equal": True,
        "enabled_samples_ms": on,
        "disabled_samples_ms": off,
        "enabled_median_ms": statistics.median(on),
        "disabled_median_ms": statistics.median(off),
        "peak_bytes_median": statistics.median(memory),
    }


def bridge(repeats: int) -> dict[str, object]:
    full: list[float] = []
    local: list[float] = []
    for _ in range(repeats):
        provider = item(1, "provider", "PROVIDER_ACTION", True)
        expected = item(2, "gateway", "EXPECTED_ACTION", True)
        intent = item(3, "app", "INTENT_CREATED", True)

        def full_run(
            provider: Evidence = provider,
            expected: Evidence = expected,
            intent: Evidence = intent,
        ) -> list[list[dict[str, object]]]:
            return [
                reconcile([provider], NOW, HEALTH),
                reconcile([provider, expected, intent], NOW, HEALTH),
            ]

        direct, elapsed, _ = measured(full_run)
        full.append(elapsed)
        with tempfile.TemporaryDirectory() as directory:
            ledger = Ledger(Path(directory) / "ledger.sqlite")
            try:
                for source in HEALTH:
                    ledger.set_health(source, True, NOW)

                def run(
                    ledger: Ledger = ledger,
                    provider: Evidence = provider,
                    expected: Evidence = expected,
                    intent: Evidence = intent,
                ) -> list[dict[str, object]]:
                    ledger.ingest(provider.to_dict(), "provider", NOW)
                    ledger.reconcile_run("p45", NOW)
                    ledger.ingest(expected.to_dict(), "gateway", NOW)
                    ledger.ingest(intent.to_dict(), "app", NOW)
                    return [
                        {"state": str(row["state"])} for row in ledger.reconcile_run("p45", NOW)
                    ]

                result, elapsed, _ = measured(run)
                local.append(elapsed)
                if [row["state"] for row in result] != [row["state"] for row in direct[1]]:
                    raise AssertionError("bridge changed findings")
            finally:
                ledger.close()
    return {
        "kind": "bridge_full",
        "repeats": repeats,
        "findings_equal": True,
        "full_samples_ms": full,
        "bridge_samples_ms": local,
        "full_median_ms": statistics.median(full),
        "bridge_median_ms": statistics.median(local),
        "limitation": "Bridge recomputes full runs and includes SQLite; no speedup claim.",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=5)
    args = parser.parse_args()
    if args.repeats < 5 or args.output.exists():
        raise ValueError("new output and at least five repeats required")
    args.output.mkdir(parents=True)
    args.output.joinpath("measurements.json").write_text(
        json.dumps(
            {"rows": [graph(100, args.repeats), graph(250, args.repeats), bridge(args.repeats)]},
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
