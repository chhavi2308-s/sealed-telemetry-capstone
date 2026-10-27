"""Frozen-policy parameter holdout stress evaluation; synthetic virtual times, never AWS timings."""

import argparse
import json
import random
from dataclasses import asdict, replace
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

from sealed_telemetry.evaluation import metrics, predictions
from sealed_telemetry.measurements import percentile, reconstruction
from sealed_telemetry.reconciliation import Policy, reconcile
from sealed_telemetry.schema import Evidence, canonical, digest, new_event, timestamp

CASES = (
    "normal",
    "replay",
    "copied-identifiers",
    "legitimate-retry",
    "bulk",
    "delayed",
    "missing-provider",
    "collector-outage",
    "duplicate",
    "out-of-order",
    "clock-skew",
    "tampering",
    "response-failure",
    "missing-identifiers",
)


def generate(rng: random.Random, case: str) -> tuple[list[tuple[float, Evidence]], dict[str, Any]]:
    def uid() -> str:
        return str(UUID(int=rng.getrandbits(128), version=4))

    base = "2026-10-27T00:00:00+00:00"
    run_id, invocation_id, action_id = uid(), uid(), uid()
    fields = dict(
        run_id=run_id,
        scenario_id="holdout-v1",
        event_time_utc=base,
        invocation_id=invocation_id,
        action_id=action_id,
        actor_pseudonym="lab-integration",
        credential_fingerprint=digest(uid()),
        operation="records:read",
        resource_pseudonym="synthetic-records",
    )
    items: list[tuple[float, Evidence]] = []
    provider_ids = []

    def add(source: str, kind: str, delay: float, **extra: Any) -> None:
        event = new_event(source, kind, **{**fields, **extra})
        event = replace(event, event_id=uid())
        items.append((delay, event))
        if source == "provider":
            provider_ids.append(event.provider_request_id)

    add("gateway", "EXPECTED_ACTION", rng.uniform(0, 4))
    add("app", "INTENT_CREATED", rng.uniform(0, 5))
    skew = rng.choice([-30, -10, 0, 10, 30]) if case == "clock-skew" else 0
    provider_time = (timestamp(base) + timedelta(seconds=skew)).isoformat()
    add(
        "provider",
        "PROVIDER_ACTION",
        rng.uniform(0, 5),
        event_time_utc=provider_time,
        provider_request_id=uid(),
        **({"invocation_id": None, "action_id": None} if case == "missing-identifiers" else {}),
    )
    attack = case in {"replay", "copied-identifiers", "response-failure"}
    if attack or case == "legitimate-retry":
        copied = case in {"copied-identifiers", "legitimate-retry"}
        add(
            "provider",
            "PROVIDER_ACTION",
            rng.uniform(1, 8),
            provider_request_id=uid(),
            invocation_id=invocation_id if copied else None,
            action_id=action_id if copied else None,
        )
    if case == "bulk":
        for _ in range(rng.randint(5, 30)):
            action = {"invocation_id": uid(), "action_id": uid()}
            add("gateway", "EXPECTED_ACTION", rng.uniform(0, 5), **action)
            add("app", "INTENT_CREATED", rng.uniform(0, 5), **action)
            add(
                "provider",
                "PROVIDER_ACTION",
                rng.uniform(0, 8),
                provider_request_id=uid(),
                **action,
            )
    if case == "delayed":
        items = [
            (rng.uniform(35, 100) if e.source_id == "provider" else delay, e) for delay, e in items
        ]
    if case in {"missing-provider", "collector-outage"}:
        items = [(d, e) for d, e in items if e.source_id != "provider"]
    if case == "duplicate":
        items += [(d + 1, e) for d, e in items[:]]
    if case == "out-of-order":
        items = [(rng.uniform(0, 40), e) for _, e in items]
    return items, {
        "run_id": run_id,
        "case": case,
        "attack": attack,
        "provider_request_ids": provider_ids,
        "start": base,
        "response_fault_injected": case == "response-failure",
    }


def run(directory: Path, seeds: list[int], trials: int) -> dict[str, Any]:
    if trials < 1 or not seeds or len(set(seeds)) != len(seeds):
        raise ValueError("positive trials and distinct seeds required")
    directory.mkdir(parents=True, exist_ok=False)
    policy = Policy()
    protocol = {
        "version": "parameter-holdout-v2",
        "seeds": seeds,
        "trials": trials,
        "cases": CASES,
        "policy": asdict(policy),
        "classification": ("Any alert in 150 seconds counts, including later-revised alerts"),
        "poll_interval_seconds": 5,
        "generator_hash": digest(Path(__file__).read_text(encoding="utf-8")),
        "limitations": (
            "Post-development synthetic parameter holdout; not blind external validation. "
            "No tuning on test results. Virtual delivery/event times."
        ),
    }
    (directory / "protocol.json").write_bytes(canonical(protocol))
    rows = []
    labels = []
    dataset = []
    completeness = []
    for seed in seeds:
        rng = random.Random(seed)  # noqa: S311 -- deterministic synthetic events, never credentials
        for case in CASES:
            for trial in range(trials):
                arrivals, label = generate(rng, case)
                visible = {}
                first_detection: dict[str, int] = {}
                report: dict[str, Any] = {}
                health = {
                    s: case != "collector-outage"
                    for s in ["gateway", "provider", "app", "collector"]
                }
                if case == "missing-provider":
                    health["provider"] = False
                for tick in range(0, 151, 5):
                    for delay, e in arrivals:
                        if delay <= tick:
                            visible[e.event_id] = e
                    now = (timestamp(label["start"]) + timedelta(seconds=tick)).isoformat()
                    decisions = reconcile(list(visible.values()), now, health, policy)
                    report = {
                        "timeline": [
                            {
                                "event": e.to_dict(),
                                "receipt": {"canonical_hash": digest(e.to_dict())},
                            }
                            for e in visible.values()
                        ],
                        "decisions": decisions,
                    }
                    if case == "tampering" and report["timeline"]:
                        report["timeline"][0]["receipt"]["canonical_hash"] = "0" * 64
                    for name, (predicted, _) in predictions(report).items():
                        if predicted and name not in first_detection:
                            first_detection[name] = tick
                for detector, (prediction, uncertain) in predictions(report).items():
                    rows.append(
                        {
                            "run_id": label["run_id"],
                            "seed": seed,
                            "trial": trial,
                            "detector": detector,
                            "prediction": detector in first_detection,
                            "final_prediction": prediction,
                            "inconclusive": uncertain,
                            "attack": label["attack"],
                            "virtual_detection_latency_seconds": first_detection.get(detector)
                            if label["attack"]
                            else None,
                        }
                    )
                dataset.append(
                    {
                        "run_id": label["run_id"],
                        "health": health,
                        "arrivals": [
                            {"received_offset_seconds": d, "event": e.to_dict()}
                            for d, e in arrivals
                        ],
                    }
                )
                labels.append(label)
                completeness.append(
                    reconstruction(
                        label["provider_request_ids"],
                        [
                            e.provider_request_id
                            for e in visible.values()
                            if e.source_id == "provider" and e.provider_request_id is not None
                        ],
                    )
                )
    summary = {
        "mode": "synthetic_parameter_holdout",
        "protocol_hash": digest(protocol),
        "runs": len(labels),
        "metrics": {
            d: metrics([r for r in rows if r["detector"] == d])
            for d in sorted({r["detector"] for r in rows})
        },
        "iber_virtual_detection_p50_seconds": percentile(
            [
                r["virtual_detection_latency_seconds"]
                for r in rows
                if r["detector"] == "iber" and r["virtual_detection_latency_seconds"] is not None
            ],
            0.5,
        ),
        "forensic_completeness": sum(r["completeness"] for r in completeness) / len(completeness),
        "cloud_detection_latency": None,
        "containment_latency": None,
        "cloud_invocation_overhead": None,
        "billed_aws_cost": None,
        "limitations": protocol["limitations"],
    }
    for filename, value in [
        ("detector-inputs", dataset),
        ("ground-truth", labels),
        ("observations", rows),
        ("summary", summary),
    ]:
        (directory / f"{filename}.json").write_bytes(canonical(value))
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seeds", type=int, nargs="+", default=[3101, 3102, 3103])
    parser.add_argument("--trials", type=int, default=5)
    args = parser.parse_args()
    print(json.dumps(run(args.output, args.seeds, args.trials), indent=2))


if __name__ == "__main__":
    main()
