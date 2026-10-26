"""Offline demo, evidence verification, and experiment commands."""

import argparse
import json
from pathlib import Path

from sealed_telemetry.lab import SCENARIOS, run_scenario


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["demo", "verify", "experiment"])
    parser.add_argument("--scenario", choices=SCENARIOS, default="normal")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--trials", type=int, default=2)
    args = parser.parse_args()
    if args.command == "demo":
        result = run_scenario(args.output, args.scenario)
        print(
            json.dumps(
                {
                    "run_id": result["run_id"],
                    "mode": "local",
                    "states": [d["state"] for d in result["decisions"]],
                    "integrity_valid": result["integrity_valid"],
                }
            )
        )
    elif args.command == "verify":
        from sealed_telemetry.schema import digest

        data = json.loads((args.output / "report.json").read_text())
        valid = all(digest(r["event"]) == r["receipt"]["canonical_hash"] for r in data["timeline"])
        print(json.dumps({"integrity_valid": valid}))
        if not valid:
            raise SystemExit(1)
    else:
        from sealed_telemetry.evaluation import experiment

        print(json.dumps(experiment(args.output, args.seed, args.trials)))


if __name__ == "__main__":
    main()
