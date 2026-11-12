"""Generate a local, integrity-checked forensic incident and tamper result; no AWS."""

import argparse
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from sealed_telemetry.lab import run_scenario
from sealed_telemetry.schema import digest


def verify_timeline(timeline: list[dict[str, Any]]) -> bool:
    return all(digest(item["event"]) == item["receipt"]["canonical_hash"] for item in timeline)


def run(output: Path) -> dict[str, Any]:
    output.mkdir(parents=True, exist_ok=False)
    run_scenario(output / "incident", "replay-suppression", "2026-11-12T10:00:00+00:00")
    report = json.loads((output / "incident" / "report.json").read_text(encoding="utf-8"))
    tampered = deepcopy(report["timeline"])
    tampered[0]["event"]["operation"] = "records:altered"
    revisions = []
    for decision in report["decisions"]:
        revisions.append(
            {key: value for key, value in decision.items() if key != "credential_fingerprint"}
        )
    result = {
        "source": "actual_local_forensic_export",
        "integrity_valid": report["integrity_valid"],
        "timeline_integrity_valid": verify_timeline(report["timeline"]),
        "tampered_timeline_integrity_valid": verify_timeline(tampered),
        "finding_revisions": revisions,
        "missing_sources": report["missing_sources"],
        "limitations": report["limitations"],
    }
    output.joinpath("forensic-summary.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8"
    )
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("benchmarks/esa-forensic-redacted"))
    print(json.dumps(run(parser.parse_args().output), indent=2))
