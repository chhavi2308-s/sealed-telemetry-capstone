"""Run five real local IBER scenarios and compare indexed/exhaustive findings."""

import json
import sqlite3
from pathlib import Path

from sealed_telemetry.lab import run_scenario
from sealed_telemetry.reconciliation import reconcile
from sealed_telemetry.schema import Evidence

SCENARIOS = {
    "authorized_activity": "normal",
    "direct_oauth_token_replay": "replay-suppression",
    "benign_application_log_failure": "benign-log-failure",
    "delayed_evidence_arrival": "delayed-audit",
    "ambiguous_legitimate_retry": "legitimate-retry",
}
NOW = "2026-11-12T10:00:00+00:00"


def compact(decisions):
    return [
        {key: item[key] for key in ("case_id", "state", "reason_codes", "correlated_event_ids")}
        for item in decisions
    ]


def run(output: Path):
    output.mkdir(parents=True, exist_ok=False)
    results = {}
    for label, scenario in SCENARIOS.items():
        result = run_scenario(output / label, scenario, NOW)
        events = [
            Evidence.parse(row["event"], row["event"]["source_id"]) for row in result["timeline"]
        ]
        health = result["decisions"][0]["source_health_snapshot"] if result["decisions"] else {}
        now = result["decisions"][0]["decided_at"] if result["decisions"] else NOW
        indexed = reconcile(events, now, health, candidate_mode="indexed")
        exhaustive = reconcile(events, now, health, candidate_mode="exhaustive")
        if indexed != exhaustive or compact(indexed) != compact(result["decisions"]):
            raise AssertionError("engine equivalence failed")
        db = sqlite3.connect(output / label / "security.sqlite")
        revisions = [
            json.loads(row[0])
            for row in db.execute("SELECT body FROM decisions ORDER BY case_id, revision")
        ]
        db.close()
        results[label] = {
            "scenario": scenario,
            "integrity_valid": result["integrity_valid"],
            "evidence": [
                {
                    "event_id": event.event_id,
                    "source": event.source_id,
                    "type": event.event_type,
                    "outcome": event.outcome,
                }
                for event in events
            ],
            "indexed_findings": compact(indexed),
            "exhaustive_findings": compact(exhaustive),
            "revisions": compact(revisions),
            "equivalent": True,
        }
    output.joinpath("demo.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    return results


if __name__ == "__main__":
    print(json.dumps(run(Path("benchmarks/esa-day2-demo")), indent=2))
