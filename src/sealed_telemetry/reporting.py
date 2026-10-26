"""Sanitized forensic report; hashes establish byte integrity, not event truth."""

from typing import Any

from sealed_telemetry.schema import timestamp
from sealed_telemetry.storage import Ledger


def report(ledger: Ledger, run_id: str, decisions: list[dict[str, Any]]) -> dict[str, Any]:
    records = ledger.records(run_id)
    return {
        "run_id": run_id,
        "integrity_valid": ledger.verify(run_id),
        "timeline": sorted(
            [{"event": raw, "receipt": receipt} for raw, receipt in records],
            key=lambda r: (timestamp(r["event"]["event_time_utc"]), r["event"]["event_id"]),
        ),
        "decisions": decisions,
        "missing_sources": sorted({s for d in decisions for s in d["missing_expected_sources"]}),
        "limitations": [
            "Local filesystem is not WORM or an IAM boundary",
            "Timestamp order is not proof of causal order",
            "Hash verification cannot prove truth or completeness",
            "Unmatched activity does not establish how a credential was obtained",
        ],
    }
