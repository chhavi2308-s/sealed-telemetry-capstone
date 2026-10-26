"""Transactional local evidence ledger with producer replay conflict detection."""

import json
import sqlite3
from pathlib import Path
from typing import Any
from uuid import uuid4

from sealed_telemetry.schema import Evidence, canonical, digest, utcnow


class Ledger:
    """Local persistence only; filesystem administrators can change this database."""

    def __init__(self, path: Path):
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS evidence (
              event_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, raw TEXT NOT NULL,
              receipt TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS evidence_run ON evidence(run_id);
            CREATE TABLE IF NOT EXISTS decisions (
              case_id TEXT NOT NULL, revision INTEGER NOT NULL, body TEXT NOT NULL,
              PRIMARY KEY(case_id, revision));
            CREATE TABLE IF NOT EXISTS health (
              source TEXT PRIMARY KEY, healthy INTEGER NOT NULL, checked_at TEXT NOT NULL);
        """)

    def ingest(self, raw: dict[str, Any], source: str, received_at: str | None = None) -> str:
        event = Evidence.parse(raw, source)
        raw_hash = digest(raw)
        with self.db:
            old = self.db.execute(
                "SELECT receipt FROM evidence WHERE event_id=?", (event.event_id,)
            ).fetchone()
            if old:
                receipt = json.loads(old[0])
                if receipt["canonical_hash"] != raw_hash:
                    raise ValueError("event ID reused with different content")
                return str(receipt["collector_receipt_id"])
            receipt = {
                "collector_receipt_id": str(uuid4()),
                "collector_received_at_utc": received_at or utcnow(),
                "canonical_hash": raw_hash,
                "authenticated_source": source,
                "trust_tier": "untrusted" if source == "app" else "independent_lab",
                "integrity_version": "sha256-v1",
            }
            self.db.execute(
                "INSERT INTO evidence VALUES (?,?,?,?)",
                (
                    event.event_id,
                    event.run_id,
                    canonical(raw).decode(),
                    canonical(receipt).decode(),
                ),
            )
        return str(receipt["collector_receipt_id"])

    def events(self, run_id: str) -> list[Evidence]:
        return [Evidence.parse(x[0], x[0]["source_id"]) for x in self.records(run_id)]

    def records(self, run_id: str) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        return [
            (json.loads(r), json.loads(s))
            for r, s in self.db.execute(
                "SELECT raw,receipt FROM evidence WHERE run_id=? ORDER BY event_id", (run_id,)
            )
        ]

    def set_health(self, source: str, healthy: bool, now: str) -> None:
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO health VALUES (?,?,?)", (source, healthy, now))

    def health(self, now: str, ttl: float = 60) -> dict[str, bool]:
        from sealed_telemetry.schema import timestamp

        return {
            s: bool(h) and 0 <= (timestamp(now) - timestamp(t)).total_seconds() <= ttl
            for s, h, t in self.db.execute("SELECT * FROM health")
        }

    def append_decision(self, decision: dict[str, Any]) -> dict[str, Any]:
        with self.db:
            old = self.history(decision["case_id"])
            # Identical sweeps do not create extra decisions; late changes always do.
            comparable = {k: v for k, v in decision.items() if k != "decided_at"}
            if old and comparable == {
                k: v for k, v in old[-1].items() if k not in {"decided_at", "revision"}
            }:
                return old[-1]
            result = {**decision, "revision": len(old) + 1}
            self.db.execute(
                "INSERT INTO decisions VALUES (?,?,?)",
                (decision["case_id"], len(old) + 1, canonical(result).decode()),
            )
        return result

    def history(self, case_id: str) -> list[dict[str, Any]]:
        return [
            json.loads(r[0])
            for r in self.db.execute(
                "SELECT body FROM decisions WHERE case_id=? ORDER BY revision", (case_id,)
            )
        ]

    def verify(self, run_id: str) -> bool:
        return all(
            digest(raw) == receipt["canonical_hash"] for raw, receipt in self.records(run_id)
        )

    def close(self) -> None:
        self.db.close()
