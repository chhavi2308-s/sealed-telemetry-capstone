"""Independent local mock provider with opaque tokens and transactional audit outbox."""

import hashlib
import json
import secrets
import sqlite3
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from sealed_telemetry.schema import canonical, new_event, pseudonym, timestamp
from sealed_telemetry.storage import Ledger


class Provider:
    def __init__(self, path: Path, fingerprint_key: bytes):
        self.key = fingerprint_key
        self.db = sqlite3.connect(path)
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS tokens (
            hash TEXT PRIMARY KEY, token_id TEXT UNIQUE NOT NULL, scope TEXT NOT NULL,
            audience TEXT NOT NULL, expires TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
          CREATE TABLE IF NOT EXISTS integration (id INTEGER PRIMARY KEY, enabled INTEGER NOT NULL);
          INSERT OR IGNORE INTO integration VALUES (1,1);
          CREATE TABLE IF NOT EXISTS outbox (
            event_id TEXT PRIMARY KEY, body TEXT NOT NULL, delivered INTEGER NOT NULL DEFAULT 0);
        """)

    def issue(
        self,
        now: str,
        scope: str = "records:read",
        audience: str = "synthetic-saas",
        ttl: int = 300,
    ) -> tuple[str, str]:
        if scope not in {"records:read", "records:export"} or not 1 <= ttl <= 900:
            raise ValueError("unsupported lab scope or lifetime")
        token, token_id = secrets.token_urlsafe(32), str(uuid4())
        expires = (timestamp(now) + timedelta(seconds=ttl)).isoformat()
        with self.db:
            self.db.execute(
                "INSERT INTO tokens(hash,token_id,scope,audience,expires) VALUES(?,?,?,?,?)",
                (hashlib.sha256(token.encode()).hexdigest(), token_id, scope, audience, expires),
            )
        return token, pseudonym(self.key, token_id)

    def call(
        self,
        token: str,
        now: str,
        run_id: str,
        scenario_id: str,
        operation: str = "records:read",
        invocation_id: str | None = None,
        action_id: str | None = None,
    ) -> dict[str, Any]:
        row = self.db.execute(
            "SELECT token_id,scope,audience,expires,revoked FROM tokens WHERE hash=?",
            (hashlib.sha256(token.encode()).hexdigest(),),
        ).fetchone()
        enabled = bool(self.db.execute("SELECT enabled FROM integration WHERE id=1").fetchone()[0])
        valid = bool(
            enabled
            and row
            and row[1] == operation
            and row[2] == "synthetic-saas"
            and timestamp(row[3]) > timestamp(now)
            and not row[4]
        )
        fingerprint = pseudonym(self.key, row[0] if row else "invalid-token")
        event = new_event(
            "provider",
            "PROVIDER_ACTION",
            run_id=run_id,
            scenario_id=scenario_id,
            event_time_utc=now,
            actor_pseudonym="lab-integration",
            credential_fingerprint=fingerprint,
            operation=operation,
            resource_pseudonym="synthetic-records",
            outcome=("success" if valid else "denied"),
            invocation_id=invocation_id,
            action_id=action_id,
            provider_request_id=str(uuid4()),
        )
        # Read-only synthetic operation commits its audit before returning data.
        # If this transaction fails, no successful response is returned.
        with self.db:
            self.db.execute(
                "INSERT INTO outbox(event_id,body) VALUES(?,?)",
                (event.event_id, canonical(event.to_dict()).decode()),
            )
        return {
            "status": 200 if valid else 403,
            "provider_request_id": event.provider_request_id,
            "data": [{"id": "synthetic-001", "value": "lab-only"}] if valid else [],
        }

    def deliver(self, ledger: Ledger, received_at: str) -> int:
        count = 0
        for event_id, body in self.db.execute("SELECT event_id,body FROM outbox WHERE delivered=0"):
            ledger.ingest(json.loads(body), "provider", received_at)
            with self.db:
                self.db.execute("UPDATE outbox SET delivered=1 WHERE event_id=?", (event_id,))
            count += 1
        return count

    def revoke(self, token: str, fail: bool = False) -> None:
        if fail:
            raise TimeoutError("injected mock revocation timeout")
        with self.db:
            self.db.execute(
                "UPDATE tokens SET revoked=1 WHERE hash=?",
                (hashlib.sha256(token.encode()).hexdigest(),),
            )

    def scope_for(self, token: str) -> str:
        row = self.db.execute(
            "SELECT scope FROM tokens WHERE hash=?", (hashlib.sha256(token.encode()).hexdigest(),)
        ).fetchone()
        if row is None:
            raise ValueError("cannot verify containment for an unknown credential")
        return str(row[0])

    def set_integration(self, enabled: bool) -> None:
        if not isinstance(enabled, bool):
            raise ValueError("explicit boolean integration state required")
        with self.db:
            self.db.execute("UPDATE integration SET enabled=? WHERE id=1", (enabled,))

    def close(self) -> None:
        self.db.close()
