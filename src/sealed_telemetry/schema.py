"""Strict source-bound evidence contract. Collector metadata is never producer supplied."""

import hashlib
import hmac
import json
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

SOURCE_TYPES = {
    "app": {"INTENT_CREATED"},
    "gateway": {"EXPECTED_ACTION"},
    "provider": {"PROVIDER_ACTION"},
    "health": {"SOURCE_HEALTH"},
    "responder": {"RESPONSE_ACTION", "EXPECTED_ACTION", "INTENT_CREATED"},
    "platform": {"LAMBDA_PLATFORM", "API_INGRESS"},
    "cloudtrail": {"AWS_API"},
    "approval": {"APPROVAL_DECISION"},
}


def utcnow() -> str:
    return datetime.now(UTC).isoformat()


def timestamp(value: str) -> datetime:
    result = datetime.fromisoformat(value)
    offset = result.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise ValueError("UTC timestamp required")
    return result


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def pseudonym(key: bytes, value: str) -> str:
    if len(key) < 32:
        raise ValueError("pseudonym key must have at least 256 bits")
    return hmac.new(key, value.encode(), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class Evidence:
    event_id: str
    run_id: str
    scenario_id: str
    source_id: str
    event_type: str
    event_time_utc: str
    actor_pseudonym: str
    credential_fingerprint: str
    operation: str
    resource_pseudonym: str
    outcome: str = "success"
    invocation_id: str | None = None
    action_id: str | None = None
    provider_request_id: str | None = None
    schema_version: str = "1"
    health_for_source: str | None = None
    source_health: str | None = None
    trace_context: dict[str, str] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def parse(cls, raw: dict[str, Any], authenticated_source: str) -> "Evidence":
        if len(canonical(raw)) > 16384:
            raise ValueError("evidence exceeds 16 KiB")
        try:
            event = cls(**raw)
        except TypeError as exc:
            raise ValueError("unknown or missing evidence fields") from exc
        if event.source_id != authenticated_source or authenticated_source not in SOURCE_TYPES:
            raise ValueError("source identity mismatch")
        if event.event_type not in SOURCE_TYPES[authenticated_source]:
            raise ValueError("event type forbidden for source")
        UUID(event.event_id)
        timestamp(event.event_time_utc)
        if event.schema_version != "1" or event.outcome not in {"success", "denied", "failure"}:
            raise ValueError("unsupported version/outcome")
        for name, value in raw.items():
            if name == "trace_context":
                if value is not None and (
                    not isinstance(value, dict)
                    or len(value) > 16
                    or any(
                        not isinstance(k, str)
                        or len(k) > 64
                        or not isinstance(v, str)
                        or len(v) > 1024
                        for k, v in value.items()
                    )
                ):
                    raise ValueError("invalid trace context")
                continue
            if value is not None and (not isinstance(value, str) or not value or len(value) > 256):
                raise ValueError(f"invalid field: {name}")
        if re.fullmatch(r"[a-f0-9]{64}", event.credential_fingerprint) is None:
            raise ValueError("HMAC fingerprint required")
        if event.event_type in {"EXPECTED_ACTION", "INTENT_CREATED"}:
            if not event.invocation_id or not event.action_id:
                raise ValueError("expected action requires invocation and action IDs")
        if event.event_type == "PROVIDER_ACTION" and not event.provider_request_id:
            raise ValueError("mock provider requires a request ID")
        if event.event_type == "SOURCE_HEALTH":
            if event.health_for_source not in {"app", "provider", "gateway", "collector"}:
                raise ValueError("unknown health source")
            if event.source_health not in {"healthy", "unhealthy", "unknown"}:
                raise ValueError("invalid source health")
        elif event.health_for_source is not None or event.source_health is not None:
            raise ValueError("only monitor may attest source health")
        return event


def new_event(source: str, event_type: str, **fields: Any) -> Evidence:
    return Evidence.parse(
        {"event_id": str(uuid4()), "source_id": source, "event_type": event_type, **fields},
        source,
    )
