"""Offline projections of existing four-stage records, not complete IBER Evidence.

The caller must collect records through authenticated, independently controlled reads.
An allowlisted ARN and a digest document provenance; neither authenticates a file.
No SDK, credentials, source-health inference, or cross-record binding is used here.
"""

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from sealed_telemetry.schema import Evidence, canonical, digest, timestamp

VERSION = "four-stage-evidence-1"
MAX_RECORDS = 1000
MAX_BYTES = 16384
SOURCES = {"gateway": "EXPECTED_ACTION", "app": "APP_INTENT", "provider": "PROVIDER_ACTION"}
FIELDS = {
    "gateway": {
        "event_type",
        "action_id",
        "operation",
        "filename",
        "authorized_at",
        "authorization_expires_at",
        "expires_at",
    },
    "app": {
        "event_type",
        "event_id",
        "action_id",
        "operation",
        "filename",
        "recorded_at",
        "invocation_id",
    },
    "provider": {
        "event_type",
        "provider_request_id",
        "action_id",
        "operation",
        "filename",
        "outcome",
        "recorded_at",
        "synthetic",
        "expires_at",
    },
}


@dataclass(frozen=True)
class CollectedRecord:
    """Collector-owned metadata, supplied separately from the producer payload.

    native_id is the DynamoDB primary-key value or CloudWatch log-event ID.
    Log resource_arn identifies the exact stream, not just the log group.
    """

    resource_arn: str
    native_id: str
    collected_at_utc: str
    payload: Mapping[str, Any]


@dataclass(frozen=True)
class Provenance:
    resource_arn: str
    native_id: str
    collected_at_utc: str
    payload_hash: str
    trust_tier: str
    normalization_version: str = VERSION


@dataclass(frozen=True)
class FourStageObservation:
    """Partial evidence. None means not observed, never a shared placeholder identity."""

    event_id: str
    source_id: str
    event_type: str
    event_time_utc: str
    action_id: str | None
    operation: str | None
    resource_name: str | None
    outcome: str | None
    invocation_id: str | None
    provider_request_id: str | None
    producer_event_id: str | None
    authorization_expires_at_utc: str | None
    provenance: Provenance
    credential_fingerprint: None = None
    actor_pseudonym: None = None

    @property
    def missing_iber_fields(self) -> tuple[str, ...]:
        # Run/scenario are experiment metadata, not recoverable from these records.
        missing = [
            "run_id",
            "scenario_id",
            "actor_pseudonym",
            "credential_fingerprint",
            "resource_pseudonym",
        ]
        if self.operation is None:
            missing.append("operation")
        if self.source_id in {"gateway", "app"}:
            if self.action_id is None:
                missing.append("action_id")
            if self.invocation_id is None:
                missing.append("invocation_id")
        return tuple(missing)

    def to_evidence(self) -> Evidence:
        """Fail closed: legacy observations cannot enter credential reconciliation."""
        raise ValueError(
            "FOUR_STAGE_IBER_CONTRACT_INCOMPLETE: " + ",".join(self.missing_iber_fields)
        )

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "missing_iber_fields": list(self.missing_iber_fields)}


@dataclass(frozen=True)
class NormalizationIssue:
    # Index only: rejected payloads, ARNs and arbitrary exception text are not exported.
    record_index: int
    reason_code: str


@dataclass(frozen=True)
class NormalizationResult:
    observations: tuple[FourStageObservation, ...]
    issues: tuple[NormalizationIssue, ...]


def text(value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise ValueError("invalid text")
    return value


def epoch(value: Any) -> str:
    # boto3's DynamoDB resource returns Decimal; accept only exact integral seconds.
    if isinstance(value, Decimal):
        if not value.is_finite() or value != value.to_integral_value():
            raise ValueError("integral epoch required")
        value = int(value)
    if type(value) is not int or not 0 <= value <= 253402300799:
        raise ValueError("integral epoch required")
    return datetime.fromtimestamp(value, UTC).isoformat()


def validate_sources(source_resources: Mapping[str, str]) -> None:
    """Exact resource allowlist is trusted configuration, never producer input."""
    for arn, source in source_resources.items():
        if source not in SOURCES or not isinstance(arn, str):
            raise ValueError("invalid source configuration")
        parts = arn.split(":", 5)
        service = "logs" if source == "app" else "dynamodb"
        if (
            len(parts) != 6
            or parts[0] != "arn"
            or parts[1] not in {"aws", "aws-cn", "aws-us-gov"}
            or parts[2] != service
            or not parts[3]
            or len(parts[4]) != 12
            or not parts[4].isdigit()
            or "*" in arn
            or "?" in arn
        ):
            raise ValueError("invalid source configuration")
        resource = parts[5]
        if source == "app":
            if not resource.startswith("log-group:") or ":log-stream:" not in resource:
                raise ValueError("exact log stream required")
            group, stream = resource.removeprefix("log-group:").split(":log-stream:", 1)
            if not group or not stream:
                raise ValueError("exact log stream required")
        elif not resource.startswith("table/") or not resource[6:] or "/" in resource[6:]:
            raise ValueError("exact table required")


def _normalize_one(record: CollectedRecord, source: str) -> FourStageObservation:
    text(record.native_id)
    collected = timestamp(record.collected_at_utc).isoformat()
    raw = dict(record.payload)
    if raw.keys() - FIELDS[source] or raw.get("event_type") != SOURCES[source]:
        raise ValueError("unsupported producer fields or type")
    # Decimal -> integer is a lossless canonicalization, not a float conversion.
    for name in ("authorized_at", "authorization_expires_at", "recorded_at", "expires_at"):
        if name in raw:
            epoch(raw[name])
            raw[name] = int(raw[name])
    if len(canonical(raw)) > MAX_BYTES:
        raise ValueError("record too large")
    action: str | None = text(raw.get("action_id"))
    operation: str | None = text(raw.get("operation"))
    resource: str | None = text(raw.get("filename"))
    # The provider writes these literal sentinels for absent request fields.
    if source == "provider":
        action = None if action == "unknown" else action
        operation = None if operation == "unknown" else operation
        resource = None if resource == "unknown" else resource
    expiry = None
    provider_id = None
    outcome = None
    if source == "gateway":
        event_time = epoch(raw["authorized_at"])
        expiry = epoch(raw["authorization_expires_at"])
        if timestamp(expiry) <= timestamp(event_time) or record.native_id != action:
            raise ValueError("invalid authorization or native key")
    else:
        event_time = epoch(raw["recorded_at"])
    producer_id = text(raw["event_id"]) if source == "app" else None
    invocation = raw.get("invocation_id") if source == "app" else None
    if invocation is not None:
        invocation = text(invocation)
    if source == "provider":
        provider_id = text(raw.get("provider_request_id"))
        outcome = raw.get("outcome")
        if (
            provider_id != record.native_id
            or outcome not in {"success", "denied"}
            or raw.get("synthetic") is not True
        ):
            raise ValueError("invalid synthetic provider receipt")
    # Native source identity, not an app-controlled event ID, namespaces deduplication.
    normalized_id = str(
        uuid5(NAMESPACE_URL, canonical([record.resource_arn, record.native_id]).decode())
    )
    return FourStageObservation(
        event_id=normalized_id,
        source_id=source,
        event_type="INTENT_CREATED" if source == "app" else SOURCES[source],
        event_time_utc=event_time,
        action_id=action,
        operation=operation,
        resource_name=resource,
        outcome=outcome,
        invocation_id=invocation,
        provider_request_id=provider_id,
        producer_event_id=producer_id,
        authorization_expires_at_utc=expiry,
        provenance=Provenance(
            resource_arn=record.resource_arn,
            native_id=record.native_id,
            collected_at_utc=collected,
            payload_hash=digest(raw),
            trust_tier="untrusted_app_claim" if source == "app" else "independent_lab_record",
        ),
    )


def normalize(
    records: Sequence[CollectedRecord], source_resources: Mapping[str, str]
) -> NormalizationResult:
    """Normalize a bounded batch; withhold every version of a conflicting native ID.

    Duplicate deliveries collapse by native identity and canonical payload hash.
    Deduplication is batch-local; persistent replay detection belongs to future intake.
    Rejections are diagnostics, not IBER findings or a claim of source completeness.
    """
    validate_sources(source_resources)
    if len(records) > MAX_RECORDS:
        raise ValueError("normalization batch exceeds bound")
    observations: dict[str, FourStageObservation] = {}
    conflicted: set[str] = set()
    issues = []
    for index, record in enumerate(records):
        source = source_resources.get(record.resource_arn)
        if source is None:
            issues.append(NormalizationIssue(index, "UNRECOGNIZED_SOURCE_RESOURCE"))
            continue
        native_key = None
        try:
            text(record.native_id)
            native_key = str(
                uuid5(NAMESPACE_URL, canonical([record.resource_arn, record.native_id]).decode())
            )
            item = _normalize_one(record, source)
        except (KeyError, ValueError, TypeError, OverflowError, OSError, AttributeError):
            if native_key is not None:
                observations.pop(native_key, None)
                conflicted.add(native_key)
            issues.append(NormalizationIssue(index, "INVALID_SOURCE_RECORD"))
            continue
        previous = observations.get(item.event_id)
        if item.event_id in conflicted:
            issues.append(NormalizationIssue(index, "CONFLICTING_NATIVE_RECORD"))
        elif previous and previous.provenance.payload_hash != item.provenance.payload_hash:
            observations.pop(item.event_id)
            conflicted.add(item.event_id)
            issues.append(NormalizationIssue(index, "CONFLICTING_NATIVE_RECORD"))
        elif previous is None:
            observations[item.event_id] = item
    return NormalizationResult(tuple(observations.values()), tuple(issues))
