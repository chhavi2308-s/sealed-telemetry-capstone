"""Explicit v1 legacy collector/archive mappings. Hashes validate integrity, not writers."""

import hashlib
import json
import re
from collections.abc import Callable
from functools import wraps
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from botocore.exceptions import BotoCoreError, ClientError

from sealed_telemetry.aws_handlers import source_for_principal
from sealed_telemetry.four_stage_c3_schema import exact, plain, require
from sealed_telemetry.four_stage_c3_schema import normalize as normalize_canonical
from sealed_telemetry.schema import digest, timestamp


def sanitized[**P, T](function: Callable[P, T]) -> Callable[P, T]:
    @wraps(function)
    def mapped(*args: P.args, **kwargs: P.kwargs) -> T:
        try:
            return function(*args, **kwargs)
        except (
            BotoCoreError,
            ClientError,
            KeyError,
            ValueError,
            TypeError,
            AttributeError,
            OverflowError,
            RecursionError,
        ):
            raise ValueError("INVALID_AWS_ARCHIVE_RECORD") from None

    return mapped


@sanitized
def envelope_v1(payload: dict[str, Any], source: str, roles: dict[str, str]) -> dict[str, Any]:
    """Only use after an authenticated read from a configured collector-owned resource."""
    exact(payload, {"raw", "raw_body", "normalized", "receipt"})
    raw: dict[str, Any] = payload["raw"]
    receipt, body = payload["receipt"], payload["raw_body"]
    role_map: dict[str, str | list[str]] = dict(roles)
    exact(
        receipt,
        {
            "collector_receipt_id",
            "collector_received_at_utc",
            "canonical_hash",
            "original_payload_hash",
            "normalized_hash",
            "normalization_version",
            "authenticated_source",
            "authenticated_principal",
            "integrity_version",
            "trust_tier",
        },
        {"queue_source_arn"},
    )
    require(receipt["normalization_version"] == "1" and receipt["integrity_version"] == "sha256-v1")
    require(receipt["authenticated_source"] == source)
    require(
        receipt["trust_tier"]
        in {
            "untrusted",
            "independent_lab",
            "independent_provider",
            "corroborative",
            "aws_control_plane",
        }
    )
    require(
        receipt["collector_receipt_id"]
        == str(uuid5(NAMESPACE_URL, source + raw["event_id"] + digest(raw)))
    )
    require(source_for_principal(receipt["authenticated_principal"], role_map) == source)
    require(isinstance(body, str) and len(body.encode()) <= 16384)
    require(json.loads(body) == raw and payload["normalized"] == raw)
    require(digest(raw) == receipt["canonical_hash"] == receipt["normalized_hash"])
    require(hashlib.sha256(body.encode()).hexdigest() == receipt["original_payload_hash"])
    timestamp(receipt["collector_received_at_utc"])
    if "queue_source_arn" in receipt:
        require(
            isinstance(receipt["queue_source_arn"], str)
            and re.fullmatch(
                r"arn:(aws|aws-cn|aws-us-gov):sqs:[a-z0-9-]+:[0-9]{12}:[A-Za-z0-9_-]{1,80}(?:\.fifo)?",
                receipt["queue_source_arn"],
            )
        )
    # Reject unsupported trace payloads/private fields before retaining an archive body.
    require(normalize_canonical(source, "iber-1", "archive", raw["event_id"], raw) is not None)
    return raw


@sanitized
def events_v1(payload: dict[str, Any], native: str, roles: dict[str, str]) -> dict[str, Any]:
    """Exact Events-table wrapper produced by aws_handlers.persist()."""
    raw = plain(payload)
    exact(
        raw,
        {
            "event_id",
            "raw_event_id",
            "run_id",
            "event_time_utc",
            "source_id",
            "credential_fingerprint",
            "canonical_hash",
            "archive_key",
            "archive_version",
            "record",
        },
    )
    require(isinstance(raw["record"], str) and len(raw["record"].encode()) <= 65536)
    envelope = json.loads(raw["record"])
    event = envelope_v1(envelope, raw["source_id"], roles)
    require(native == raw["event_id"] == event["source_id"] + ":" + event["event_id"])
    for field in ("run_id", "event_time_utc", "source_id", "credential_fingerprint"):
        require(raw[field] == event[field])
    require(raw["raw_event_id"] == event["event_id"] and raw["canonical_hash"] == digest(event))
    require(
        raw["archive_key"] == "evidence/" + event["source_id"] + "/" + event["event_id"] + ".json"
    )
    require(isinstance(raw["archive_version"], str) and 0 < len(raw["archive_version"]) <= 256)
    return event


@sanitized
def sqs_v1(
    record: dict[str, Any], queue_sources: dict[str, str], roles: dict[str, str]
) -> dict[str, Any]:
    """Pure mapping for an AWS-owned SQS trigger; caller must secure the event source mapping.

    This function does not authenticate an arbitrary JSON argument as an AWS trigger.
    Collector-queue fan-in still requires a trusted collector receipt principal.
    """
    source = queue_sources[record["eventSourceARN"]]
    require(record["eventSource"] == "aws:sqs")
    envelope = json.loads(record["body"])
    raw = envelope["raw"]
    if source == "collector":
        role_map: dict[str, str | list[str]] = dict(roles)
        source = source_for_principal(envelope["receipt"]["authenticated_principal"], role_map)
    event = envelope_v1(envelope, source, roles)
    require(event == raw)
    return {
        "event": event,
        "queue_arn": record["eventSourceARN"],
        "message_id": record["messageId"],
        "sent_at_epoch_ms": int(record["attributes"]["SentTimestamp"]),
        "mapping_version": "aws-sqs-envelope-1",
    }


@sanitized
def read_s3_v1(
    client: Any, bucket: str, owner: str, key: str, version: str, source: str, roles: dict[str, str]
) -> dict[str, Any]:
    """Explicit exact-version read; no List/Get-latest fallback or bucket discovery."""
    require(version not in {"", "null", "unversioned"})
    response = client.get_object(
        Bucket=bucket, Key=key, VersionId=version, ExpectedBucketOwner=owner
    )
    try:
        require(response.get("VersionId") == version)
        data = response["Body"].read(65537)
        require(len(data) <= 65536)
        event = envelope_v1(json.loads(data), source, roles)
        require(key == "evidence/" + source + "/" + event["event_id"] + ".json")
        return {
            "event": event,
            "bucket": bucket,
            "key": key,
            "version_id": version,
            "mapping_version": "aws-s3-envelope-1",
        }
    finally:
        response["Body"].close()
