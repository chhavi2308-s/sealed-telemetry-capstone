"""AWS evidence adapters. No deployment or credentials are required on import."""

import hashlib
import json
import logging
import os
from datetime import UTC, datetime
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from sealed_telemetry.aws_support import SDK_CONFIG
from sealed_telemetry.reconciliation import Policy
from sealed_telemetry.schema import Evidence, canonical, digest, timestamp, utcnow

LOG = logging.getLogger(__name__)


def response(status: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json", "Cache-Control": "no-store"},
        "body": json.dumps(body),
    }


def source_for_principal(principal: str, roles: dict[str, str | list[str]]) -> str:
    """Bind a principal to one configured source, including cross-account STS sessions."""
    if not isinstance(principal, str):
        raise ValueError("invalid principal")
    for source, configured in roles.items():
        for role in [configured] if isinstance(configured, str) else configured:
            if not isinstance(role, str) or not role.startswith("arn:"):
                continue
            if principal == role:
                return source
            if ":iam::" not in role or ":role/" not in role:
                continue
            prefix, account, name = (
                role.split(":iam::")[0],
                role.split(":")[4],
                role.rsplit("/", 1)[1],
            )
            stem = f"{prefix}:sts::{account}:assumed-role/{name}/"
            if (
                principal.startswith(stem)
                and principal[len(stem) :]
                and "/" not in principal[len(stem) :]
            ):
                return source
    raise ValueError("unknown authenticated principal")


def collector(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """REST API AWS_IAM auth is mandatory; source is bound to the signing IAM role."""
    try:
        principal = event["requestContext"]["identity"]["userArn"]
        source = source_for_principal(principal, json.loads(os.environ["SOURCE_ROLES"]))
    except (KeyError, ValueError, TypeError):
        return response(403, {"error": "source_forbidden"})
    try:
        body = event.get("body", "")
        if event.get("isBase64Encoded") or not isinstance(body, str) or len(body) > 16384:
            return response(413, {"error": "invalid_encoding_or_size"})
        raw = json.loads(body)
        evidence = Evidence.parse(raw, source)
    except (ValueError, TypeError, AttributeError):
        return response(400, {"error": "schema_rejected"})
    receipt_id = str(uuid5(NAMESPACE_URL, source + evidence.event_id + digest(raw)))
    envelope = {
        "raw": raw,
        "raw_body": body,
        "normalized": evidence.to_dict(),
        "receipt": {
            "collector_receipt_id": receipt_id,
            "collector_received_at_utc": utcnow(),
            "canonical_hash": digest(raw),
            "original_payload_hash": hashlib.sha256(body.encode()).hexdigest(),
            "normalized_hash": digest(evidence.to_dict()),
            "normalization_version": "1",
            "authenticated_source": source,
            "authenticated_principal": principal,
            "integrity_version": "sha256-v1",
            "trust_tier": "untrusted" if source == "app" else "independent_lab",
        },
    }
    # Only return 202 after durable enqueue. Service errors propagate for API 5xx/retry.
    boto3.client("sqs", config=SDK_CONFIG).send_message(
        QueueUrl=os.environ["QUEUE_URL"], MessageBody=canonical(envelope).decode()
    )
    LOG.info(json.dumps({"event_id": evidence.event_id, "result": "enqueued"}))
    return response(202, {"receipt_id": receipt_id, "event_id": evidence.event_id})


def persist(envelope: dict[str, Any]) -> None:
    raw, receipt = envelope["raw"], envelope["receipt"]
    event = Evidence.parse(raw, receipt["authenticated_source"])
    if digest(raw) != receipt["canonical_hash"]:
        raise ValueError("receipt hash mismatch")
    if "raw_body" in envelope:
        if (
            hashlib.sha256(envelope["raw_body"].encode()).hexdigest()
            != receipt["original_payload_hash"]
            or json.loads(envelope["raw_body"]) != raw
        ):
            raise ValueError("original payload hash mismatch")
        if (
            envelope["normalized"] != event.to_dict()
            or digest(envelope["normalized"]) != receipt["normalized_hash"]
        ):
            raise ValueError("normalized payload mismatch")
    timestamp(receipt["collector_received_at_utc"])
    s3 = boto3.client("s3", config=SDK_CONFIG)
    bucket = os.environ["ARCHIVE_BUCKET"]
    # Global event UUID avoids unsafe producer-controlled path characters.
    key = f"evidence/{event.source_id}/{event.event_id}.json"
    try:
        stored = s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=canonical(envelope),
            ContentType="application/json",
            IfNoneMatch="*",
        )
        version = stored.get("VersionId", "unversioned")
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in {"PreconditionFailed", "412"}:
            raise
        previous = s3.get_object(Bucket=bucket, Key=key)
        saved = json.loads(previous["Body"].read())
        if saved["raw"] != raw or saved["receipt"]["authenticated_source"] != event.source_id:
            raise ValueError("event ID content conflict") from exc
        # Preserve the first accepted receipt on retried producer submissions.
        envelope = saved
        receipt = saved["receipt"]
        version = previous.get("VersionId", "unversioned")
    table = boto3.resource("dynamodb", config=SDK_CONFIG).Table(os.environ["EVENT_TABLE"])
    item = {
        "event_id": event.source_id + ":" + event.event_id,
        "raw_event_id": event.event_id,
        "run_id": event.run_id,
        "event_time_utc": event.event_time_utc,
        "source_id": event.source_id,
        "credential_fingerprint": event.credential_fingerprint,
        "canonical_hash": digest(raw),
        "archive_key": key,
        "archive_version": version,
        "record": canonical(envelope).decode(),
    }
    try:
        table.put_item(Item=item, ConditionExpression="attribute_not_exists(event_id)")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
            raise
        existing = table.get_item(
            Key={"event_id": event.source_id + ":" + event.event_id}, ConsistentRead=True
        )["Item"]
        if existing["canonical_hash"] != item["canonical_hash"]:
            raise ValueError("index content conflict") from exc
    operational = boto3.resource("dynamodb", config=SDK_CONFIG)
    if event.event_type == "SOURCE_HEALTH":
        try:
            operational.Table(os.environ["HEALTH_TABLE"]).put_item(
                Item={
                    "source_id": event.health_for_source,
                    "checked_at": timestamp(event.event_time_utc).isoformat(),
                    "state": event.source_health,
                    "event_id": event.event_id,
                },
                ConditionExpression="attribute_not_exists(checked_at) OR checked_at <= :checked",
                ExpressionAttributeValues={":checked": timestamp(event.event_time_utc).isoformat()},
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
                raise
    elif event.event_type in {
        "EXPECTED_ACTION",
        "INTENT_CREATED",
        "PROVIDER_ACTION",
        "RESPONSE_ACTION",
    }:
        policy = Policy(**json.loads(os.environ.get("POLICY_JSON", "{}")))
        activation_seconds = max(
            900,
            int(
                max(policy.provider_deadline, policy.gateway_deadline, policy.app_deadline)
                + policy.clock_skew
                + 120
            ),
        )
        operational.Table(os.environ["ACTIVE_TABLE"]).put_item(
            Item={
                "credential_fingerprint": event.credential_fingerprint,
                "expires_at": int(timestamp(utcnow()).timestamp()) + activation_seconds,
            }
        )
    # Archive first, index second. A crash between them is recoverable by queue redelivery.


def normalizer(event: dict[str, Any], context: Any) -> dict[str, Any]:
    failures = []
    for record in event["Records"]:
        try:
            routing = json.loads(os.environ["QUEUE_SOURCES"])
            source = routing.get(record.get("eventSourceARN"))
            if source is None:
                raise ValueError("untrusted queue origin")
            envelope = json.loads(record["body"])
            if source != "collector" and envelope["receipt"]["authenticated_source"] != source:
                raise ValueError("queue cannot assert another evidence source")
            if source != "collector":
                envelope["receipt"]["collector_received_at_utc"] = datetime.fromtimestamp(
                    int(record["attributes"]["SentTimestamp"]) / 1000, UTC
                ).isoformat()
                envelope["receipt"]["queue_source_arn"] = record["eventSourceARN"]
                envelope["receipt"]["trust_tier"] = (
                    "corroborative"
                    if source == "platform"
                    else "independent_provider"
                    if source == "provider"
                    else "aws_control_plane"
                )
            persist(envelope)
        except (BotoCoreError, ClientError, ValueError, KeyError, TypeError, AttributeError) as exc:
            # Never log the body or credentials. Poison messages eventually enter the DLQ.
            LOG.error(
                "evidence_processing_failed message_id=%s error_type=%s",
                record["messageId"],
                type(exc).__name__,
            )
            failures.append({"itemIdentifier": record["messageId"]})
    return {"batchItemFailures": failures}
