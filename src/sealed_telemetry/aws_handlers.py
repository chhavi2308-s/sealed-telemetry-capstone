"""AWS evidence adapters. No deployment or credentials are required on import."""

import hashlib
import json
import logging
import os
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import boto3
from botocore.exceptions import ClientError

from sealed_telemetry.aws_support import SDK_CONFIG
from sealed_telemetry.reconciliation import Policy
from sealed_telemetry.schema import Evidence, canonical, digest, timestamp, utcnow

LOG = logging.getLogger(__name__)


def response(status: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def source_for_principal(principal: str, roles: dict[str, str]) -> str:
    """Match full IAM role or its STS session ARN, including partition and account."""
    for source, role in roles.items():
        if principal == role:
            return source
        prefix, account, role_path = (
            role.split(":iam::")[0],
            role.split(":")[4],
            role.split(":role/")[-1],
        )
        sts_prefix = f"{prefix}:sts::{account}:assumed-role/{role_path.split('/')[-1]}/"
        if principal.startswith(sts_prefix) and len(principal) > len(sts_prefix):
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
    key = f"evidence/{event.event_id}.json"
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
        "event_id": event.event_id,
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
        existing = table.get_item(Key={"event_id": event.event_id}, ConsistentRead=True)["Item"]
        if existing["canonical_hash"] != item["canonical_hash"]:
            raise ValueError("index content conflict") from exc
    operational = boto3.resource("dynamodb", config=SDK_CONFIG)
    if event.event_type == "SOURCE_HEALTH":
        try:
            operational.Table(os.environ["HEALTH_TABLE"]).put_item(
                Item={
                    "source_id": event.health_for_source,
                    "checked_at": event.event_time_utc,
                    "state": event.source_health,
                    "event_id": event.event_id,
                },
                ConditionExpression="attribute_not_exists(checked_at) OR checked_at <= :checked",
                ExpressionAttributeValues={":checked": event.event_time_utc},
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
                raise
    elif event.source_id != "responder":
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
            persist(json.loads(record["body"]))
        except (ClientError, ValueError, KeyError, TypeError):
            # Never log the body or credentials. Poison messages eventually enter the DLQ.
            LOG.exception("evidence_processing_failed message_id=%s", record["messageId"])
            failures.append({"itemIdentifier": record["messageId"]})
    return {"batchItemFailures": failures}
