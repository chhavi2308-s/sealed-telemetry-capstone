"""Supplementary AWS observations: bounded parsing, redaction and source-isolated transport.

CloudWatch runtime text can be spoofed by workload code. CloudTrail observes supported
AWS API actions only. Neither source is promoted to provider-action evidence.
"""

import base64
import gzip
import hashlib
import io
import json
import os
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote_plus
from uuid import NAMESPACE_URL, uuid5

import boto3

from sealed_telemetry.aws_support import SDK_CONFIG
from sealed_telemetry.schema import Evidence, canonical, digest, timestamp, utcnow

MAX_BYTES = 8 * 1024 * 1024
RUNTIME = re.compile(r"^(START|END|REPORT) RequestId: ([a-fA-F0-9-]{36})(?:\s|$)")


def unpack_gzip(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_BYTES:
        raise ValueError("compressed observation exceeds bound")
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
        decoded = stream.read(MAX_BYTES + 1)
    if len(decoded) > MAX_BYTES:
        raise ValueError("decompressed observation exceeds bound")
    value = json.loads(decoded)
    if not isinstance(value, dict):
        raise ValueError("observation object required")
    return value


def observation(
    source: str,
    kind: str,
    native_id: str,
    time: str,
    operation: str,
    actor: str,
    resource: str,
    trace: dict[str, str],
    invocation_id: str | None = None,
    denied: bool = False,
) -> Evidence:
    event_id = str(uuid5(NAMESPACE_URL, source + ":" + native_id))
    return Evidence.parse(
        {
            "event_id": event_id,
            "run_id": str(uuid5(NAMESPACE_URL, "observation:" + native_id)),
            "scenario_id": "aws-observation-v1",
            "source_id": source,
            "event_type": kind,
            "event_time_utc": timestamp(time).isoformat(),
            "actor_pseudonym": hashlib.sha256(actor.encode()).hexdigest(),
            "credential_fingerprint": "0" * 64,
            "operation": operation,
            "resource_pseudonym": hashlib.sha256(resource.encode()).hexdigest(),
            "invocation_id": invocation_id,
            "outcome": "denied" if denied else "success",
            "trace_context": trace,
        },
        source,
    )


def cloudwatch_records(batch: dict[str, Any]) -> list[Evidence]:
    if batch.get("messageType") == "CONTROL_MESSAGE":
        return []
    if batch.get("messageType") != "DATA_MESSAGE" or len(batch.get("logEvents", [])) > 10000:
        raise ValueError("unsupported CloudWatch batch")
    group, stream = batch["logGroup"], batch["logStream"]
    records = []
    for item in batch["logEvents"]:
        message = item["message"]
        match = RUNTIME.match(message)
        kind, invocation = None, None
        trace = {
            "origin_log_group": group,
            "origin_log_stream": stream,
            "origin_log_event_id": item["id"],
            "native_record_hash": digest(item),
            "telemetry_trust": "corroborative_not_runtime_attestation",
        }
        if match:
            kind, invocation = "LAMBDA_PLATFORM", match.group(2)
            operation = "lambda:" + match.group(1).lower()
        else:
            try:
                obj = json.loads(message)
            except (ValueError, TypeError):
                continue
            if not isinstance(obj, dict):
                continue
            if obj.get("type") in {"platform.start", "platform.report", "platform.runtimeDone"}:
                kind, operation = "LAMBDA_PLATFORM", str(obj["type"])
                invocation = (obj.get("record") or {}).get("requestId")
            elif {"requestId", "status", "requestTimeEpoch"} <= obj.keys():
                kind, operation = "API_INGRESS", "apigateway:ingress"
                trace["aws_request_id"] = str(obj["requestId"])
                trace["http_status"] = str(obj["status"])
            else:
                continue  # Never forward arbitrary application messages or bearer values.
        when = datetime.fromtimestamp(int(item["timestamp"]) / 1000, UTC).isoformat()
        records.append(
            observation(
                "platform",
                kind,
                group + ":" + item["id"],
                when,
                operation,
                "aws-cloudwatch",
                group,
                trace,
                invocation,
            )
        )
    return records


def cloudtrail_records(document: dict[str, Any], origin: dict[str, str]) -> list[Evidence]:
    if not isinstance(document.get("Records"), list) or len(document["Records"]) > 10000:
        raise ValueError("CloudTrail record array required")
    records = []
    for item in document["Records"]:
        # Allow only event metadata; never copy request/response parameters or credentials.
        trace = {
            **origin,
            "aws_event_source": item["eventSource"],
            "aws_event_name": item["eventName"],
            "aws_region": item["awsRegion"],
            "aws_account_id": item["recipientAccountId"],
            "native_record_hash": digest(item),
            "aws_request_id": str(item.get("requestID", item["eventID"])),
        }
        resources = ",".join(str(r.get("ARN", "")) for r in item.get("resources", []))
        records.append(
            observation(
                "cloudtrail",
                "AWS_API",
                item["eventID"],
                item["eventTime"],
                item["eventSource"] + ":" + item["eventName"],
                str(item.get("userIdentity", {}).get("arn", "aws-service")),
                resources or item["eventSource"],
                trace,
                denied=bool(item.get("errorCode")),
            )
        )
    return records


def publish(records: list[Evidence], queue_url: str) -> int:
    sqs = boto3.client("sqs", config=SDK_CONFIG)
    envelopes = []
    for record in records:
        raw = record.to_dict()
        body = canonical(raw).decode()
        envelopes.append(
            {
                "raw": raw,
                "raw_body": body,
                "normalized": raw,
                "receipt": {
                    "collector_receipt_id": str(
                        uuid5(NAMESPACE_URL, record.source_id + record.event_id + digest(raw))
                    ),
                    "collector_received_at_utc": utcnow(),
                    "authenticated_source": record.source_id,
                    "canonical_hash": digest(raw),
                    "original_payload_hash": hashlib.sha256(body.encode()).hexdigest(),
                    "normalized_hash": digest(raw),
                    "normalization_version": "1",
                    "integrity_version": "sha256-v1",
                    "trust_tier": "corroborative"
                    if record.source_id == "platform"
                    else "aws_control_plane",
                },
            }
        )
    for offset in range(0, len(envelopes), 10):
        result = sqs.send_message_batch(
            QueueUrl=queue_url,
            Entries=[
                {"Id": str(i), "MessageBody": canonical(value).decode()}
                for i, value in enumerate(envelopes[offset : offset + 10])
            ],
        )
        if result.get("Failed"):
            # Retry the entire source batch; deterministic IDs make duplicates safe.
            raise RuntimeError("supplementary evidence buffering partially failed")
    return len(records)


def cloudwatch(event: dict[str, Any], context: Any) -> dict[str, int]:
    data = event["awslogs"]["data"]
    if len(data) > MAX_BYTES * 2:
        raise ValueError("encoded log batch exceeds bound")
    batch = unpack_gzip(base64.b64decode(data, validate=True))
    allowed = json.loads(os.environ["ALLOWED_LOG_GROUPS"])
    if batch.get("messageType") != "CONTROL_MESSAGE" and batch.get("logGroup") not in allowed:
        raise ValueError("unconfigured log group")
    return {"buffered": publish(cloudwatch_records(batch), os.environ["PLATFORM_QUEUE_URL"])}


def cloudtrail(event: dict[str, Any], context: Any) -> dict[str, int]:
    total = 0
    s3 = boto3.client("s3", config=SDK_CONFIG)
    for record in event["Records"]:
        bucket, obj = record["s3"]["bucket"]["name"], record["s3"]["object"]
        key = unquote_plus(obj["key"])
        if (
            bucket != os.environ["TRAIL_BUCKET"]
            or "/CloudTrail/" not in key
            or not obj.get("versionId")
        ):
            raise ValueError("untrusted or unversioned CloudTrail origin")
        item = s3.get_object(Bucket=bucket, Key=key, VersionId=obj["versionId"])
        document = unpack_gzip(item["Body"].read(MAX_BYTES + 1))
        total += publish(
            cloudtrail_records(
                document,
                {
                    "origin_s3_bucket": bucket,
                    "origin_s3_key": key,
                    "origin_s3_version": obj["versionId"],
                },
            ),
            os.environ["CLOUDTRAIL_QUEUE_URL"],
        )
    return {"buffered": total}
