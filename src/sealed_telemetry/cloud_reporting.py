"""Version-pinned forensic export and operator-authenticated report archival."""

import hashlib
import json
import os
from typing import Any
from uuid import uuid4

import boto3
from boto3.dynamodb.conditions import Key

from sealed_telemetry.approvals import authorized
from sealed_telemetry.aws_handlers import response
from sealed_telemetry.aws_support import SDK_CONFIG
from sealed_telemetry.cloud_lab import parse_body
from sealed_telemetry.schema import canonical, digest, timestamp, utcnow


def export(
    run_id: str, events: Any, decisions: Any, s3: Any, bucket: str, fingerprint: str | None = None
) -> dict[str, Any]:
    items = []
    query: dict[str, Any] = {
        "IndexName": "RunIndex",
        "KeyConditionExpression": Key("run_id").eq(run_id),
    }
    if fingerprint:
        query = {
            "IndexName": "CredentialIndex",
            "KeyConditionExpression": Key("credential_fingerprint").eq(fingerprint),
        }
    while True:
        page = events.query(**query)
        items.extend(page["Items"])
        if len(items) > 1000:
            raise ValueError("report capacity exceeded; partition credential/time scope")
        if not page.get("LastEvaluatedKey"):
            break
        query["ExclusiveStartKey"] = page["LastEvaluatedKey"]
    if not items:
        raise ValueError("no evidence indexed; do not claim an empty reconstruction succeeded")
    timeline: list[dict[str, Any]] = []
    history: list[dict[str, Any]] = []
    for item in items:
        if item["archive_version"] == "unversioned":
            raise ValueError("versioned archive required")
        archived = s3.get_object(
            Bucket=bucket, Key=item["archive_key"], VersionId=item["archive_version"]
        )
        envelope = json.loads(archived["Body"].read())
        raw, receipt = envelope["raw"], envelope["receipt"]
        valid = digest(raw) == receipt["canonical_hash"] == item["canonical_hash"]
        if "raw_body" in envelope:
            valid = (
                valid
                and hashlib.sha256(envelope["raw_body"].encode()).hexdigest()
                == receipt["original_payload_hash"]
            )
            valid = valid and digest(envelope["normalized"]) == receipt["normalized_hash"]
        timeline.append(
            {
                "event": raw,
                "receipt": receipt,
                "integrity_valid": valid,
                "archive_key": item["archive_key"],
                "archive_version": item["archive_version"],
            }
        )
        q = {
            "KeyConditionExpression": Key("case_id").eq(raw["run_id"] + ":" + raw["event_id"]),
            "ConsistentRead": True,
        }
        while True:
            page = decisions.query(**q)
            history.extend(
                {
                    **json.loads(row["body"]),
                    "decision_id": row["decision_id"],
                    "revision": int(row.get("revision", 0)),
                }
                for row in page["Items"]
                if row["decision_id"] != "CURRENT"
            )
            if not page.get("LastEvaluatedKey"):
                break
            q["ExclusiveStartKey"] = page["LastEvaluatedKey"]
    current: dict[str, dict[str, Any]] = {}
    for decision in history:
        previous = current.get(decision["case_id"])
        if previous is None or decision["revision"] > previous["revision"]:
            current[decision["case_id"]] = decision
    return {
        "current_decisions": list(current.values()),
        "run_id": run_id,
        "exported_at": utcnow(),
        "mode": "aws_archive_export",
        "integrity_valid": all(e["integrity_valid"] for e in timeline),
        "timeline": sorted(timeline, key=lambda e: timestamp(e["event"]["event_time_utc"])),
        "decision_history": history,
        "known_gaps": sorted(
            {source for d in history for source in d.get("missing_expected_sources", [])}
        ),
        "limitations": [
            "An event-time ordering is not a causal proof",
            "Hashes do not prove event truth or completeness",
            "External activity may have a separate provider-assigned run ID",
        ],
    }


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    try:
        authorized(event, read_only=True)
    except (ValueError, KeyError, TypeError):
        return response(403, {"error": "operator_forbidden"})
    try:
        request = parse_body(event)
        run_id, fingerprint = request.get("run_id"), request.get("credential_fingerprint")
        if bool(run_id) == bool(fingerprint):
            raise ValueError("exactly one report scope required")
        if any(not isinstance(v, str) or not 1 <= len(v) <= 256 for v in [run_id or fingerprint]):
            raise ValueError("invalid report scope")
        ddb = boto3.resource("dynamodb", config=SDK_CONFIG)
        s3 = boto3.client("s3", config=SDK_CONFIG)
        bucket = os.environ["ARCHIVE_BUCKET"]
        report = export(
            run_id or "credential-investigation",
            ddb.Table(os.environ["EVENT_TABLE"]),
            ddb.Table(os.environ["DECISION_TABLE"]),
            s3,
            bucket,
            fingerprint,
        )
        if not report["integrity_valid"]:
            return response(409, {"error": "evidence_integrity_failure", "report_archived": False})
        content = canonical(report)
        key = "reports/" + str(uuid4()) + ".json"
        saved = s3.put_object(
            Bucket=bucket, Key=key, Body=content, ContentType="application/json", IfNoneMatch="*"
        )
        return response(
            201,
            {
                "bucket": bucket,
                "key": key,
                "version_id": saved["VersionId"],
                "sha256": hashlib.sha256(content).hexdigest(),
                "integrity_valid": True,
            },
        )
    except ValueError:
        return response(400, {"error": "invalid_or_unavailable_report_scope"})
