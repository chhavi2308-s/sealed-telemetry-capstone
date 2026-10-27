"""Read exact archived versions and export a sanitized, integrity-checked incident report."""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key

from sealed_telemetry.aws_support import SDK_CONFIG
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
        if not page.get("LastEvaluatedKey"):
            break
        query["ExclusiveStartKey"] = page["LastEvaluatedKey"]
    if not items:
        raise ValueError("no evidence indexed; do not claim an empty reconstruction succeeded")
    timeline, history = [], []
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
        q = {"KeyConditionExpression": Key("case_id").eq(raw["run_id"] + ":" + raw["event_id"])}
        while True:
            page = decisions.query(**q)
            history.extend(
                json.loads(row["body"]) for row in page["Items"] if row["decision_id"] != "CURRENT"
            )
            if not page.get("LastEvaluatedKey"):
                break
            q["ExclusiveStartKey"] = page["LastEvaluatedKey"]
    return {
        "run_id": run_id,
        "exported_at": utcnow(),
        "mode": "aws_archive_export",
        "integrity_valid": all(e["integrity_valid"] for e in timeline),
        "timeline": sorted(timeline, key=lambda e: timestamp(e["event"]["event_time_utc"])),
        "decision_history": history,
        "known_gaps": sorted({source for d in history for source in d["missing_expected_sources"]}),
        "limitations": [
            "An event-time ordering is not a causal proof",
            "Hashes do not prove event truth or completeness",
            "External activity may have a separate provider-assigned run ID",
        ],
    }


def main() -> None:
    p = argparse.ArgumentParser()
    scope = p.add_mutually_exclusive_group(required=True)
    scope.add_argument("--run-id")
    scope.add_argument("--credential-fingerprint")
    for name in ("event-table", "decision-table", "archive-bucket", "region"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    session = boto3.Session(region_name=args.region)
    ddb = session.resource("dynamodb", config=SDK_CONFIG)
    result = export(
        args.run_id or "credential-investigation",
        ddb.Table(args.event_table),
        ddb.Table(args.decision_table),
        session.client("s3", config=SDK_CONFIG),
        args.archive_bucket,
        fingerprint=args.credential_fingerprint,
    )
    args.output.write_bytes(canonical(result))
    if not result["integrity_valid"]:
        raise SystemExit("Evidence integrity check failed; report marks affected records")
    print("Version-pinned incident report saved.")


if __name__ == "__main__":
    main()
