"""Bounded AWS deadline sweeper and append-only decision publisher."""

import json
import os
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key
from boto3.dynamodb.types import TypeSerializer

from sealed_telemetry.aws_support import SDK_CONFIG
from sealed_telemetry.reconciliation import reconcile
from sealed_telemetry.schema import Evidence, canonical, digest, timestamp, utcnow


def detector(event: dict[str, Any], context: Any) -> dict[str, int]:
    table = boto3.resource("dynamodb", config=SDK_CONFIG).Table(os.environ["EVENT_TABLE"])
    decisions = boto3.resource("dynamodb", config=SDK_CONFIG).Table(os.environ["DECISION_TABLE"])
    now = utcnow()
    operational = boto3.resource("dynamodb", config=SDK_CONFIG)
    health = {}
    for source in ("app", "provider", "gateway", "collector"):
        latest = (
            operational.Table(os.environ["HEALTH_TABLE"])
            .get_item(Key={"source_id": source}, ConsistentRead=True)
            .get("Item")
        )
        age = (timestamp(now) - timestamp(latest["checked_at"])).total_seconds() if latest else -1
        health[source] = bool(latest and latest["state"] == "healthy" and 0 <= age <= 130)
    if not health["collector"]:
        health = {source: False for source in health}
    active = operational.Table(os.environ["ACTIVE_TABLE"])
    credentials: list[str] = []
    scan_args: dict[str, Any] = {}
    while True:
        scanned = active.scan(**scan_args)
        credentials.extend(
            row["credential_fingerprint"]
            for row in scanned["Items"]
            if int(row["expires_at"]) > timestamp(now).timestamp()
        )
        if not scanned.get("LastEvaluatedKey"):
            break
        scan_args["ExclusiveStartKey"] = scanned["LastEvaluatedKey"]
        if len(credentials) > 10000:
            raise RuntimeError("active credential capacity exceeded")
    total = 0
    for fingerprint in credentials:
        envelopes: list[dict[str, Any]] = []
        query_args: dict[str, Any] = {
            "IndexName": "CredentialIndex",
            "KeyConditionExpression": Key("credential_fingerprint").eq(fingerprint),
        }
        while True:
            page = table.query(**query_args)
            envelopes.extend(json.loads(item["record"]) for item in page["Items"])
            if len(envelopes) > 1000:
                raise RuntimeError(
                    "per-credential evidence capacity exceeded; investigate and partition"
                )
            if not page.get("LastEvaluatedKey"):
                break
            query_args["ExclusiveStartKey"] = page["LastEvaluatedKey"]
        records = [
            Evidence.parse(e["raw"], e["receipt"]["authenticated_source"]) for e in envelopes
        ]
        integrity_ok = all(
            digest(e["raw"]) == e["receipt"].get("canonical_hash") for e in envelopes
        )
        for decision in reconcile(records, now, health):
            if not integrity_ok:
                decision.update(
                    state="INCONCLUSIVE",
                    reason_codes=["INTEGRITY_FAILURE"],
                    confidence_category="low",
                )
            content = {k: v for k, v in decision.items() if k != "decided_at"}
            state_hash = digest(content)
            current_key = {"case_id": decision["case_id"], "decision_id": "CURRENT"}
            previous = decisions.get_item(Key=current_key, ConsistentRead=True).get("Item")
            if previous and previous["state_hash"] == state_hash:
                decision = json.loads(previous["body"])
                decision_id = previous["current_decision_id"]
            else:
                revision = int(previous["revision"]) + 1 if previous else 1
                decision_id = f"{revision:010d}:{state_hash}"
                record = {
                    "case_id": decision["case_id"],
                    "decision_id": decision_id,
                    "revision": revision,
                    "decided_at": now,
                    "body": canonical(decision).decode(),
                }
                current = {
                    **current_key,
                    "state_hash": state_hash,
                    "revision": revision,
                    "current_decision_id": decision_id,
                    "body": record["body"],
                }
                serializer = TypeSerializer()
                put_current: dict[str, Any] = {
                    "TableName": os.environ["DECISION_TABLE"],
                    "Item": {k: serializer.serialize(v) for k, v in current.items()},
                    "ConditionExpression": "revision = :old"
                    if previous
                    else "attribute_not_exists(revision)",
                }
                if previous:
                    put_current["ExpressionAttributeValues"] = {
                        ":old": serializer.serialize(previous["revision"])
                    }
                boto3.client("dynamodb", config=SDK_CONFIG).transact_write_items(
                    TransactItems=[
                        {"Put": put_current},
                        {
                            "Put": {
                                "TableName": os.environ["DECISION_TABLE"],
                                "Item": {k: serializer.serialize(v) for k, v in record.items()},
                                "ConditionExpression": "attribute_not_exists(case_id)",
                            }
                        },
                    ]
                )
            # Repeated delivery is possible. Consumers must deduplicate decision_id.
            if decision["state"] in {"SUSPICIOUS", "CORROBORATED_SUSPECTED_ABUSE"}:
                result = boto3.client("events", config=SDK_CONFIG).put_events(
                    Entries=[
                        {
                            "EventBusName": os.environ["FINDINGS_BUS"],
                            "Source": "sealed.iber",
                            "DetailType": "EvidenceFinding",
                            "Detail": canonical({**decision, "decision_id": decision_id}).decode(),
                        }
                    ]
                )
                if result["FailedEntryCount"]:
                    raise RuntimeError("finding publication failed; sweep will retry")
            total += 1
    return {"credential_groups": len(credentials), "decisions": total}
