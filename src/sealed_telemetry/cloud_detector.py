"""Bounded AWS deadline sweeper and append-only decision publisher."""

import json
import os
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key
from boto3.dynamodb.types import TypeSerializer

from sealed_telemetry.aws_support import SDK_CONFIG
from sealed_telemetry.reconciliation import Policy, reconcile
from sealed_telemetry.schema import Evidence, canonical, digest, timestamp, utcnow


def detector(event: dict[str, Any], context: Any) -> dict[str, int]:
    table = boto3.resource("dynamodb", config=SDK_CONFIG).Table(os.environ["EVENT_TABLE"])
    decisions = boto3.resource("dynamodb", config=SDK_CONFIG).Table(os.environ["DECISION_TABLE"])
    policy = Policy(**json.loads(os.environ.get("POLICY_JSON", "{}")))
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
    # Persist the scan cursor so large active sets receive round-robin bounded sweeps.
    control_key = {"credential_fingerprint": "__sweep_cursor__"}
    control = active.get_item(Key=control_key, ConsistentRead=True).get("Item", {})
    credentials: list[str] = []
    scan_args: dict[str, Any] = {"Limit": 10}
    if control.get("cursor"):
        scan_args["ExclusiveStartKey"] = control["cursor"]
    next_cursor: dict[str, Any] = {}
    while True:
        scanned = active.scan(**scan_args)
        credentials.extend(
            row["credential_fingerprint"]
            for row in scanned["Items"]
            if row["credential_fingerprint"] != "__sweep_cursor__"
            and int(row.get("expires_at", 0)) > timestamp(now).timestamp()
        )
        next_cursor = scanned.get("LastEvaluatedKey", {})
        if not next_cursor or len(credentials) >= 10:
            break
        scan_args["ExclusiveStartKey"] = next_cursor
    total = 0
    for fingerprint in credentials:
        envelopes: list[dict[str, Any]] = []
        query_args: dict[str, Any] = {
            "IndexName": "CredentialIndex",
            "KeyConditionExpression": Key("credential_fingerprint").eq(fingerprint),
        }
        overflow = False
        while True:
            page = table.query(**query_args)
            envelopes.extend(json.loads(item["record"]) for item in page["Items"])
            if len(envelopes) > 1000:
                envelopes = envelopes[:1000]
                overflow = True
                break
            if not page.get("LastEvaluatedKey"):
                break
            query_args["ExclusiveStartKey"] = page["LastEvaluatedKey"]
        records = [
            Evidence.parse(e["raw"], e["receipt"]["authenticated_source"]) for e in envelopes
        ]
        integrity_ok = all(
            digest(e["raw"]) == e["receipt"].get("canonical_hash") for e in envelopes
        )
        findings = (
            reconcile(records, now, health, policy)
            if not overflow
            else [
                {
                    "case_id": "capacity:" + fingerprint,
                    "finding_id": "capacity:" + fingerprint,
                    "run_id": records[0].run_id,
                    "credential_fingerprint": fingerprint,
                    "state": "INCONCLUSIVE",
                    "reason_codes": ["EVIDENCE_CAPACITY_EXCEEDED"],
                    "confidence_category": "low",
                    "decided_at": now,
                    "evidence_ids": [r.event_id for r in records],
                    "source_health_snapshot": health,
                    "residual_uncertainty": "Bounded prefix; reconstruct archive before judgement",
                }
            ]
        )
        for decision in findings:
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
    active.put_item(
        Item={
            **control_key,
            "cursor": next_cursor,
            "expires_at": int(timestamp(now).timestamp()) + 86400,
        }
    )
    return {"credential_groups": len(credentials), "decisions": total}
