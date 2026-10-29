"""Explicit, digest-reviewed recovery plans. Planning is read-only; execution never purges."""

import argparse
import json
import os
from pathlib import Path
from typing import Any

import boto3

from sealed_telemetry.aws_support import SDK_CONFIG
from sealed_telemetry.schema import Evidence, digest, utcnow
from sealed_telemetry.telemetry import publish


def queue_plan(session: Any, source: str, destination: str) -> dict[str, Any]:
    sqs = session.client("sqs", config=SDK_CONFIG)
    identity = session.client("sts", config=SDK_CONFIG).get_caller_identity()
    queues = []
    for url in (source, destination):
        attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"])["Attributes"]
        arn = attrs["QueueArn"]
        if arn.split(":")[4] != identity["Account"] or arn.split(":")[3] != session.region_name:
            raise ValueError("queue account/region mismatch")
        queues.append({"url": url, "arn": arn})
    destination_attrs = sqs.get_queue_attributes(
        QueueUrl=destination, AttributeNames=["RedrivePolicy"]
    )["Attributes"]
    if (
        json.loads(destination_attrs.get("RedrivePolicy", "{}")).get("deadLetterTargetArn")
        != queues[0]["arn"]
    ):
        raise ValueError("source is not destination's configured DLQ")
    return {
        "kind": "sqs",
        "account": identity["Account"],
        "region": session.region_name,
        "source": queues[0],
        "destination": queues[1],
        "maximum_messages_per_second": 5,
    }


def execute_queue(session: Any, plan: dict[str, Any], approved_hash: str) -> dict[str, Any]:
    if approved_hash != digest(plan):
        raise ValueError("reviewed plan digest mismatch")
    current = queue_plan(session, plan["source"]["url"], plan["destination"]["url"])
    if current != plan:
        raise ValueError("queue configuration changed; regenerate plan")
    sqs = session.client("sqs", config=SDK_CONFIG)
    tasks = sqs.list_message_move_tasks(SourceArn=plan["source"]["arn"], MaxResults=10)["Results"]
    if any(t["Status"] in {"RUNNING", "CANCELLING"} for t in tasks):
        raise ValueError("redrive already running")
    result: dict[str, Any] = sqs.start_message_move_task(
        SourceArn=plan["source"]["arn"],
        DestinationArn=plan["destination"]["arn"],
        MaxNumberOfMessagesPerSecond=plan["maximum_messages_per_second"],
    )
    return {"task_handle": result["TaskHandle"], "started_at": utcnow(), "verified_complete": False}


def outbox_replay(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Security-owned dry-run and digest-bound replay of selected immutable outbox bodies."""
    ids = event.get("event_ids")
    if not isinstance(ids, list) or not 1 <= len(ids) <= 100 or len(set(ids)) != len(ids):
        raise ValueError("one to 100 unique event IDs required")
    table = boto3.resource("dynamodb", config=SDK_CONFIG).Table(os.environ["OUTBOX_TABLE"])
    records = []
    for event_id in sorted(ids):
        row = table.get_item(Key={"event_id": event_id}, ConsistentRead=True).get("Item")
        if not row:
            raise ValueError("selected outbox event unavailable")
        records.append(Evidence.parse(json.loads(row["body"]), "provider"))
    plan = {
        "kind": "outbox",
        "queue": os.environ["PROVIDER_QUEUE_URL"],
        "records": [{"event_id": e.event_id, "hash": digest(e.to_dict())} for e in records],
    }
    plan_hash = digest(plan)
    if "approved_plan_hash" not in event:
        return {"plan": plan, "plan_hash": plan_hash, "executed": False}
    if event["approved_plan_hash"] != plan_hash:
        raise ValueError("outbox replay plan changed")
    publish(records, os.environ["PROVIDER_QUEUE_URL"])
    # Never remove original provider bodies or mark archive delivery based on queue acceptance.
    return {"plan_hash": plan_hash, "enqueued": len(records), "verified_archived": False}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--region", required=True)
    p.add_argument("--source-url")
    p.add_argument("--destination-url")
    p.add_argument("--plan", required=True, type=Path)
    p.add_argument("--approved-plan-hash")
    a = p.parse_args()
    session = boto3.Session(region_name=a.region)
    if a.approved_plan_hash:
        result = execute_queue(
            session, json.loads(a.plan.read_text(encoding="utf-8")), a.approved_plan_hash
        )
    else:
        result = queue_plan(session, a.source_url, a.destination_url)
        a.plan.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        result = {"plan_hash": digest(result), "executed": False}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
