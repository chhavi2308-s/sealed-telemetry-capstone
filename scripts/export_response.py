"""Read-only export of durable response attempts, including interrupted attempts."""

import argparse
import json
from pathlib import Path

import boto3
from boto3.dynamodb.conditions import Key

from sealed_telemetry.aws_support import SDK_CONFIG
from sealed_telemetry.schema import canonical, utcnow


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    for name in ["account", "region", "table", "approval-id"]:
        p.add_argument("--" + name, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    session = boto3.Session(region_name=args.region)
    if session.client("sts", config=SDK_CONFIG).get_caller_identity()["Account"] != args.account:
        raise SystemExit("Account mismatch")
    table = session.resource("dynamodb", config=SDK_CONFIG).Table(args.table)
    query = {
        "KeyConditionExpression": Key("response_id").eq(args.approval_id),
        "ConsistentRead": True,
    }
    records = []
    while True:
        page = table.query(**query)
        for item in page["Items"]:
            records.append(
                {
                    "attempt_key": int(item["attempt"]),
                    "phase": item.get("phase", "completed"),
                    "body": json.loads(item["body"]),
                    "evidence": json.loads(item["evidence"]) if item.get("evidence") else None,
                }
            )
        if not page.get("LastEvaluatedKey"):
            break
        query["ExclusiveStartKey"] = page["LastEvaluatedKey"]
    if not records:
        raise SystemExit("No response attempt records; no successful reconstruction claimed")
    args.output.write_bytes(
        canonical(
            {
                "approval_id": args.approval_id,
                "exported_at": utcnow(),
                "mode": "aws_response_history",
                "attempts": records,
                "limitations": [
                    "Incomplete attempt records never establish successful containment"
                ],
            }
        )
    )


if __name__ == "__main__":
    main()
