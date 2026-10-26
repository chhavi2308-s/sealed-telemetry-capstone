"""Read-only cleanup inventory; deletion requires explicit account confirmation."""

import argparse
import json
from pathlib import Path

import boto3


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--stack", required=True)
    p.add_argument("--account", required=True)
    p.add_argument("--region", required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--execute", action="store_true")
    p.add_argument("--approve-account")
    args = p.parse_args()
    session = boto3.Session(region_name=args.region)
    if session.client("sts").get_caller_identity()["Account"] != args.account:
        raise SystemExit("Account mismatch")
    cfn = session.client("cloudformation")
    description = cfn.describe_stacks(StackName=args.stack)["Stacks"][0]
    if not any(
        tag["Key"] == "Project" and tag["Value"] == "SealedTelemetry"
        for tag in description.get("Tags", [])
    ):
        raise SystemExit("Refusing a stack without the SealedTelemetry project tag")
    resources = []
    for page in cfn.get_paginator("list_stack_resources").paginate(
        StackName=description["StackId"]
    ):
        resources.extend(page["StackResourceSummaries"])
    plan = {
        "stack_arn": description["StackId"],
        "resources": resources,
        "retained": [
            "Archive",
            "EvidenceKey",
            "CredentialKey",
            "Events",
            "Decisions",
            "Responses",
            "ProviderOutbox",
        ],
        "warning": "Retained resources, staging buckets and logs may keep incurring charges",
    }
    args.output.write_text(json.dumps(plan, default=str, indent=2) + "\n")
    if args.execute:
        if args.approve_account != args.account:
            raise SystemExit("Explicit --approve-account matching account required")
        cfn.delete_stack(StackName=description["StackId"])
        print("Deletion requested; completion and retained-resource reconciliation still required.")
    else:
        print("Read-only inventory saved. Nothing deleted.")


if __name__ == "__main__":
    main()
