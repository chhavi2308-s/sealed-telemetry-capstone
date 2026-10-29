"""Read-only cleanup plan; execution requires quiescence and digest-bound approval."""

import argparse
import json
from pathlib import Path
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key

from sealed_telemetry.aws_support import SDK_CONFIG
from sealed_telemetry.schema import digest


def plan(session: Any, account: str, stack: str) -> dict[str, Any]:
    if session.client("sts", config=SDK_CONFIG).get_caller_identity()["Account"] != account:
        raise ValueError("Account mismatch")
    cfn = session.client("cloudformation", config=SDK_CONFIG)
    description = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    if not any(
        t["Key"] == "Project" and t["Value"] == "SealedTelemetry"
        for t in description.get("Tags", [])
    ):
        raise ValueError("Project stack tag required")
    resources = []
    for page in cfn.get_paginator("list_stack_resources").paginate(
        StackName=description["StackId"]
    ):
        resources.extend(page["StackResourceSummaries"])
    body = cfn.get_template(StackName=description["StackId"], TemplateStage="Processed")[
        "TemplateBody"
    ]
    template = json.loads(body) if isinstance(body, str) else body
    retained = [n for n, r in template["Resources"].items() if r.get("DeletionPolicy") == "Retain"]
    blockers = []
    if not any(
        p["ParameterKey"] == "Quiesce" and p["ParameterValue"] == "true"
        for p in description.get("Parameters", [])
    ):
        blockers.append("Apply reviewed Quiesce=true update first; stop all harness clients")
    queues = {}
    for resource in resources:
        if resource.get("ResourceStatus") == "DELETE_COMPLETE":
            continue
        name = resource["LogicalResourceId"]
        physical = resource["PhysicalResourceId"]
        if resource["ResourceType"] == "AWS::SQS::Queue":
            attrs = session.client("sqs", config=SDK_CONFIG).get_queue_attributes(
                QueueUrl=physical,
                AttributeNames=[
                    "ApproximateNumberOfMessages",
                    "ApproximateNumberOfMessagesNotVisible",
                    "ApproximateNumberOfMessagesDelayed",
                ],
            )["Attributes"]
            queues[name] = {k: int(v) for k, v in attrs.items()}
            if sum(queues[name].values()):
                blockers.append("Queue not drained: " + name)
        if name == "ProviderOutbox":
            pending = (
                session.resource("dynamodb", config=SDK_CONFIG)
                .Table(physical)
                .query(
                    IndexName="PendingIndex",
                    KeyConditionExpression=Key("pending_partition").eq("pending"),
                    Limit=1,
                )
            )
            if pending["Items"]:
                blockers.append("Provider outbox still pending")
        if resource["ResourceType"] == "AWS::StepFunctions::StateMachine":
            running = session.client("stepfunctions", config=SDK_CONFIG).list_executions(
                stateMachineArn=physical, statusFilter="RUNNING", maxResults=1
            )
            if running["executions"]:
                blockers.append("Resolve or reject running approval/response workflows")
    result = {
        "stack_arn": description["StackId"],
        "account": account,
        "region": session.region_name,
        "resources": resources,
        "retained": retained,
        "queues": queues,
        "blockers": blockers,
        "warning": "Retained costs continue; delayed feeds remain possible.",
    }
    return json.loads(json.dumps(result, default=str))


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--stack", required=True)
    p.add_argument("--account", required=True)
    p.add_argument("--region", required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--execute", action="store_true")
    p.add_argument("--approve-account")
    p.add_argument("--approved-plan-hash")
    args = p.parse_args()
    session = boto3.Session(region_name=args.region)
    result = plan(session, args.account, args.stack)
    plan_hash = digest(result)
    args.output.write_text(
        json.dumps({"plan": result, "plan_hash": plan_hash}, indent=2) + "\n", encoding="utf-8"
    )
    if args.execute:
        if args.approve_account != args.account or args.approved_plan_hash != plan_hash:
            raise SystemExit("Explicit account and exact reviewed plan hash required")
        if result["blockers"]:
            raise SystemExit("Cleanup blocked; inspect plan. Nothing deleted")
        session.client("cloudformation", config=SDK_CONFIG).delete_stack(
            StackName=result["stack_arn"]
        )
        print("Deletion requested. Verify completion and retained resource inventory separately.")
    else:
        print("Read-only plan saved. Nothing deleted. Plan hash: " + plan_hash)


if __name__ == "__main__":
    main()
