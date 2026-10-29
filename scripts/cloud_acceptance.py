"""Approved live acceptance runner; real AWS calls only after an explicit execution flag."""

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key

from sealed_telemetry.aws_support import SDK_CONFIG
from sealed_telemetry.cloud_lab import https_json
from sealed_telemetry.cloud_reporting import export
from sealed_telemetry.schema import canonical, utcnow


def validate_target(session: Any, account: str, stack: str) -> tuple[dict[str, str], list[Any]]:
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
    for page in cfn.get_paginator("list_stack_resources").paginate(StackName=stack):
        resources.extend(page["StackResourceSummaries"])
    return {v["OutputKey"]: v["OutputValue"] for v in description["Outputs"]}, resources


def run(args: Any) -> dict[str, Any]:
    if not args.execute_approved:
        raise ValueError("Explicit --execute-approved required; AWS invocation can incur charges")
    args.output.mkdir(parents=True, exist_ok=False)
    session = boto3.Session(region_name=args.region)
    outputs, resources = validate_target(session, args.account, args.stack)
    os.environ["AWS_REGION"] = args.region
    lambda_client = session.client("lambda", config=SDK_CONFIG)
    lambda_states = {
        r["LogicalResourceId"]: lambda_client.get_function_configuration(
            FunctionName=r["PhysicalResourceId"]
        )["State"]
        for r in resources
        if r["ResourceType"] == "AWS::Lambda::Function"
    }
    if any(state != "Active" for state in lambda_states.values()):
        raise ValueError("Not all stack functions active")
    ddb = session.resource("dynamodb", config=SDK_CONFIG)
    events = ddb.Table(outputs["EvidenceTable"])
    decisions = ddb.Table(outputs["DecisionTable"])
    outcomes = []
    for scenario in ["normal", "replay-suppression", "benign-log-failure"]:
        attack = scenario == "replay-suppression"
        started_at = utcnow()
        started = time.monotonic()
        result = https_json(
            outputs["WorkloadUrl"],
            {"suppress_log": scenario != "normal", "expose_test_token": attack},
            signed=True,
        )
        if result["status"] != 200:
            raise ValueError("Legitimate invocation failed")
        body = result["body"]
        replay_status = None
        if attack:
            token = body.pop("disposable_test_token", None)
            if not token:
                raise ValueError("Approved disposable lab exposure build required")
            replay = https_json(
                outputs["SaasUrl"],
                headers={"Authorization": "Bearer " + token, "X-Run-Id": body["run_id"]},
            )
            replay_status = replay["status"]
            del token
        report = None
        observed_at = None
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            page = events.query(
                IndexName="RunIndex", KeyConditionExpression=Key("run_id").eq(body["run_id"])
            )
            if page["Items"]:
                candidate = export(
                    body["run_id"],
                    events,
                    decisions,
                    session.client("s3", config=SDK_CONFIG),
                    outputs["ArchiveBucket"],
                )
                provider = [
                    r for r in candidate["timeline"] if r["event"]["source_id"] == "provider"
                ]
                if (
                    len(provider) >= (2 if attack else 1)
                    and candidate["decision_history"]
                    and not any(d["state"] == "PENDING" for d in candidate["current_decisions"])
                ):
                    report = candidate
                    observed_at = utcnow()
                    break
            time.sleep(5)
        states = {d["state"] for d in report["current_decisions"]} if report else set()
        expected = (
            "SUSPICIOUS" in states
            if attack
            else ("CONSISTENT" in states if scenario == "normal" else "INCONCLUSIVE" in states)
        )
        passed = bool(
            report
            and report["integrity_valid"]
            and expected
            and body["application_result"]["status"] == 200
            and (not attack or replay_status == 200)
        )
        observation = {
            "mode": "LIVE_AWS",
            "scenario": scenario,
            "run_id": body["run_id"],
            "started_at": started_at,
            "first_report_observed_at": observed_at,
            "client_observed_evidence_seconds": time.monotonic() - started,
            "passed": passed,
            "states": sorted(states),
            "replay_status": replay_status,
            "timing_limit": "Client invocation, polling and network time; not Lambda-only overhead",
        }
        (args.output / f"{scenario}.json").write_bytes(
            canonical({"observation": observation, "report": report})
        )
        outcomes.append(observation)
    summary = {
        "mode": "LIVE_AWS",
        "scope": "three_review2_core_scenarios_only",
        "final_acceptance_passed": False,
        "account": args.account,
        "region": args.region,
        "stack": args.stack,
        "lambda_states": lambda_states,
        "scenarios": outcomes,
        "passed": all(r["passed"] for r in outcomes),
        "remaining_live_checks": [
            "Actual workload-role permission_probe",
            "Collector outage and DLQ recovery",
            "Approved containment/recovery",
            "CloudTrail digest signature validation",
            "Rollback/teardown",
            "Repeated calibrated cloud evaluation, invocation overhead and billed cost",
        ],
    }
    (args.output / "acceptance-summary.json").write_bytes(canonical(summary))
    return summary


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--account", required=True)
    p.add_argument("--region", required=True)
    p.add_argument("--stack", required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--execute-approved", action="store_true")
    args = p.parse_args()
    if not 60 <= args.timeout <= 900:
        raise SystemExit("timeout must be 60..900 seconds")
    result = run(args)
    print(json.dumps(result, indent=2))
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
