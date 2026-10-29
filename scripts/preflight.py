"""Read-only AWS readiness gate. Never uploads, creates a change set, or deploys."""

import argparse
import json
import math
from pathlib import Path
from typing import Any

import boto3

from sealed_telemetry.aws_support import SDK_CONFIG

SERVICES = [
    "lambda",
    "apigateway",
    "dynamodb",
    "sqs",
    "s3",
    "kms",
    "secretsmanager",
    "logs",
    "events",
    "stepfunctions",
    "cloudtrail",
    "sns",
    "cloudformation",
]


def inspect(session: Any, args: Any) -> dict[str, Any]:
    identity = session.client("sts", config=SDK_CONFIG).get_caller_identity()
    if identity["Account"] != args.account:
        raise ValueError("Account mismatch; deployment forbidden")
    credentials = session.get_credentials()
    if (
        not credentials
        or not credentials.get_frozen_credentials().token
        or ":assumed-role/" not in identity["Arn"]
    ):
        raise ValueError("SSO/temporary assumed-role credentials required")
    if not math.isfinite(args.max_budget_usd) or args.max_budget_usd <= 0:
        raise ValueError("finite positive approved budget required")
    available = session.client("account", config=SDK_CONFIG).get_region_opt_status(
        RegionName=args.region
    )
    if available["RegionOptStatus"] not in {"ENABLED", "ENABLED_BY_DEFAULT"}:
        raise ValueError("Target region is not enabled")
    services = (
        ["lambda", "logs", "s3", "cloudformation", "sqs", "cloudtrail"]
        if getattr(args, "deployment_profile", "lab") == "workload"
        else SERVICES
    )
    unavailable = [s for s in services if args.region not in session.get_available_regions(s)]
    if unavailable:
        raise ValueError("Regional services unsupported: " + ",".join(unavailable))
    budgets = session.client("budgets", config=SDK_CONFIG)
    budget = budgets.describe_budget(AccountId=args.account, BudgetName=args.budget_name)["Budget"]
    notifications = budgets.describe_notifications_for_budget(
        AccountId=args.account, BudgetName=args.budget_name
    )["Notifications"]
    subscribers = [
        subscriber
        for notification in notifications
        for subscriber in budgets.describe_subscribers_for_notification(
            AccountId=args.account, BudgetName=args.budget_name, Notification=notification
        )["Subscribers"]
    ]
    amount = float(budget["BudgetLimit"]["Amount"])
    if budget["BudgetLimit"]["Unit"] != "USD" or amount > args.max_budget_usd or not subscribers:
        raise ValueError("Approved USD budget with subscribers required")
    logging = None
    if getattr(args, "deployment_profile", "lab") != "workload":
        logging = (
            session.client("apigateway", config=SDK_CONFIG).get_account().get("cloudwatchRoleArn")
        )
    if getattr(args, "deployment_profile", "lab") != "workload" and not logging:
        raise ValueError(
            "Regional API Gateway logging role missing; account-wide change requires approval"
        )
    bucket = session.client("s3", config=SDK_CONFIG)
    bucket.head_bucket(Bucket=args.artifact_bucket, ExpectedBucketOwner=args.account)
    location = (
        bucket.get_bucket_location(
            Bucket=args.artifact_bucket, ExpectedBucketOwner=args.account
        ).get("LocationConstraint")
        or "us-east-1"
    )
    if location != args.region:
        raise ValueError("Artifact bucket region mismatch")
    public = bucket.get_public_access_block(Bucket=args.artifact_bucket)[
        "PublicAccessBlockConfiguration"
    ]
    if not all(public.values()):
        raise ValueError("Artifact bucket must block all public access")
    bucket.get_bucket_encryption(Bucket=args.artifact_bucket)
    role = session.client("iam", config=SDK_CONFIG).get_role(
        RoleName=identity["Arn"].split("/")[1]
    )["Role"]["Arn"]
    permission_plan = json.loads(args.permission_plan.read_text(encoding="utf-8"))
    inventory_name = (
        "template"
        if getattr(args, "deployment_profile", "lab") == "lab"
        else args.deployment_profile
    )
    inventory = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "docs/release"
            / (inventory_name + "-inventory.json")
        ).read_text(encoding="utf-8")
    )
    iam_summary = session.client("iam", config=SDK_CONFIG).get_account_summary()["SummaryMap"]
    required_roles = inventory["counts"].get("AWS::IAM::Role", 0)
    if iam_summary["Roles"] + required_roles > iam_summary["RolesQuota"]:
        raise ValueError("Insufficient IAM role quota")
    lambda_limits = session.client("lambda", config=SDK_CONFIG).get_account_settings()[
        "AccountLimit"
    ]
    if inventory_name != "workload" and lambda_limits["UnreservedConcurrentExecutions"] <= 100:
        raise ValueError(
            "Reserved detector concurrency needs at least 101 currently unreserved units"
        )
    if (
        permission_plan.get("account") != args.account
        or permission_plan.get("region") != args.region
    ):
        raise ValueError("Permission plan account/region mismatch")
    checks = permission_plan.get("checks", [])
    if not checks:
        raise ValueError("Explicit reviewed permission checks required")
    service_role = permission_plan.get("cloudformation_service_role")
    if (
        not isinstance(service_role, str)
        or (":iam::" + args.account + ":role/") not in service_role
    ):
        raise ValueError("Same-account CloudFormation service role ARN required in permission plan")
    service_role_details = session.client("iam", config=SDK_CONFIG).get_role(
        RoleName=service_role.rsplit("/", 1)[1]
    )["Role"]
    if service_role_details["Arn"] != service_role:
        raise ValueError("CloudFormation service role identity mismatch")
    evaluations = []
    iam = session.client("iam", config=SDK_CONFIG)
    for check in checks:
        if not check.get("ActionNames") or not check.get("ResourceArns"):
            raise ValueError("Permission check requires actions and resource ARNs")
        check = dict(check)
        source = check.pop("policy_source", "caller")
        if source not in {"caller", "cloudformation"}:
            raise ValueError("unknown permission-check principal")
        result = iam.simulate_principal_policy(
            PolicySourceArn=service_role if source == "cloudformation" else role, **check
        )
        evaluations.extend(result["EvaluationResults"])
        if result.get("IsTruncated"):
            raise ValueError("Permission simulation truncated; split plan checks")
    denied = [
        e for e in evaluations if e["EvalDecision"] != "allowed" or e.get("MissingContextValues")
    ]
    return {
        "account": args.account,
        "region": args.region,
        "principal": identity["Arn"],
        "role": role,
        "cloudformation_service_role": service_role,
        "service_role_trust_policy": service_role_details["AssumeRolePolicyDocument"],
        "iam_roles_required": required_roles,
        "lambda_account_limits": lambda_limits,
        "temporary_credentials": True,
        "budget_name": args.budget_name,
        "budget_limit_usd": amount,
        "api_gateway_logging_role": logging,
        "artifact_bucket": args.artifact_bucket,
        "regional_services": services,
        "deployment_profile": getattr(args, "deployment_profile", "lab"),
        "permission_evaluations": evaluations,
        "permission_denials_or_missing_context": len(denied),
        "preflight_passed": not denied,
        "deployment_approved": False,
        "limitations": [
            "Simulation cannot prove SCPs, resource policies, KMS grants or propagation.",
            "Review the change set and service-role iam:PassRole before execution.",
            "Budgets do not cap spend; owner must confirm SNS/email delivery.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--deployment-profile", choices=["lab", "security", "workload"], default="lab"
    )
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--budget-name", required=True)
    parser.add_argument("--max-budget-usd", required=True, type=float)
    parser.add_argument("--artifact-bucket", required=True)
    parser.add_argument("--permission-plan", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = inspect(boto3.Session(region_name=args.region), args)
    args.output.write_text(json.dumps(result, indent=2, default=str) + "\n", encoding="utf-8")
    if not result["preflight_passed"]:
        raise SystemExit("Preflight failed permission checks. Nothing deployed.")
    print("Read-only checks passed. Deployment still requires explicit approval.")


if __name__ == "__main__":
    main()
