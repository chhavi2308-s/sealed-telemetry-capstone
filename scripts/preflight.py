"""Read-only AWS deployment readiness report. Never deploys or changes account settings."""

import argparse
import json
from pathlib import Path

import boto3


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--account", required=True)
    p.add_argument("--region", required=True)
    p.add_argument("--budget-name", required=True)
    p.add_argument("--max-budget-usd", required=True, type=float)
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    session = boto3.Session(region_name=a.region)
    identity = session.client("sts").get_caller_identity()
    if identity["Account"] != a.account:
        raise SystemExit("Account mismatch; deployment forbidden")
    budget_client = session.client("budgets")
    budget = budget_client.describe_budget(AccountId=a.account, BudgetName=a.budget_name)["Budget"]
    notifications = budget_client.describe_notifications_for_budget(
        AccountId=a.account, BudgetName=a.budget_name
    )["Notifications"]
    subscribers = [
        subscriber
        for notification in notifications
        for subscriber in budget_client.describe_subscribers_for_notification(
            AccountId=a.account, BudgetName=a.budget_name, Notification=notification
        )["Subscribers"]
    ]
    if not subscribers:
        raise SystemExit("Budget notification subscribers required")
    amount = float(budget["BudgetLimit"]["Amount"])
    if (
        budget["BudgetLimit"]["Unit"] != "USD"
        or amount > a.max_budget_usd
        or a.max_budget_usd <= 0
        or not notifications
    ):
        raise SystemExit("Approved USD budget and notifications required")
    logging = session.client("apigateway").get_account().get("cloudwatchRoleArn")
    if not logging:
        raise SystemExit(
            "Regional API Gateway logging role missing; account-wide change needs approval"
        )
    report = {
        "account": a.account,
        "region": a.region,
        "principal": identity["Arn"],
        "budget_name": a.budget_name,
        "budget_limit_usd": amount,
        "api_gateway_logging_role": logging,
        "deployment_approved": False,
        "retained_resources": [
            "S3 Object Lock archive",
            "KMS key",
            "evidence index",
            "decisions",
            "provider outbox",
        ],
        "remaining_checks": [
            "Review deployment role permissions and change set",
            "Approve actual expected spend and retention",
            "Subscribe operator to stack alarm topic",
            "Review teardown and recovery runbook",
        ],
    }
    a.output.write_text(json.dumps(report, indent=2) + "\n")
    print("Read-only preflight saved. No deployment performed or approved.")


if __name__ == "__main__":
    main()
