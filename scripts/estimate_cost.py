"""Conservative planning model, never measured AWS billing or an enforceable spend cap."""

import argparse
import json
from pathlib import Path


def estimate(inventory: dict, days: int = 30) -> dict:
    if not 1 <= days <= 30:
        raise ValueError("days must be 1..30")
    counts = inventory["counts"]
    minutes = days * 24 * 60
    assumptions = {
        "region_example": "us-east-1",
        "days_running": days,
        "test_interactions": 1000,
        "lambda_requests": int(minutes * 8 + 5000),
        "lambda_gb_seconds": minutes * 8 * 0.25,
        "rest_requests": minutes * 4 + 4000,
        "logs_ingested_gb": 1,
        "kms_requests": minutes * 8,
        "secret_reads": 10000,
        "other_services_allowance_usd": 10,
        "allowance_scope": "Other services and staging; replace allowance with target-region quote",
    }
    components = {
        "retained_kms_keys_full_month": counts.get("AWS::KMS::Key", 0) * 1.0,
        "retained_secret_full_month": counts.get("AWS::SecretsManager::Secret", 0) * 0.4,
        "alarms": counts.get("AWS::CloudWatch::Alarm", 0) * 0.1 * days / 30,
        "dashboard": counts.get("AWS::CloudWatch::Dashboard", 0) * 3 * days / 30,
        "lambda_requests": assumptions["lambda_requests"] * 0.2 / 1_000_000,
        "lambda_compute": assumptions["lambda_gb_seconds"] * 0.0000166667,
        "api_gateway_rest": assumptions["rest_requests"] * 3.5 / 1_000_000,
        "logs_ingestion": assumptions["logs_ingested_gb"] * 0.5,
        "kms_requests": assumptions["kms_requests"] * 0.03 / 10000,
        "secret_reads": assumptions["secret_reads"] * 0.05 / 10000,
        "unpriced_other_services_allowance": assumptions["other_services_allowance_usd"],
    }
    subtotal = sum(components.values())
    return {
        "mode": "PLANNING_ONLY",
        "observed_pricing_date": "2026-10-27",
        "account": "UNCONFIRMED",
        "deployment_region": "UNCONFIRMED",
        "assumptions": assumptions,
        "usd_components": {k: round(v, 4) for k, v in components.items()},
        "usd_subtotal": round(subtotal, 2),
        "usd_with_30_percent_contingency": round(subtotal * 1.3, 2),
        "free_tier_assumed": False,
        "rate_sources": [
            "https://aws.amazon.com/lambda/pricing/",
            "https://aws.amazon.com/api-gateway/pricing/",
            "https://aws.amazon.com/kms/pricing/",
            "https://aws.amazon.com/cloudwatch/pricing/",
            "https://aws.amazon.com/secrets-manager/pricing/",
        ],
        "limits": [
            "Not a cap or quote; traffic, retries, region and existing trails change cost.",
            "Review key rotations, retained growth, support, taxes and organization costs.",
            "Retained keys/secret keep charging; allowance is not regional unit pricing.",
        ],
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--inventory", type=Path, default=Path("docs/release/template-inventory.json"))
    p.add_argument("--days", type=int, default=30)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    result = estimate(json.loads(args.inventory.read_text(encoding="utf-8")), args.days)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in ["usd_subtotal", "usd_with_30_percent_contingency"]}))


if __name__ == "__main__":
    main()
