"""Offline SAM-expanded inventory. Requires pinned SAM tooling, no AWS credentials or API calls."""

import copy
import json
from collections import Counter
from pathlib import Path

import boto3
from samtranslator.parser.parser import Parser
from samtranslator.translator.translator import Translator


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    target = root / "docs/release"
    target.mkdir(exist_ok=True)
    for profile in ["template", "security", "workload"]:
        raw = json.loads((root / f"infra/{profile}.yaml").read_text(encoding="utf-8"))
        template = copy.deepcopy(raw)
        for resource in template["Resources"].values():
            if resource["Type"] == "AWS::Serverless::Function":
                resource["Properties"]["CodeUri"] = {
                    "Bucket": "OFFLINE-ARTIFACT-PLACEHOLDER",
                    "Key": "source.zip",
                }
        expanded = Translator(
            {}, Parser(), boto_session=boto3.Session(region_name="us-east-1")
        ).translate(template, {})
        entries = []
        iam = []
        for name, resource in sorted(expanded["Resources"].items()):
            entries.append(
                {
                    "logical_id": name,
                    "type": resource["Type"],
                    "generated_by_sam": name not in raw["Resources"],
                    "condition": resource.get("Condition"),
                    "deletion_policy": resource.get("DeletionPolicy", "Delete"),
                    "properties": resource.get("Properties", {}),
                }
            )
            if resource["Type"] in {
                "AWS::IAM::ManagedPolicy",
                "AWS::IAM::Role",
                "AWS::IAM::Policy",
                "AWS::S3::BucketPolicy",
                "AWS::SQS::QueuePolicy",
                "AWS::Lambda::Permission",
            }:
                iam.append({"logical_id": name, **resource})
        result = {
            "mode": "OFFLINE",
            "sam_translator": "1.115.0",
            "profile": profile,
            "account": "UNCONFIRMED",
            "region": "UNCONFIRMED",
            "expansion_region_example": "us-east-1",
            "artifact_placeholder": True,
            "counts": dict(Counter(e["type"] for e in entries)),
            "total": len(entries),
            "retained": [e["logical_id"] for e in entries if e["deletion_policy"] == "Retain"],
            "resources": entries,
        }
        (target / f"{profile}-inventory.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        (target / f"{profile}-permissions.json").write_text(
            json.dumps(iam, indent=2) + "\n", encoding="utf-8"
        )
        print(profile, len(entries), result["counts"])


if __name__ == "__main__":
    main()
