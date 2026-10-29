"""IAM-signed operator CLI. All writes require a separately reviewed plan hash."""

import argparse
import json
import os
from urllib.parse import quote

from sealed_telemetry.approvals import action_fields
from sealed_telemetry.cloud_lab import https_json
from sealed_telemetry.schema import digest


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=["list", "show", "approve", "reject", "case", "report"])
    p.add_argument("--url", required=True, help="OperatorApiUrl stack output")
    p.add_argument("--region", required=True)
    p.add_argument("--approval-id")
    p.add_argument("--case-id")
    p.add_argument("--run-id")
    p.add_argument("--credential-fingerprint")
    p.add_argument("--response-action", choices=["contain", "recover"], default="contain")
    p.add_argument("--disable-integration", action="store_true")
    p.add_argument("--execute", action="store_true")
    p.add_argument("--approved-plan-hash")
    args = p.parse_args()
    os.environ["AWS_REGION"] = args.region
    base = args.url.rstrip("/")
    if args.mode in {"list", "show", "case"}:
        path = "/v1/approvals"
        if args.mode == "show":
            if not args.approval_id:
                p.error("--approval-id required")
            path += "/" + quote(args.approval_id, safe="")
        if args.mode == "case":
            if not args.case_id:
                p.error("--case-id required")
            path = "/v1/cases/" + quote(args.case_id, safe="")
        result = https_json(base + path, signed=True)
    else:
        if args.mode == "report":
            if bool(args.run_id) == bool(args.credential_fingerprint):
                p.error("Exactly one report scope required")
            body = (
                {"run_id": args.run_id}
                if args.run_id
                else {"credential_fingerprint": args.credential_fingerprint}
            )
            path = "/v1/reports"
            plan = {"path": path, "body": body}
        else:
            if not args.approval_id:
                p.error("--approval-id required")
            path = "/v1/approvals/" + quote(args.approval_id, safe="")
            row = https_json(base + path, signed=True)
            if row["status"] != 200:
                raise SystemExit("Approval lookup failed")
            body = {
                "approved": args.mode == "approve",
                "action": args.response_action,
                "disable_integration": args.disable_integration,
            }
            fields = action_fields({**row["body"]["finding"], **body})
            plan = {
                "approval_id": args.approval_id,
                "url": base + path,
                "body": body,
                "action_fields": fields,
            }
        plan_hash = digest(plan)
        if not args.execute:
            print(json.dumps({"plan": plan, "plan_hash": plan_hash, "executed": False}, indent=2))
            return
        if args.approved_plan_hash != plan_hash:
            raise SystemExit("Exact reviewed plan hash required; nothing written")
        result = https_json(base + path, body, signed=True)
    print(json.dumps(result, indent=2))
    if result["status"] not in {200, 201}:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
