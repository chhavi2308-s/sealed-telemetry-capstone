"""Approved live synthetic request + read-back verification. No credentials printed/exported.

Run with a Python runtime containing boto3 and CRT for AWS browser-login profiles.
All network operations are behind main; --help is offline.
"""

import argparse
import json
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def verify(expected, audit, output):
    keys = ("action_id", "operation", "filename")
    return bool(
        expected
        and audit
        and expected.get("event_type") == "EXPECTED_ACTION"
        and audit.get("event_type") == "PROVIDER_ACTION"
        and audit.get("outcome") == "success"
        and audit.get("synthetic") is True
        and all(expected.get(k) == audit.get(k) == output.get(k) for k in keys)
        and output.get("filename") == "invoice_101.pdf"
        and output.get("operation") == "files:upload"
        and audit.get("provider_request_id") == output.get("provider_request_id")
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--account", required=True)
    parser.add_argument("--stack", default="sealed-telemetry-four-stage")
    parser.add_argument("--execute-approved", action="store_true")
    args = parser.parse_args()
    if not args.execute_approved:
        parser.error(
            "Sending a request writes AWS records. Obtain approval, then use --execute-approved."
        )
    session = boto3.Session(profile_name=args.profile, region_name="ap-south-1")
    identity = session.client("sts").get_caller_identity()
    if identity["Account"] != args.account or ":assumed-role/" not in identity["Arn"]:
        raise SystemExit("Stop: expected account and a non-root assumed-role session are required.")
    stack = session.client("cloudformation").describe_stacks(StackName=args.stack)["Stacks"][0]
    outputs = {x["OutputKey"]: x["OutputValue"] for x in stack["Outputs"]}
    url = outputs["UploadUrl"]
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or not parsed.hostname.endswith(".execute-api.ap-south-1.amazonaws.com")
        or parsed.path != "/demo/upload"
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
        or parsed.port
    ):
        raise SystemExit("Unexpected endpoint; refusing to send signed request.")
    body = json.dumps({"operation": "files:upload", "filename": "invoice_101.pdf"}).encode()
    credentials = session.get_credentials()
    if credentials is None or not credentials.token:
        raise SystemExit("Temporary session credentials are required.")
    req = AWSRequest(
        method="POST", url=url, data=body, headers={"Content-Type": "application/json"}
    )
    SigV4Auth(credentials.get_frozen_credentials(), "execute-api", "ap-south-1").add_auth(req)
    try:
        with build_opener(NoRedirect).open(
            Request(url, data=body, headers=dict(req.headers), method="POST"),  # noqa: S310 -- HTTPS host validated above
            timeout=35,
        ) as result:
            output = json.loads(result.read(16384))
    except HTTPError as exc:
        raise SystemExit(
            f"API returned HTTP {exc.code}; inspect Lambda logs. Do not retry blindly."
        ) from None
    if output.get("status") != "success":
        raise SystemExit("API did not report success; do not claim a completed demonstration.")
    ddb = session.resource("dynamodb")
    expected = (
        ddb.Table(outputs["ExpectedTable"])
        .get_item(Key={"action_id": output["action_id"]}, ConsistentRead=True)
        .get("Item")
    )
    audit = (
        ddb.Table(outputs["AuditTable"])
        .get_item(Key={"provider_request_id": output["provider_request_id"]}, ConsistentRead=True)
        .get("Item")
    )
    passed = verify(expected, audit, output)
    # Only known safe fields are displayed; never print SDK credentials or token-table rows.
    expected_fields = ("event_type", "action_id", "operation", "filename", "authorized_at")
    audit_fields = (
        "event_type",
        "provider_request_id",
        "action_id",
        "operation",
        "filename",
        "outcome",
        "synthetic",
        "recorded_at",
    )
    print(
        json.dumps(
            {
                "aws_verified": passed,
                "response": {
                    k: output.get(k)
                    for k in ("status", "action_id", "provider_request_id", "synthetic")
                },
                "expected": {k: (expected or {}).get(k) for k in expected_fields},
                "audit": {k: (audit or {}).get(k) for k in audit_fields},
            },
            default=str,
            indent=2,
        )
    )
    if not passed:
        raise SystemExit("Verification failed: authorization and SaaS audit do not match.")


if __name__ == "__main__":
    main()
