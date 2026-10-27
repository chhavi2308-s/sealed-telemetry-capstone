"""Read exact archived versions and export a sanitized, integrity-checked incident report."""

import argparse
from pathlib import Path

import boto3

from sealed_telemetry.aws_support import SDK_CONFIG
from sealed_telemetry.cloud_reporting import export
from sealed_telemetry.schema import canonical


def main() -> None:
    p = argparse.ArgumentParser()
    scope = p.add_mutually_exclusive_group(required=True)
    scope.add_argument("--run-id")
    scope.add_argument("--credential-fingerprint")
    for name in ("event-table", "decision-table", "archive-bucket", "region"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    session = boto3.Session(region_name=args.region)
    ddb = session.resource("dynamodb", config=SDK_CONFIG)
    result = export(
        args.run_id or "credential-investigation",
        ddb.Table(args.event_table),
        ddb.Table(args.decision_table),
        session.client("s3", config=SDK_CONFIG),
        args.archive_bucket,
        fingerprint=args.credential_fingerprint,
    )
    args.output.write_bytes(canonical(result))
    if not result["integrity_valid"]:
        raise SystemExit("Evidence integrity check failed; report marks affected records")
    print("Version-pinned incident report saved.")


if __name__ == "__main__":
    main()
