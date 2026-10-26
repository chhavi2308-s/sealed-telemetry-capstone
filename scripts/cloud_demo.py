"""Sanitized AWS Review-2 harness. No bearer token is written to output."""

import argparse
from pathlib import Path
from time import perf_counter

from sealed_telemetry.cloud_lab import https_json
from sealed_telemetry.schema import canonical, utcnow


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--workload-url", required=True)
    p.add_argument("--saas-url", required=True)
    p.add_argument(
        "--scenario", choices=["normal", "replay-suppression", "benign-log-failure"], required=True
    )
    p.add_argument("--region", required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    import os

    os.environ["AWS_REGION"] = args.region
    started_at = utcnow()
    start = perf_counter()
    attack = args.scenario == "replay-suppression"
    result = https_json(
        args.workload_url,
        {"suppress_log": args.scenario != "normal", "expose_test_token": attack},
        signed=True,
    )
    if result["status"] != 200:
        raise SystemExit("Workload call failed; no successful demonstration claimed")
    body = result["body"]
    replay_status = None
    if attack:
        token = body.pop("disposable_test_token", None)
        if not token:
            raise SystemExit("Explicit disposable-token exposure build is not enabled")
        replay = https_json(
            args.saas_url, headers={"Authorization": "Bearer " + token, "X-Run-Id": body["run_id"]}
        )
        replay_status = replay["status"]
        del token
    record = {
        "mode": "aws_harness",
        "run_id": body["run_id"],
        "scenario": args.scenario,
        "started_at": started_at,
        "completed_at": utcnow(),
        "harness_duration_seconds": perf_counter() - start,
        "legitimate_status": body["application_result"]["status"],
        "replay_status": replay_status,
        "detection_status": "not_yet_observed",
        "ground_truth_attack": attack,
    }
    args.output.write_bytes(canonical(record))
    print(
        "Sanitized harness observation saved; independently retrieve findings and archive versions."
    )


if __name__ == "__main__":
    main()
