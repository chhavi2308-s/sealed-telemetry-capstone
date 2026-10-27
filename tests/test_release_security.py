import json
from pathlib import Path
from unittest.mock import patch

from sealed_telemetry.cloud_response import responder
from sealed_telemetry.schema import digest, timestamp, utcnow


def test_concurrent_response_lease_prevents_second_effect(monkeypatch):
    monkeypatch.setenv("RESPONSE_TABLE", "responses")
    event = {
        "state": "SUSPICIOUS",
        "approved": True,
        "approval_id": "approval",
        "decision_id": "d",
        "run_id": "run",
        "credential_fingerprint": "a" * 64,
    }
    from sealed_telemetry.approvals import action_fields

    previous = {
        "request_hash": digest(action_fields(event)),
        "status": "in_progress",
        "attempt": 1,
        "lease_until": int(timestamp(utcnow()).timestamp()) + 60,
    }
    with (
        patch("sealed_telemetry.cloud_response.verify_proof"),
        patch("sealed_telemetry.cloud_response.boto3.resource") as db,
        patch("sealed_telemetry.cloud_response.https_json") as call,
    ):
        db.return_value.Table.return_value.get_item.return_value = {"Item": previous}
        assert responder(event, None)["status"] == "in_progress"
        db.return_value.Table.return_value.put_item.assert_not_called()
        call.assert_not_called()


def test_cross_account_profiles_preserve_security_boundary():
    root = Path(__file__).resolve().parents[1]
    security = json.loads((root / "infra/security.yaml").read_text(encoding="utf-8"))
    workload = json.loads((root / "infra/workload.yaml").read_text(encoding="utf-8"))
    assert "AppFunction" not in security["Resources"]
    assert "Archive" not in workload["Resources"]
    for name in ["AppPolicy", "AppLogPolicy"]:
        actions = [
            a
            for s in workload["Resources"][name]["Properties"]["PolicyDocument"]["Statement"]
            for a in s["Action"]
        ]
        assert not any(a.startswith(("sts:", "s3:", "dynamodb:", "kms:")) for a in actions)
    deny = security["Resources"]["ArchivePolicy"]["Properties"]["PolicyDocument"]["Statement"][1]
    assert deny["Effect"] == "Deny" and "aws:PrincipalArn" in deny["Condition"]["ArnEquals"]
