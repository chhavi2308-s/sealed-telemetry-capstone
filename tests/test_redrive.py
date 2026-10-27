import json
from unittest.mock import MagicMock, patch

import pytest

from sealed_telemetry.redrive import execute_queue, outbox_replay
from sealed_telemetry.schema import digest


def test_redrive_requires_exact_plan_and_rechecks_configuration():
    session = MagicMock()
    plan = {
        "source": {"url": "source", "arn": "source-arn"},
        "destination": {"url": "dest", "arn": "dest-arn"},
        "maximum_messages_per_second": 5,
    }
    with pytest.raises(ValueError, match="digest"):
        execute_queue(session, plan, "unapproved")
    session.client.assert_not_called()
    with patch("sealed_telemetry.redrive.queue_plan", return_value={"changed": True}):
        with pytest.raises(ValueError, match="changed"):
            execute_queue(session, plan, digest(plan))
    with patch("sealed_telemetry.redrive.queue_plan", return_value=plan):
        session.client.return_value.list_message_move_tasks.return_value = {
            "Results": [{"Status": "RUNNING"}]
        }
        with pytest.raises(ValueError, match="already"):
            execute_queue(session, plan, digest(plan))
        session.client.return_value.start_message_move_task.assert_not_called()


def test_outbox_plan_and_replay_preserve_original_evidence(monkeypatch):
    from sealed_telemetry.schema import new_event

    monkeypatch.setenv("OUTBOX_TABLE", "outbox")
    monkeypatch.setenv("PROVIDER_QUEUE_URL", "provider-queue")
    raw = new_event(
        "provider",
        "PROVIDER_ACTION",
        run_id="run",
        scenario_id="lab",
        event_time_utc="2026-10-27T00:00:00+00:00",
        actor_pseudonym="provider",
        credential_fingerprint="a" * 64,
        operation="records:read",
        resource_pseudonym="synthetic",
        provider_request_id="provider-request",
    ).to_dict()
    with (
        patch("sealed_telemetry.redrive.boto3.resource") as db,
        patch("sealed_telemetry.redrive.publish") as send,
    ):
        db.return_value.Table.return_value.get_item.return_value = {
            "Item": {"body": json.dumps(raw)}
        }
        request = {"event_ids": [raw["event_id"]]}
        plan = outbox_replay(request, None)
        send.assert_not_called()
        with pytest.raises(ValueError, match="changed"):
            outbox_replay({**request, "approved_plan_hash": "wrong"}, None)
        result = outbox_replay({**request, "approved_plan_hash": plan["plan_hash"]}, None)
        assert result["enqueued"] == 1 and result["verified_archived"] is False
        assert send.call_args.args[0][0].to_dict() == raw
        db.return_value.Table.return_value.delete_item.assert_not_called()
