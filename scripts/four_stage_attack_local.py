"""In-memory four-stage lab. No external token input, network, or AWS invocation."""

import argparse
import copy
import json
from unittest.mock import patch

from sealed_telemetry import four_stage as demo
from sealed_telemetry.four_stage_analysis import analyze


class MemoryTable:
    def __init__(self, key):
        self.key = key
        self.rows = {}

    def get_item(self, Key, **kwargs):
        row = self.rows.get(Key[self.key])
        return {"Item": copy.deepcopy(row)} if row else {}

    def put_item(self, Item, **kwargs):
        key = Item[self.key]
        if key in self.rows:
            raise RuntimeError("Local conditional write failed")
        self.rows[key] = copy.deepcopy(Item)
        return {}


def run(*, simulate_copy=False, suppress_intent=False):
    """Only captures tokens created in this memory fixture; never accepts a bearer value."""
    tables = {
        "EXPECTED_TABLE": MemoryTable("action_id"),
        "TOKEN_TABLE": MemoryTable("token_hash"),
        "AUDIT_TABLE": MemoryTable("provider_request_id"),
    }
    intents = []
    # An opaque sentinel from the synthetic issuer is held only inside this closure.
    copied = []
    clock = [1000]
    state = {"application_completed": False, "replay_after_completion": False}

    def emit(event, context):
        intents.append(
            {
                "event_type": "APP_INTENT",
                "event_id": "local-intent-1",
                "action_id": event["action_id"],
                "operation": demo.OPERATION,
                "filename": demo.FILENAME,
                "recorded_at": clock[0],
            }
        )

    def invoke(name, payload):
        if name == "APP_FUNCTION":
            result = demo.app({**payload, "suppress_app_intent": suppress_intent}, None)
            state["application_completed"] = True
            return result
        if name == "ISSUER_FUNCTION":
            result = demo.issuer(payload, None)
            if simulate_copy and "access_token" in result:
                copied.append(result["access_token"])
            return result
        if name == "SAAS_FUNCTION":
            return demo.saas(payload, None)
        raise RuntimeError("Unknown local function")

    def no_network(*args, **kwargs):
        raise RuntimeError("Network is disabled in the local synthetic harness")

    try:
        with (
            patch.object(demo, "table", side_effect=lambda name: tables[name]),
            patch.object(demo, "call", side_effect=invoke),
            patch.object(demo, "emit_intent", side_effect=emit),
            patch.object(demo.time, "time", side_effect=lambda: clock[0]),
            patch.dict(demo.os.environ, {"FOUR_STAGE_LAB_ENABLED": "true"}),
            patch("socket.socket.connect", side_effect=no_network),
            patch("socket.create_connection", side_effect=no_network),
        ):
            event = {
                "body": json.dumps({"operation": demo.OPERATION, "filename": demo.FILENAME}),
                "requestContext": {
                    "authorizer": {
                        "iam": {"userArn": "arn:aws:sts::000000000000:assumed-role/local/synthetic"}
                    }
                },
            }
            response = demo.authorization(event, None)
            if response["statusCode"] != 200:
                raise RuntimeError("Local legitimate operation failed")
            action = next(iter(tables["EXPECTED_TABLE"].rows.values()))
            if simulate_copy:
                if not state["application_completed"] or not copied:
                    raise RuntimeError("Local simulation sequencing failed")
                clock[0] += 1
                state["replay_after_completion"] = True
                demo.saas({**action, "access_token": copied[0]}, None)
                clock[0] += 1
                demo.saas(
                    {**action, "access_token": copied[0], "filename": "invoice_102.pdf"}, None
                )
        audits = list(tables["AUDIT_TABLE"].rows.values())
        expected = list(tables["EXPECTED_TABLE"].rows.values())
        return {
            "mode": "local-in-memory-only",
            **state,
            "token_copy_enabled": simulate_copy,
            "expected": expected,
            "intents": intents,
            "audits": audits,
            "findings": analyze(expected, intents, audits, now=1010, complete=True),
        }
    finally:
        copied.clear()
        tables["TOKEN_TABLE"].rows.clear()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--simulate-copy", action="store_true")
    parser.add_argument("--suppress-intent", action="store_true")
    args = parser.parse_args()
    print(
        json.dumps(
            run(simulate_copy=args.simulate_copy, suppress_intent=args.suppress_intent), indent=2
        )
    )


if __name__ == "__main__":
    main()
