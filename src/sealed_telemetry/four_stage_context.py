"""Opt-in source-owned C4 records. No context ID is generated in place of an invocation."""

import hashlib
import hmac
import os
import re
import time
from typing import Any
from uuid import uuid4

import boto3
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import BotoCoreError, ClientError

from sealed_telemetry.aws_support import SDK_CONFIG
from sealed_telemetry.four_stage_c3_schema import normalize as normalize_c2
from sealed_telemetry.four_stage_c3_schema import plain, uuid
from sealed_telemetry.four_stage_evidence import epoch
from sealed_telemetry.schema import canonical, digest, timestamp

VERSION = "four-stage-context-4"


def context_keys() -> tuple[str, dict[str, bytes]]:
    from sealed_telemetry.four_stage_binding import _key, _secret, _version

    value = _secret("C4_CONTEXT_SECRET")
    active = _version(value["active_version"])
    keys = {_version(version): _key(encoded) for version, encoded in value["keys"].items()}
    if active not in keys:
        raise ValueError("MISSING_CONTEXT_KEY")
    return active, keys


def signed_fields(binding: dict[str, Any]) -> dict[str, str]:
    return {
        key: binding[key]
        for key in (
            "app_invocation_id",
            "action_id",
            "issuance_id",
            "credential_fingerprint",
            "context_request_id",
            "context_key_version",
            "event_time_utc",
        )
    }


def signature(fields: dict[str, str], key: bytes) -> str:
    return hmac.new(
        key, b"sealed-telemetry:app-context:4\x00" + canonical(fields), hashlib.sha256
    ).hexdigest()


def enabled() -> bool:
    mode = os.environ.get("FOUR_STAGE_CONTEXT_MODE", "disabled")
    if mode not in {"disabled", "c4"}:
        raise ValueError("INVALID_CONTEXT_MODE")
    if mode == "c4" and os.environ.get("FOUR_STAGE_EVIDENCE_MODE") != "c2":
        raise ValueError("C4_REQUIRES_C2")
    return mode == "c4"


def database() -> Any:
    return boto3.resource("dynamodb", config=SDK_CONFIG)


def table(db: Any, variable: str) -> Any:
    return db.Table(os.environ[variable])


def read(db: Any, variable: str, key: dict[str, str]) -> dict[str, Any]:
    value: dict[str, Any] = table(db, variable).get_item(Key=key, ConsistentRead=True).get("Item")
    if not value:
        raise ValueError("MISSING_CONTEXT")
    result: dict[str, Any] = plain(value)
    return result  # DynamoDB Decimal timestamps retain their integral value.


def append(db: Any, variable: str, record: dict[str, Any], key: str) -> None:
    # No retry after an indeterminate write. The immutable key exposes later conflicts.
    table(db, variable).put_item(Item=record, ConditionExpression=Attr(key).not_exists())


def invocation(context: Any) -> str:
    return uuid(getattr(context, "aws_request_id", None))


def dispatch(event: dict[str, Any], context: Any, expected: dict[str, Any]) -> dict[str, Any]:
    from sealed_telemetry import four_stage as demo

    db = database()
    api_id = event.get("requestContext", {}).get("requestId")
    if api_id is not None and (
        not isinstance(api_id, str) or re.fullmatch(r"[A-Za-z0-9_+=/-]{1,128}", api_id) is None
    ):
        raise ValueError("INVALID_API_REQUEST_ID")
    action = uuid(expected["action_id"])
    record = {
        "record_id": "authorization:" + action,
        "evidence_contract": VERSION,
        "record_kind": "authorization_context",
        "source_id": "gateway",
        "action_id": action,
        "authorization_hash": expected["authorization_hash"],
        "run_id": str(uuid4()),  # A gateway-assigned run, never an invocation ID.
        "scenario_id": "lab-v1",
        "api_gateway_request_id": api_id,
        "gateway_lambda_invocation_id": invocation(context),
        "event_time_utc": epoch(int(time.time())),
    }
    append(db, "C4_GATEWAY_TABLE", record, "record_id")
    payload = {
        name: expected[name]
        for name in (
            "action_id",
            "operation",
            "filename",
            "authorized_at",
            "authorization_expires_at",
        )
    }
    result = demo.call("APP_FUNCTION", payload)
    observed_id = result.get("app_invocation_id")
    if observed_id is not None:
        observed_id = uuid(observed_id)
    append(
        db,
        "C4_GATEWAY_TABLE",
        {
            "record_id": "dispatch:" + action,
            "evidence_contract": VERSION,
            "record_kind": "dispatch_observation",
            "source_id": "gateway",
            "action_id": action,
            "context_hash": digest(record),
            "gateway_lambda_invocation_id": record["gateway_lambda_invocation_id"],
            "reported_app_invocation_id": observed_id,
            "event_time_utc": epoch(int(time.time())),
        },
        "record_id",
    )
    return result


def application(event: dict[str, Any], context: Any) -> dict[str, Any]:
    from sealed_telemetry import four_stage as demo

    try:
        db, app_id = database(), invocation(context)
        action = uuid(event.get("action_id"))
        expected = read(db, "EXPECTED_TABLE", {"action_id": action})
        normalize_c2("gateway", "c2", table(db, "EXPECTED_TABLE").table_arn, action, expected)
        gateway = read(db, "C4_GATEWAY_TABLE", {"record_id": "authorization:" + action})
        if (
            gateway["authorization_hash"] != expected["authorization_hash"]
            or event.get("operation") != expected["operation"]
            or event.get("filename") != expected["filename"]
        ):
            raise ValueError("CONTEXT_MISMATCH")
        started = epoch(int(time.time()))
        intent = {
            "record_id": "intent:" + app_id,
            "evidence_contract": VERSION,
            "record_kind": "application_intent",
            "source_id": "app",
            "app_invocation_id": app_id,
            "action_id": action,
            "run_id": gateway["run_id"],
            "scenario_id": gateway["scenario_id"],
            "context_hash": digest(gateway),
            "authorization_hash": expected["authorization_hash"],
            "event_time_utc": started,
        }
        append(db, "C4_APP_TABLE", intent, "record_id")
        credential = demo.call("ISSUER_FUNCTION", event)
        if (
            "access_token" not in credential
            or credential.get("evidence_contract") != "four-stage-issuance-envelope-2"
        ):
            return {"status": "unavailable", "app_invocation_id": app_id}
        # Independently read issuer-owned evidence; never accept a caller's fingerprint.
        claim = read(db, "ISSUANCE_TABLE", {"issuance_id": "authorization:" + action})
        issuance = read(db, "ISSUANCE_TABLE", {"issuance_id": claim["recorded_issuance_id"]})
        normalize_c2(
            "issuer", "c2", table(db, "ISSUANCE_TABLE").table_arn, issuance["issuance_id"], issuance
        )
        att = issuance["attestation"]
        if (
            att["action_id"] != action
            or claim["authorization_hash"] != expected["authorization_hash"]
        ):
            raise ValueError("ISSUANCE_CONTEXT_MISMATCH")
        binding = {
            "record_id": "binding:" + app_id,
            "evidence_contract": VERSION,
            "record_kind": "application_credential_observation",
            "source_id": "app",
            "app_invocation_id": app_id,
            "action_id": action,
            "intent_hash": digest(intent),
            "issuance_id": att["issuance_id"],
            "credential_fingerprint": att["credential_fingerprint"],
            "fingerprint_key_version": att["fingerprint_key_version"],
            "event_time_utc": epoch(int(time.time())),
            "context_request_id": str(uuid4()),
            "context_key_version": context_keys()[0],
        }
        append(db, "C4_APP_TABLE", binding, "record_id")
        _, keys = context_keys()
        proof = signature(signed_fields(binding), keys[binding["context_key_version"]])
        result = demo.call(
            "SAAS_FUNCTION",
            {
                **event,
                "access_token": credential["access_token"],
                "app_invocation_id": app_id,
                "context_signature": proof,
            },
        )
        if result.get("evidence_contract") != "four-stage-provider-2":
            return {"status": "unavailable", "app_invocation_id": app_id}
        return {
            "status": result["status"],
            "provider_request_id": result["provider_request_id"],
            "app_invocation_id": app_id,
        }
    except (BotoCoreError, ClientError, KeyError, ValueError, TypeError):
        return {"status": "unavailable", "error": "APPLICATION_CONTEXT_UNAVAILABLE"}


def observe_provider(event: dict[str, Any], context: Any) -> dict[str, Any]:
    from sealed_telemetry.four_stage_binding import provider

    try:
        provider_invocation = invocation(context)
        db = database()
        candidate, intent, binding, authenticated = None, None, None, False
        try:
            candidate = uuid(event.get("app_invocation_id"))
            intent = read(db, "C4_APP_TABLE", {"record_id": "intent:" + candidate})
            binding = read(db, "C4_APP_TABLE", {"record_id": "binding:" + candidate})
            _, keys = context_keys()
            proof = event.get("context_signature")
            authenticated = bool(
                isinstance(proof, str)
                and len(proof) == 64
                and hmac.compare_digest(
                    proof, signature(signed_fields(binding), keys[binding["context_key_version"]])
                )
                and binding["action_id"] == event.get("action_id")
                and event.get("operation") == "files:upload"
                and event.get("filename") == "invoice_101.pdf"
                and 0 <= int(time.time()) - timestamp(binding["event_time_utc"]).timestamp() <= 60
            )
        except (KeyError, ValueError, TypeError):
            authenticated = False
        if authenticated and binding is not None:
            # Reserve once before invoking the action. Indeterminate claims never auto-retry.
            try:
                append(
                    db,
                    "C4_PROVIDER_TABLE",
                    {
                        "provider_request_id": "request:" + binding["context_request_id"],
                        "evidence_contract": VERSION,
                        "record_kind": "context_request_claim",
                        "source_id": "provider",
                        "context_request_id": binding["context_request_id"],
                        "app_invocation_id": candidate,
                        "provider_lambda_invocation_id": provider_invocation,
                        "event_time_utc": epoch(int(time.time())),
                    },
                    "provider_request_id",
                )
            except db.meta.client.exceptions.ConditionalCheckFailedException:
                return {"status": "unavailable", "error": "CONTEXT_REQUEST_ALREADY_CLAIMED"}
        result = provider(event, int(time.time()))
        if result.get("status") not in {"success", "denied"}:
            return result
        audit = read(db, "AUDIT_TABLE", {"provider_request_id": result["provider_request_id"]})
        app_id, intent_hash, binding_hash = None, None, None
        try:
            if (
                authenticated
                and intent is not None
                and binding is not None
                and intent["app_invocation_id"] == binding["app_invocation_id"] == candidate
                and binding["intent_hash"] == digest(intent)
                and binding["credential_fingerprint"] == audit["credential_fingerprint"]
                and binding["fingerprint_key_version"] == audit["fingerprint_key_version"]
                and binding["issuance_id"] == audit["issuance_id"]
                and binding["action_id"] == intent["action_id"] == audit["authorized_action_id"]
            ):
                app_id, intent_hash, binding_hash = candidate, digest(intent), digest(binding)
        except (KeyError, ValueError, TypeError):
            pass  # The provider observation remains explicitly unbound to application context.
        append(
            db,
            "C4_PROVIDER_TABLE",
            {
                "provider_request_id": result["provider_request_id"],
                "evidence_contract": VERSION,
                "source_id": "provider",
                "record_kind": "provider_context",
                "provider_lambda_invocation_id": provider_invocation,
                "verified_app_invocation_id": app_id,
                "intent_hash": intent_hash,
                "binding_hash": binding_hash,
                "audit_hash": digest(audit),
                "event_time_utc": epoch(int(time.time())),
                "context_request_id": binding["context_request_id"] if app_id and binding else None,
                "context_key_version": binding["context_key_version"]
                if app_id and binding
                else None,
            },
            "provider_request_id",
        )
        return result
    except (BotoCoreError, ClientError, KeyError, ValueError, TypeError):
        # The underlying provider action may already be recorded: never automatically retry.
        return {"status": "unavailable", "error": "PROVIDER_CONTEXT_OUTCOME_UNKNOWN"}
