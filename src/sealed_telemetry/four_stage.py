"""Four-stage synthetic upload demo; no detector, evidence pipeline or response actions.

Only the authorization handler has an HTTP integration (AWS_IAM protected).
Other handlers are private Lambda invocations. Tokens never leave internal payloads.
"""

import hashlib
import json
import logging
import os
import secrets
import time
from typing import Any
from uuid import uuid4

import boto3
from botocore.config import Config

from sealed_telemetry.aws_handlers import response
from sealed_telemetry.aws_support import SDK_CONFIG
from sealed_telemetry.cloud_lab import parse_body
from sealed_telemetry.schema import canonical

# Do not automatically retry operations which create an audit/action.
INVOKE_CONFIG = Config(connect_timeout=2, read_timeout=20, retries={"total_max_attempts": 1})
OPERATION = "files:upload"
FILENAME = "invoice_101.pdf"
LOG = logging.getLogger(__name__)
LOG.setLevel(logging.INFO)


def table(variable: str) -> Any:
    return boto3.resource("dynamodb", config=SDK_CONFIG).Table(os.environ[variable])


def call(function: str, payload: dict[str, Any]) -> dict[str, Any]:
    result = boto3.client("lambda", config=INVOKE_CONFIG).invoke(
        FunctionName=os.environ[function], Payload=canonical(payload)
    )
    if result.get("FunctionError"):
        raise RuntimeError("internal demo service failed")
    return json.loads(result["Payload"].read())


def authorization(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Validate allowlisted synthetic action and persist EXPECTED_ACTION before invocation."""
    try:
        request = parse_body(event)
    except (ValueError, TypeError):
        return response(400, {"error": "invalid_request"})
    if request != {"operation": OPERATION, "filename": FILENAME}:
        return response(400, {"error": "only_synthetic_invoice_upload_is_allowed"})
    principal = event.get("requestContext", {}).get("authorizer", {}).get("iam", {}).get("userArn")
    if not isinstance(principal, str) or not principal.startswith("arn:"):
        return response(403, {"error": "iam_authentication_required"})
    now = int(time.time())
    action = {
        "action_id": str(uuid4()),
        "operation": OPERATION,
        "filename": FILENAME,
        "authorized_at": now,
        "authorization_expires_at": now + 300,
    }
    table("EXPECTED_TABLE").put_item(
        Item={**action, "event_type": "EXPECTED_ACTION", "expires_at": now + 86400},
        ConditionExpression="attribute_not_exists(action_id)",
    )
    result = call("APP_FUNCTION", action)
    if result.get("status") != "success":
        return response(502, {"action_id": action["action_id"], "error": "operation_failed"})
    return response(
        200,
        {
            **action,
            "status": "success",
            "synthetic": True,
            "provider_request_id": result["provider_request_id"],
        },
    )


def emit_intent(event: dict[str, Any], context: Any) -> None:
    """Only allowlisted action fields are logged; never serialize an invocation payload."""
    intent = {
        "event_type": "APP_INTENT",
        "event_id": str(uuid4()),
        "action_id": event["action_id"],
        "operation": OPERATION,
        "filename": FILENAME,
        "recorded_at": int(time.time()),
        "invocation_id": getattr(context, "aws_request_id", None),
    }
    LOG.info("%s", json.dumps(intent))


def app(event: dict[str, Any], context: Any) -> dict[str, Any]:
    # Only an explicitly enabled lab invocation may omit the application intent.
    # The public authorization request schema still rejects simulation fields.
    suppress = (
        os.environ.get("FOUR_STAGE_LAB_ENABLED") == "true"
        and event.get("suppress_app_intent") is True
    )
    if not suppress:
        emit_intent(event, context)
    credential = call("ISSUER_FUNCTION", event)
    if "access_token" not in credential:
        return {"status": "denied"}
    result = call("SAAS_FUNCTION", {**event, "access_token": credential["access_token"]})
    # Never return the token or the issuer payload to the client.
    return {"status": result["status"], "provider_request_id": result["provider_request_id"]}


def issuer(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Private synthetic OAuth-like issuer; not a standards-complete OAuth server."""
    expected = (
        table("EXPECTED_TABLE")
        .get_item(Key={"action_id": event["action_id"]}, ConsistentRead=True)
        .get("Item")
    )
    if not expected or any(expected.get(k) != event.get(k) for k in ("operation", "filename")):
        return {"error": "not_authorized"}
    now = int(time.time())
    if expected["authorization_expires_at"] <= now:
        return {"error": "authorization_expired"}
    token = secrets.token_urlsafe(32)
    expires = min(now + 300, int(expected["authorization_expires_at"]))
    table("TOKEN_TABLE").put_item(
        Item={
            "token_hash": hashlib.sha256(token.encode()).hexdigest(),
            "action_id": event["action_id"],
            "scope": OPERATION,
            "filename": expected["filename"],
            "audience": "synthetic-saas",
            "expires_at": expires,
        },
        ConditionExpression="attribute_not_exists(token_hash)",
    )
    return {"access_token": token, "token_type": "Bearer", "expires_in": expires - now}


def saas(event: dict[str, Any], context: Any) -> dict[str, Any]:
    token = event.get("access_token", "")
    row = None
    if isinstance(token, str) and 16 <= len(token) <= 256:
        row = (
            table("TOKEN_TABLE")
            .get_item(
                Key={"token_hash": hashlib.sha256(token.encode()).hexdigest()}, ConsistentRead=True
            )
            .get("Item")
        )
    now = int(time.time())
    valid = bool(
        row
        and row["expires_at"] > now
        and row["audience"] == "synthetic-saas"
        and row["scope"] == event.get("operation") == OPERATION
        and row["filename"] == event.get("filename") == FILENAME
        and row["action_id"] == event.get("action_id")
    )
    provider_id = str(uuid4())
    status = "success" if valid else "denied"
    # Audit is the durable synthetic operation receipt; no PDF bytes are stored.
    table("AUDIT_TABLE").put_item(
        Item={
            "provider_request_id": provider_id,
            "event_type": "PROVIDER_ACTION",
            "action_id": event.get("action_id", "unknown"),
            "operation": event.get("operation", "unknown"),
            "filename": event.get("filename", "unknown"),
            "outcome": status,
            "recorded_at": now,
            "synthetic": True,
            "expires_at": now + 86400,
        },
        ConditionExpression="attribute_not_exists(provider_request_id)",
    )
    return {"status": status, "provider_request_id": provider_id}
