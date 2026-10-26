"""Disposable AWS lab services. Source identity uses SigV4, never shared API keys."""

import base64
import hashlib
import json
import logging
import os
import secrets
from datetime import timedelta
from typing import Any
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import UUID, uuid4

import boto3
from boto3.dynamodb.types import TypeDeserializer
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

from sealed_telemetry.aws_handlers import response
from sealed_telemetry.aws_support import SDK_CONFIG
from sealed_telemetry.schema import canonical, new_event, pseudonym, timestamp, utcnow

LOG = logging.getLogger(__name__)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


def parse_body(event: dict[str, Any]) -> dict[str, Any]:
    body = event.get("body") or "{}"
    if not isinstance(body, str) or len(body) > 4096 or event.get("isBase64Encoded"):
        raise ValueError("invalid request body")
    value = json.loads(body)
    if not isinstance(value, dict):
        raise ValueError("JSON object required")
    return value


def https_json(
    url: str,
    body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    signed: bool = False,
) -> dict[str, Any]:
    if not url.startswith("https://"):
        raise ValueError("HTTPS required")
    data = canonical(body) if body is not None else None
    hdr = {"Content-Type": "application/json", **(headers or {})}
    method = "POST" if data is not None else "GET"
    if signed:
        session = boto3.Session()
        credentials = session.get_credentials()
        if credentials is None:
            raise RuntimeError("temporary role credentials unavailable")
        aws_request = AWSRequest(method=method, url=url, data=data, headers=hdr)
        SigV4Auth(
            credentials.get_frozen_credentials(), "execute-api", os.environ["AWS_REGION"]
        ).add_auth(aws_request)
        hdr = dict(aws_request.headers)
    try:
        with build_opener(NoRedirect).open(
            Request(url, data=data, headers=hdr, method=method),  # noqa: S310 -- HTTPS enforced
            timeout=8,
        ) as result:
            return {"status": result.status, "body": json.loads(result.read())}
    except HTTPError as exc:
        return {"status": exc.code, "body": {"error": "remote_rejected"}}


def emit(event: Any) -> None:
    result = https_json(os.environ["INTAKE_URL"], event.to_dict(), signed=True)
    if result["status"] != 202:
        raise RuntimeError("evidence intake rejected event")


def invoke(function: str, payload: dict[str, Any]) -> dict[str, Any]:
    result = boto3.client("lambda", config=SDK_CONFIG).invoke(
        FunctionName=function, Payload=canonical(payload)
    )
    if result.get("FunctionError"):
        raise RuntimeError("lab service invocation failed")
    value: dict[str, Any] = json.loads(result["Payload"].read())
    return value


def issuer(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Internal IAM-invoked issuer; no anonymous OAuth issuance endpoint."""
    is_http = "requestContext" in event
    try:
        request = parse_body(event) if is_http else event
    except ValueError:
        return response(400, {"error": "invalid_request"})
    if is_http and request.get("grant_type") != "client_credentials":
        return response(400, {"error": "unsupported_grant_type"})
    if not is_http and request.get("operation") != "issue":
        raise ValueError("unsupported issuer operation")
    scope = request.get("scope", "records:read")
    if scope not in {"records:read", "records:export"}:
        return response(400, {"error": "invalid_scope"}) if is_http else {"error": "invalid_scope"}
    token, token_id = secrets.token_urlsafe(32), str(uuid4())
    secret = boto3.client("secretsmanager", config=SDK_CONFIG).get_secret_value(
        SecretId=os.environ["PSEUDONYM_SECRET"]
    )["SecretString"]
    fingerprint = pseudonym(secret.encode(), token_id)
    encrypted = boto3.client("kms", config=SDK_CONFIG).encrypt(
        KeyId=os.environ["CREDENTIAL_KEY"],
        Plaintext=token.encode(),
        EncryptionContext={"purpose": "sealed-lab-token", "fingerprint": fingerprint},
    )["CiphertextBlob"]
    boto3.resource("dynamodb", config=SDK_CONFIG).Table(os.environ["TOKEN_TABLE"]).put_item(
        Item={
            "token_hash": hashlib.sha256(token.encode()).hexdigest(),
            "credential_fingerprint": fingerprint,
            "encrypted_token": base64.b64encode(encrypted).decode(),
            "scope": scope,
            "audience": "synthetic-saas",
            "expires_at": (timestamp(utcnow()) + timedelta(seconds=300)).isoformat(),
            "revoked": False,
        }
    )
    issued = {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 300,
        "credential_fingerprint": fingerprint,
        "scope": scope,
    }
    return response(200, issued) if is_http else issued


def saas(event: dict[str, Any], context: Any) -> dict[str, Any]:
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    token = headers.get("authorization", "").removeprefix("Bearer ")
    row = (
        boto3.resource("dynamodb", config=SDK_CONFIG)
        .Table(os.environ["TOKEN_TABLE"])
        .get_item(
            Key={"token_hash": hashlib.sha256(token.encode()).hexdigest()}, ConsistentRead=True
        )
        .get("Item")
    )
    integration = (
        boto3.resource("dynamodb", config=SDK_CONFIG)
        .Table(os.environ["TOKEN_TABLE"])
        .get_item(Key={"token_hash": "integration:enabled"}, ConsistentRead=True)
        .get("Item", {"enabled": True})
    )
    operation = "records:export" if event.get("path", "").endswith("/export") else "records:read"
    valid = bool(
        integration["enabled"]
        and row
        and not row["revoked"]
        and row["scope"] == operation
        and row["audience"] == "synthetic-saas"
        and timestamp(row["expires_at"]) > timestamp(utcnow())
    )
    try:
        run_id = str(UUID(headers["x-run-id"])) if headers.get("x-run-id") else str(uuid4())
    except ValueError:
        return response(400, {"error": "lab_run_id_required"})
    audit = new_event(
        "provider",
        "PROVIDER_ACTION",
        run_id=run_id,
        scenario_id="lab-v1",
        event_time_utc=utcnow(),
        actor_pseudonym="lab-integration",
        credential_fingerprint=row["credential_fingerprint"] if row else "0" * 64,
        operation=operation,
        resource_pseudonym="synthetic-records",
        outcome="success" if valid else "denied",
        invocation_id=headers.get("x-invocation-id"),
        action_id=headers.get("x-action-id"),
        provider_request_id=str(uuid4()),
    )
    # Provider-owned durable outbox: audit is committed before synthetic read response.
    boto3.resource("dynamodb", config=SDK_CONFIG).Table(os.environ["OUTBOX_TABLE"]).put_item(
        Item={
            "event_id": audit.event_id,
            "body": canonical(audit.to_dict()).decode(),
            "pending_partition": "pending",
            "created_at": audit.event_time_utc,
        },
        ConditionExpression="attribute_not_exists(event_id)",
    )
    return response(
        200 if valid else 403,
        {
            "provider_request_id": audit.provider_request_id,
            "data": [{"id": "synthetic-001", "value": "lab-only"}] if valid else [],
        },
    )


def audit_forwarder(event: dict[str, Any], context: Any) -> dict[str, Any]:
    failures = []
    decoder = TypeDeserializer()
    for record in event["Records"]:
        if record["eventName"] != "INSERT":
            continue
        try:
            item = {k: decoder.deserialize(v) for k, v in record["dynamodb"]["NewImage"].items()}
            raw = json.loads(item["body"])
            emit(new_event_from_raw(raw))
            boto3.resource("dynamodb", config=SDK_CONFIG).Table(
                os.environ["OUTBOX_TABLE"]
            ).update_item(
                Key={"event_id": raw["event_id"]},
                UpdateExpression="SET delivered_at = :now REMOVE pending_partition",
                ExpressionAttributeValues={":now": utcnow()},
            )
        except Exception:
            # The stream mapping retries and sends exhausted batches to its failure queue.
            LOG.exception("provider_audit_forward_failed event_id=%s", record["eventID"])
            failures.append({"itemIdentifier": record["dynamodb"]["SequenceNumber"]})
    return {"batchItemFailures": failures}


def new_event_from_raw(raw: dict[str, Any]) -> Any:
    from sealed_telemetry.schema import Evidence

    return Evidence.parse(raw, "provider")


def gateway(event: dict[str, Any], context: Any) -> dict[str, Any]:
    try:
        body = parse_body(event)
    except ValueError:
        return response(400, {"error": "invalid_request"})
    run_id, invocation_id, action_id = str(uuid4()), str(uuid4()), str(uuid4())
    credential = invoke(os.environ["ISSUER_FUNCTION"], {"operation": "issue"})
    fields = {
        "run_id": run_id,
        "scenario_id": "lab-v1",
        "event_time_utc": utcnow(),
        "invocation_id": invocation_id,
        "action_id": action_id,
        "credential_fingerprint": credential["credential_fingerprint"],
        "actor_pseudonym": "lab-integration",
        "operation": "records:read",
        "resource_pseudonym": "synthetic-records",
    }
    emit(new_event("gateway", "EXPECTED_ACTION", **fields))
    lab_enabled = os.environ.get("LAB_EXPOSURE_ENABLED") == "true"
    result = invoke(
        os.environ["APP_FUNCTION"],
        {
            "fields": fields,
            "access_token": credential["access_token"],
            "suppress_log": lab_enabled and body.get("suppress_log") is True,
        },
    )
    output = {"run_id": run_id, "application_result": result}
    if lab_enabled and body.get("expose_test_token") is True:
        output["disposable_test_token"] = credential["access_token"]
    return response(200, output)


def app(event: dict[str, Any], context: Any) -> dict[str, Any]:
    fields = event["fields"]
    if not event.get("suppress_log"):
        intent = new_event("app", "INTENT_CREATED", **fields)
        emit(intent)
        LOG.info(canonical(intent.to_dict()).decode())
    result = https_json(
        os.environ["SAAS_URL"],
        headers={
            "Authorization": "Bearer " + event["access_token"],
            "X-Run-Id": fields["run_id"],
            "X-Invocation-Id": fields["invocation_id"],
            "X-Action-Id": fields["action_id"],
        },
    )
    return {
        "status": result["status"],
        "provider_request_id": result["body"].get("provider_request_id"),
    }
