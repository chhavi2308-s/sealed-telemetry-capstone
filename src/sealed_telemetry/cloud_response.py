"""Leased, approval-bound containment with explicit backend denial verification."""

import base64
import json
import os
from typing import Any
from urllib.error import URLError
from uuid import NAMESPACE_URL, uuid4, uuid5

import boto3
from boto3.dynamodb.conditions import Key
from boto3.dynamodb.types import TypeSerializer
from botocore.exceptions import BotoCoreError, ClientError

from sealed_telemetry.approvals import action_fields, verify_proof
from sealed_telemetry.aws_support import SDK_CONFIG
from sealed_telemetry.cloud_lab import emit, https_json, invoke
from sealed_telemetry.schema import Evidence, canonical, digest, new_event, timestamp, utcnow


def responder(event: dict[str, Any], context: Any) -> dict[str, Any]:
    if event.get("approved") is not True:
        return {"status": "approval_required", "verified_at": None}
    if event.get("state") not in {"SUSPICIOUS", "CORROBORATED_SUSPECTED_ABUSE"}:
        raise ValueError("finding not eligible for containment")
    verify_proof(event)
    resource = boto3.resource("dynamodb", config=SDK_CONFIG)
    responses = resource.Table(os.environ["RESPONSE_TABLE"])
    response_id, action_hash = event["approval_id"], digest(action_fields(event))
    previous = responses.get_item(Key={"response_id": response_id}, ConsistentRead=True).get("Item")
    now = int(timestamp(utcnow()).timestamp())
    if previous:
        if previous["request_hash"] != action_hash:
            raise ValueError("response action identity conflict")
        if (
            previous["status"] in {"verified", "failed"}
            or ("body" in previous and not json.loads(previous["body"]).get("retryable"))
            or (int(previous["attempt"]) >= 3 and "body" in previous)
        ):
            if "evidence" in previous:
                emit(Evidence.parse(json.loads(previous["evidence"]), "responder"))
            result: dict[str, Any] = json.loads(previous["body"])
            return result
        if previous["status"] == "in_progress" and int(previous["lease_until"]) > now:
            return {"status": "in_progress", "verified_at": None, "retryable": True}
    if previous and int(previous["attempt"]) >= 3:
        return {"status": "unverified", "verified_at": None, "retryable": False}
    attempt = int(previous["attempt"]) + 1 if previous else 1
    owner = str(uuid4())
    claim = {
        "response_id": response_id,
        "request_hash": action_hash,
        "status": "in_progress",
        "attempt": attempt,
        "lease_owner": owner,
        "lease_until": now + 60,
    }
    args: dict[str, Any] = {
        "Item": claim,
        "ConditionExpression": "attribute_not_exists(response_id)",
    }
    if previous:
        args.update(
            ConditionExpression="attempt=:old AND lease_owner=:owner AND #s=:status",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":old": previous["attempt"],
                ":owner": previous["lease_owner"],
                ":status": previous["status"],
            },
        )
    try:
        responses.put_item(**args)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
            raise
        return {"status": "in_progress", "verified_at": None, "retryable": True}
    result = {
        "status": "unverified",
        "verified_at": None,
        "retryable": True,
        "decision_id": event["decision_id"],
        "approval_id": response_id,
        "run_id": event["run_id"],
        "attempt": attempt,
        "integration_disabled": event.get("disable_integration") is True,
        "recovery": "separate_approved_recovery_required",
    }
    fingerprint = event["credential_fingerprint"]
    try:
        table = resource.Table(os.environ["TOKEN_TABLE"])
        rows = table.query(
            IndexName="CredentialIndex",
            KeyConditionExpression=Key("credential_fingerprint").eq(fingerprint),
        )["Items"]
        if len(rows) != 1:
            raise RuntimeError("credential lookup unavailable or ambiguous")
        row = table.get_item(Key={"token_hash": rows[0]["token_hash"]}, ConsistentRead=True)["Item"]
        if row["scope"] not in {"records:read", "records:export"}:
            raise ValueError("unsupported registered scope")
        plaintext = boto3.client("kms", config=SDK_CONFIG).decrypt(
            CiphertextBlob=base64.b64decode(row["encrypted_token"]),
            KeyId=os.environ["CREDENTIAL_KEY"],
            EncryptionContext={"purpose": "sealed-lab-token", "fingerprint": fingerprint},
        )["Plaintext"]
        token = plaintext.decode()
        if event.get("action", "contain") == "recover":
            result.update(restore(table, token, fingerprint, row["scope"], event))
        elif event.get("action", "contain") == "contain":
            table.update_item(
                Key={"token_hash": row["token_hash"]},
                UpdateExpression="SET revoked=:yes",
                ExpressionAttributeValues={":yes": True},
            )
            if event.get("disable_integration") is True:
                table.put_item(Item={"token_hash": "integration:enabled", "enabled": False})
            verify_url = os.environ["SAAS_URL"]
            if row["scope"] == "records:export":
                verify_url = verify_url.rsplit("/", 1)[0] + "/export"
            verification = https_json(
                verify_url,
                headers={"Authorization": "Bearer " + token, "X-Run-Id": event["run_id"]},
            )
            body = verification.get("body", {})
            verified = (
                verification["status"] == 403
                and body.get("error") == "invalid_token"
                and body.get("reason") in {"revoked", "integration_disabled"}
                and bool(body.get("provider_request_id"))
            )
            result.update(
                status="verified" if verified else "unverified",
                verified_at=utcnow() if verified else None,
                verification_status=verification["status"],
                verification_request_id=body.get("provider_request_id"),
                retryable=not verified and verification["status"] in {429, 500, 502, 503, 504},
            )
        else:
            raise ValueError("unsupported response action")
    except (BotoCoreError, ClientError, URLError, TimeoutError, RuntimeError, ValueError) as exc:
        result["error_type"] = type(exc).__name__  # Never include provider body, URL auth or token.
    result["retryable"] = bool(result["retryable"] and attempt < 3)
    at = utcnow()
    evidence = new_event(
        "responder",
        "RESPONSE_ACTION",
        run_id=event["run_id"],
        scenario_id="lab-v1",
        event_time_utc=at,
        actor_pseudonym="lab-responder",
        credential_fingerprint=fingerprint,
        operation="integration:recover:verify"
        if event.get("action") == "recover"
        else "token:revoke:verify",
        resource_pseudonym="synthetic-integration",
        outcome="success" if result["status"] == "verified" else "failure",
        trace_context={
            "approval_id": response_id,
            "attempt": str(attempt),
            "request_hash": action_hash,
        },
    )
    evidence = Evidence.parse(
        {
            **evidence.to_dict(),
            "event_id": str(uuid5(NAMESPACE_URL, response_id + ":" + str(attempt))),
        },
        "responder",
    )
    final = {
        **claim,
        "status": result["status"],
        "body": canonical(result).decode(),
        "evidence": canonical(evidence.to_dict()).decode(),
        "recorded_at": at,
        "lease_until": 0,
    }
    serializer = TypeSerializer()
    boto3.client("dynamodb", config=SDK_CONFIG).transact_write_items(
        TransactItems=[
            {
                "Put": {
                    "TableName": os.environ["RESPONSE_TABLE"],
                    "Item": {k: serializer.serialize(v) for k, v in final.items()},
                    "ConditionExpression": "lease_owner=:owner",
                    "ExpressionAttributeValues": {":owner": {"S": owner}},
                }
            },
            {
                "Put": {
                    "TableName": os.environ["RESPONSE_HISTORY_TABLE"],
                    "Item": {
                        "response_id": {"S": response_id},
                        "attempt": {"N": str(attempt)},
                        "body": {"S": canonical(result).decode()},
                        "evidence": {"S": canonical(evidence.to_dict()).decode()},
                    },
                    "ConditionExpression": "attribute_not_exists(response_id)",
                }
            },
        ]
    )
    emit(evidence)
    return result


def restore(
    table: Any, old_token: str, fingerprint: str, scope: str, event: dict[str, Any]
) -> dict[str, Any]:
    """Approved synthetic integration recovery; fail closed if either verification fails."""
    # The old credential must already be revoked before reopening the integration.
    rows = table.query(
        IndexName="CredentialIndex",
        KeyConditionExpression=Key("credential_fingerprint").eq(fingerprint),
    )["Items"]
    row = table.get_item(Key={"token_hash": rows[0]["token_hash"]}, ConsistentRead=True)["Item"]
    if row.get("revoked") is not True:
        raise ValueError("recovery requires previously revoked credential")
    fresh = invoke(os.environ["ISSUER_FUNCTION"], {"operation": "issue", "scope": scope})
    fields = dict(
        run_id=event["run_id"],
        scenario_id="lab-v1",
        event_time_utc=utcnow(),
        actor_pseudonym="lab-integration",
        credential_fingerprint=fresh["credential_fingerprint"],
        operation=scope,
        resource_pseudonym="synthetic-records",
        invocation_id=str(uuid4()),
        action_id=str(uuid4()),
    )
    # Security-owned recovery claims are explicitly distinguished from workload claims.
    for kind in ["EXPECTED_ACTION", "INTENT_CREATED"]:
        emit(new_event("responder", kind, **fields))
    table.put_item(Item={"token_hash": "integration:enabled", "enabled": True})
    url = os.environ["SAAS_URL"]
    if scope == "records:export":
        url = url.rsplit("/", 1)[0] + "/export"
    verified = False
    try:
        old = https_json(
            url, headers={"Authorization": "Bearer " + old_token, "X-Run-Id": event["run_id"]}
        )
        fresh_result = https_json(
            url,
            headers={
                "Authorization": "Bearer " + fresh["access_token"],
                "X-Run-Id": event["run_id"],
                "X-Invocation-Id": fields["invocation_id"],
                "X-Action-Id": fields["action_id"],
            },
        )
        verified = (
            old["status"] == 403
            and old.get("body", {}).get("reason") == "revoked"
            and bool(old.get("body", {}).get("provider_request_id"))
            and fresh_result["status"] == 200
            and bool(fresh_result.get("body", {}).get("provider_request_id"))
        )
        return {
            "status": "verified" if verified else "unverified",
            "verified_at": utcnow() if verified else None,
            "retryable": not verified,
            "recovery": "verified" if verified else "unverified",
            "fresh_credential_fingerprint": fresh["credential_fingerprint"],
            "integration_disabled": not verified,
            "old_credential_verification_id": old.get("body", {}).get("provider_request_id"),
            "fresh_credential_verification_id": fresh_result.get("body", {}).get(
                "provider_request_id"
            ),
        }
    finally:
        if not verified:
            table.put_item(Item={"token_hash": "integration:enabled", "enabled": False})
