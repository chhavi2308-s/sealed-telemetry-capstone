"""Operator-authenticated callback approval. Task tokens never leave encrypted coordination."""

import base64
import json
import os
from decimal import Decimal
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from sealed_telemetry.aws_handlers import response, source_for_principal
from sealed_telemetry.aws_support import SDK_CONFIG
from sealed_telemetry.cloud_lab import emit, parse_body
from sealed_telemetry.schema import Evidence, canonical, digest, new_event, timestamp, utcnow


def action_fields(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "action": event.get("action", "contain"),
        "decision_id": event["decision_id"],
        "run_id": event["run_id"],
        "credential_fingerprint": event["credential_fingerprint"],
        "state": event["state"],
        "disable_integration": event.get("disable_integration") is True,
    }


def public_record(item: dict[str, Any]) -> dict[str, Any]:
    names = {
        "approval_id",
        "finding",
        "status",
        "requested_at",
        "expires_at",
        "approved_by",
        "approved",
        "authorized_until",
        "request_hash",
        "action_fields",
    }
    return {k: int(v) if isinstance(v, Decimal) else v for k, v in item.items() if k in names}


def broker(event: dict[str, Any], context: Any) -> dict[str, str]:
    finding = action_fields(event["finding"])
    if finding["state"] not in {"SUSPICIOUS", "CORROBORATED_SUSPECTED_ABUSE"}:
        raise ValueError("non-actionable finding")
    approval_id = str(uuid5(NAMESPACE_URL, event["execution_arn"]))
    table = boto3.resource("dynamodb", config=SDK_CONFIG).Table(os.environ["APPROVAL_TABLE"])
    now = utcnow()
    token_hash = digest(event["task_token"])
    encrypted = boto3.client("kms", config=SDK_CONFIG).encrypt(
        KeyId=os.environ["APPROVAL_KEY"],
        Plaintext=event["task_token"].encode(),
        EncryptionContext={"purpose": "sealed-approval", "approval_id": approval_id},
    )["CiphertextBlob"]
    row = {
        "approval_id": approval_id,
        "finding": finding,
        "execution_arn": event["execution_arn"],
        "token_hash": token_hash,
        "encrypted_token": base64.b64encode(encrypted).decode(),
        "requested_at": now,
        "expires_at": int(timestamp(now).timestamp()) + 3500,
        "status": "pending",
    }
    try:
        table.put_item(Item=row, ConditionExpression="attribute_not_exists(approval_id)")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
            raise
        previous = table.get_item(Key={"approval_id": approval_id}, ConsistentRead=True)["Item"]
        if previous["token_hash"] != token_hash or previous["finding"] != finding:
            raise ValueError("approval execution identity conflict") from exc
    return {"approval_id": approval_id}


def authorized(event: dict[str, Any], read_only: bool = False) -> str:
    principal = event.get("requestContext", {}).get("identity", {}).get("userArn")
    roles = [os.environ.get("OPERATOR_PRINCIPAL", "")]
    if read_only:
        roles.append(os.environ.get("INVESTIGATOR_PRINCIPAL", ""))
    source_for_principal(principal, {"operator": roles})
    return str(principal)


def verify_proof(event: dict[str, Any]) -> None:
    """Boolean approved alone is never authorization for the deployed responder."""
    table = boto3.resource("dynamodb", config=SDK_CONFIG).Table(os.environ["APPROVAL_TABLE"])
    row = table.get_item(Key={"approval_id": event["approval_id"]}, ConsistentRead=True).get("Item")
    if (
        not row
        or row.get("approved") is not True
        or row.get("status") not in {"claimed", "approved"}
        or int(row.get("authorized_until", 0)) < timestamp(utcnow()).timestamp()
        or row.get("request_hash") != digest(action_fields(event))
        or row.get("approved_by") != event.get("approved_by")
    ):
        raise ValueError("approved action proof missing, expired or changed")


def api(event: dict[str, Any], context: Any) -> dict[str, Any]:
    try:
        principal = authorized(event)
    except (ValueError, KeyError, TypeError):
        return response(403, {"error": "operator_forbidden"})
    table = boto3.resource("dynamodb", config=SDK_CONFIG).Table(os.environ["APPROVAL_TABLE"])
    params = event.get("pathParameters") or {}
    approval_id = params.get("approval_id")
    if event.get("httpMethod") == "GET":
        if approval_id:
            item = table.get_item(Key={"approval_id": approval_id}, ConsistentRead=True).get("Item")
            return response(
                200 if item else 404, public_record(item) if item else {"error": "not_found"}
            )
        result = table.query(
            IndexName="StatusIndex", KeyConditionExpression=Key("status").eq("pending"), Limit=50
        )
        return response(
            200,
            {
                "approvals": [public_record(i) for i in result["Items"]],
                "truncated": bool(result.get("LastEvaluatedKey")),
            },
        )
    try:
        body = parse_body(event)
        if not approval_id or type(body.get("approved")) is not bool:
            raise ValueError("explicit approval decision required")
        if type(body.get("disable_integration", False)) is not bool:
            raise ValueError("explicit integration decision required")
        row = table.get_item(Key={"approval_id": approval_id}, ConsistentRead=True).get("Item")
        if not row:
            return response(404, {"error": "not_found"})
        if body.get("action", "contain") not in {"contain", "recover"}:
            raise ValueError("unsupported response action")
        action = {
            **row["finding"],
            "action": body.get("action", "contain"),
            "disable_integration": body.get("disable_integration", False),
        }
        if action["action"] == "recover" and action["disable_integration"]:
            raise ValueError("recovery cannot also disable integration")
        request_hash = digest(action)
        if row["status"] == "pending":
            if int(row["expires_at"]) < timestamp(utcnow()).timestamp():
                return response(410, {"error": "approval_expired"})
            now = utcnow()
            evidence = new_event(
                "approval",
                "APPROVAL_DECISION",
                run_id=action["run_id"],
                scenario_id="lab-v1",
                event_time_utc=now,
                actor_pseudonym=digest(principal),
                credential_fingerprint=action["credential_fingerprint"],
                operation="response:approve" if body["approved"] else "response:reject",
                resource_pseudonym="synthetic-integration",
                trace_context={"approval_id": approval_id, "request_hash": request_hash},
            )
            evidence = Evidence.parse(
                {**evidence.to_dict(), "event_id": str(uuid5(NAMESPACE_URL, approval_id))},
                "approval",
            )
            table.update_item(
                Key={"approval_id": approval_id},
                UpdateExpression=(
                    "SET #s=:claimed, approved=:approved, approved_by=:actor, "
                    "request_hash=:hash, authorized_until=:until, "
                    "evidence=:evidence, action_fields=:action, expires_at=:expiry"
                ),
                ConditionExpression="#s=:pending",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":claimed": "claimed",
                    ":pending": "pending",
                    ":approved": body["approved"],
                    ":actor": principal,
                    ":hash": request_hash,
                    ":until": int(timestamp(now).timestamp()) + 900,
                    ":expiry": int(timestamp(now).timestamp()) + 86400,
                    ":evidence": canonical(evidence.to_dict()).decode(),
                    ":action": action,
                },
            )
            row = table.get_item(Key={"approval_id": approval_id}, ConsistentRead=True)["Item"]
        if row.get("request_hash") != request_hash or row.get("approved") != body["approved"]:
            return response(409, {"error": "approval_decision_conflict"})
        callback = {
            "action": action["action"],
            "approved": row["approved"],
            "approved_by": row["approved_by"],
            "approval_id": approval_id,
            "request_hash": request_hash,
            "disable_integration": action["disable_integration"],
        }
        if row["status"] not in {"approved", "rejected"}:
            token = (
                boto3.client("kms", config=SDK_CONFIG)
                .decrypt(
                    KeyId=os.environ["APPROVAL_KEY"],
                    CiphertextBlob=base64.b64decode(row["encrypted_token"]),
                    EncryptionContext={"purpose": "sealed-approval", "approval_id": approval_id},
                )["Plaintext"]
                .decode()
            )
            sfn = boto3.client("stepfunctions", config=SDK_CONFIG)
            try:
                sfn.send_task_success(taskToken=token, output=canonical(callback).decode())
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in {
                    "TaskDoesNotExist",
                    "TaskTimedOut",
                    "InvalidToken",
                }:
                    raise
                # An acknowledgement can be lost; confirm the exact callback in execution history.
                found = False
                for page in sfn.get_paginator("get_execution_history").paginate(
                    executionArn=row["execution_arn"]
                ):
                    for history in page["events"]:
                        value = history.get("taskSucceededEventDetails", {}).get("output", "")
                        if value and json.loads(value) == callback:
                            found = True
                if not found:
                    return response(
                        202, {"status": "callback_unverified", "approval_id": approval_id}
                    )
            table.update_item(
                Key={"approval_id": approval_id},
                UpdateExpression="SET #s=:s",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":s": "approved" if row["approved"] else "rejected"},
            )
        emit(Evidence.parse(json.loads(row["evidence"]), "approval"))
        return response(
            200,
            {"approval_id": approval_id, "status": "approved" if row["approved"] else "rejected"},
        )
    except ValueError:
        return response(400, {"error": "invalid_approval_request"})
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return response(409, {"error": "approval_already_claimed"})
        raise


def cases(event: dict[str, Any], context: Any) -> dict[str, Any]:
    try:
        authorized(event, read_only=True)
    except (ValueError, KeyError, TypeError):
        return response(403, {"error": "operator_forbidden"})
    case_id = (event.get("pathParameters") or {}).get("case_id", "")
    if not case_id or len(case_id) > 512:
        return response(400, {"error": "invalid_case_id"})
    table = boto3.resource("dynamodb", config=SDK_CONFIG).Table(os.environ["DECISION_TABLE"])
    result = table.query(KeyConditionExpression=Key("case_id").eq(case_id), Limit=100)
    return response(
        200,
        {
            "case_id": case_id,
            "decisions": [
                json.loads(i["body"]) for i in result["Items"] if i["decision_id"] != "CURRENT"
            ],
            "truncated": bool(result.get("LastEvaluatedKey")),
        },
    )


def dispatch(event: dict[str, Any], context: Any) -> dict[str, str]:
    """Deterministic execution names deduplicate at-least-once finding delivery for 90 days."""
    finding = event.get("detail", event)
    if finding.get("state") not in {"SUSPICIOUS", "CORROBORATED_SUSPECTED_ABUSE"}:
        return {"status": "not_actionable"}
    execution_name = digest({"case_id": finding["case_id"], "decision_id": finding["decision_id"]})
    try:
        boto3.client("stepfunctions", config=SDK_CONFIG).start_execution(
            stateMachineArn=os.environ["WORKFLOW_ARN"],
            name=execution_name,
            input=canonical(finding).decode(),
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionAlreadyExists":
            raise
        return {"status": "already_started"}
    return {"status": "started"}
