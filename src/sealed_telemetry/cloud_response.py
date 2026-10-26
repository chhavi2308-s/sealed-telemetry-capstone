"""Approved cloud containment with encrypted token retrieval and actual rejection check."""

import base64
import json
import os
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from sealed_telemetry.aws_support import SDK_CONFIG
from sealed_telemetry.cloud_lab import emit, https_json
from sealed_telemetry.schema import Evidence, canonical, new_event, utcnow


def responder(event: dict[str, Any], context: Any) -> dict[str, Any]:
    if event.get("approved") is not True:
        return {"status": "approval_required", "verified_at": None}
    if event.get("state") not in {"SUSPICIOUS", "CORROBORATED_SUSPECTED_ABUSE"}:
        raise ValueError("finding not eligible for containment")
    responses = boto3.resource("dynamodb", config=SDK_CONFIG).Table(os.environ["RESPONSE_TABLE"])
    previous = responses.get_item(
        Key={"response_id": event["decision_id"]}, ConsistentRead=True
    ).get("Item")
    if previous:
        saved: dict[str, Any] = json.loads(previous["body"])
        emit(Evidence.parse(json.loads(previous["evidence"]), "responder"))
        return saved
    fingerprint = event["credential_fingerprint"]
    table = boto3.resource("dynamodb", config=SDK_CONFIG).Table(os.environ["TOKEN_TABLE"])
    rows = table.query(
        IndexName="CredentialIndex",
        KeyConditionExpression=Key("credential_fingerprint").eq(fingerprint),
    )["Items"]
    if len(rows) != 1:
        raise RuntimeError("credential unavailable or ambiguous; retry after index propagation")
    row = table.get_item(Key={"token_hash": rows[0]["token_hash"]}, ConsistentRead=True)["Item"]
    plaintext = boto3.client("kms", config=SDK_CONFIG).decrypt(
        CiphertextBlob=base64.b64decode(row["encrypted_token"]),
        KeyId=os.environ["CREDENTIAL_KEY"],
        EncryptionContext={"purpose": "sealed-lab-token", "fingerprint": fingerprint},
    )["Plaintext"]
    token = plaintext.decode()
    table.update_item(
        Key={"token_hash": row["token_hash"]},
        UpdateExpression="SET revoked = :yes",
        ExpressionAttributeValues={":yes": True},
    )
    if event.get("disable_integration") is True:
        table.put_item(Item={"token_hash": "integration:enabled", "enabled": False})
    verification = https_json(
        os.environ["SAAS_URL"],
        headers={"Authorization": "Bearer " + token, "X-Run-Id": event["run_id"]},
    )
    verified = verification["status"] == 403
    now = utcnow()
    result = {
        "status": "verified" if verified else "unverified",
        "verified_at": now if verified else None,
        "decision_id": event["decision_id"],
        "run_id": event["run_id"],
        "verification_status": verification["status"],
        "recovery": "not_requested",
        "integration_disabled": event.get("disable_integration") is True,
    }
    result["recovery"] = "manual_clean_redeployment_required"
    evidence = new_event(
        "responder",
        "RESPONSE_ACTION",
        run_id=event["run_id"],
        scenario_id="lab-v1",
        event_time_utc=now,
        actor_pseudonym="lab-responder",
        credential_fingerprint=fingerprint,
        operation="token:revoke:verify",
        resource_pseudonym="synthetic-integration",
        outcome="success" if verified else "failure",
    )
    try:
        responses.put_item(
            Item={
                "response_id": event["decision_id"],
                "decision_id": event["decision_id"],
                "body": canonical(result).decode(),
                "evidence": canonical(evidence.to_dict()).decode(),
                "recorded_at": now,
            },
            ConditionExpression="attribute_not_exists(response_id)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
            raise
        previous = responses.get_item(
            Key={"response_id": event["decision_id"]}, ConsistentRead=True
        )["Item"]
        result = json.loads(previous["body"])
        evidence = Evidence.parse(json.loads(previous["evidence"]), "responder")
    emit(evidence)
    return result
