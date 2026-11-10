"""Opt-in C2 producers. No collection authentication or execution attestation is implied."""

import base64
import hashlib
import json
import os
import re
import secrets
import time
from dataclasses import asdict, dataclass
from typing import Any
from uuid import UUID, uuid4

import boto3
from boto3.dynamodb.conditions import Attr, ConditionExpressionBuilder
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from sealed_telemetry.aws_support import SDK_CONFIG
from sealed_telemetry.four_stage_evidence import epoch
from sealed_telemetry.four_stage_issuance import (
    FINGERPRINT_PATTERN,
    KEY_VERSION_PATTERN,
    IssuanceAttestation,
    credential_fingerprint,
    verify_attestation_fingerprint,
)
from sealed_telemetry.schema import digest, pseudonym, timestamp

OPERATION = "files:upload"
FILENAME = "invoice_101.pdf"
GATEWAY_VERSION = "four-stage-gateway-2"
REGISTRY_VERSION = "four-stage-registry-2"
ISSUANCE_VERSION = "four-stage-issuance-envelope-2"
PROVIDER_VERSION = "four-stage-provider-2"
TX_CONFIG = Config(retries={"total_max_attempts": 1}, connect_timeout=2, read_timeout=10)
UNCERTAINTY = "Credential binding does not establish application execution or attacker identity."


class EvidenceError(ValueError):
    """Only fixed, non-sensitive reason codes cross the handler boundary."""


@dataclass(frozen=True, repr=False)
class Identity:
    key: bytes
    version: str
    subject: str

    def actor(self) -> str:
        return pseudonym(self.key, "oauth-subject:" + self.subject)

    def resource(self) -> str:
        return pseudonym(self.key, "resource:" + FILENAME)


def _uuid(value: Any) -> str:
    if not isinstance(value, str) or len(value) != 36:
        raise EvidenceError("invalid_action")
    try:
        parsed = UUID(value)
    except ValueError:
        raise EvidenceError("invalid_action") from None
    if str(parsed) != value or parsed.version != 4:
        raise EvidenceError("invalid_action")
    return value


def _version(value: Any) -> str:
    if not isinstance(value, str) or KEY_VERSION_PATTERN.fullmatch(value) is None:
        raise EvidenceError("invalid_configuration")
    return value


def _key(value: Any) -> bytes:
    if not isinstance(value, str):
        raise EvidenceError("invalid_configuration")
    decoded = base64.b64decode(value, validate=True)
    if len(decoded) < 32:
        raise EvidenceError("invalid_configuration")
    return decoded


def _secret(variable: str) -> dict[str, Any]:
    try:
        result = boto3.client("secretsmanager", config=SDK_CONFIG).get_secret_value(
            SecretId=os.environ[variable]
        )
        raw = result["SecretString"]
        if not isinstance(raw, str) or len(raw) > 16384:
            raise ValueError("invalid configuration")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("invalid configuration")
        return value
    except (BotoCoreError, ClientError, KeyError, ValueError, TypeError):
        raise EvidenceError("evidence_configuration_unavailable") from None


def _identity() -> Identity:
    try:
        value = _secret("FOUR_STAGE_IDENTITY_SECRET")
        subject = value["subject"]
        if not isinstance(subject, str) or not subject.strip() or len(subject) > 256:
            raise ValueError("invalid subject")
        return Identity(_key(value["key_b64"]), _version(value["key_version"]), subject)
    except (KeyError, ValueError, TypeError):
        raise EvidenceError("evidence_configuration_unavailable") from None


def _credential_key() -> tuple[str, bytes]:
    try:
        value = _secret("FOUR_STAGE_CREDENTIAL_SECRET")
        version = _version(value["active_version"])
        return version, _key(value["keys"][version])
    except (KeyError, ValueError, TypeError):
        raise EvidenceError("evidence_configuration_unavailable") from None


def prepare_authorization(
    action: dict[str, Any], principal: str, request_id: Any
) -> dict[str, Any]:
    """Gateway-owned fields come from authenticated context and trusted configuration."""
    identity = _identity()
    snapshot = {
        **action,
        "event_type": "EXPECTED_ACTION",
        "source_id": "gateway",
        "evidence_contract": GATEWAY_VERSION,
        "authorization_revision": str(uuid4()),
        "actor_pseudonym": identity.actor(),
        "resource_pseudonym": identity.resource(),
        "authorizing_principal_pseudonym": pseudonym(identity.key, "iam-principal:" + principal),
        "identity_key_version": identity.version,
        "expires_at": action["authorized_at"] + 86400,
    }
    if isinstance(request_id, str) and request_id:
        snapshot["gateway_request_id"] = request_id
    return {**snapshot, "authorization_hash": digest(snapshot)}


def _authorization(raw: dict[str, Any], now: int) -> tuple[dict[str, Any], str]:
    try:
        snapshot = {key: value for key, value in raw.items() if key != "authorization_hash"}
        for key in ("authorized_at", "authorization_expires_at", "expires_at"):
            epoch(snapshot[key])
            snapshot[key] = int(snapshot[key])
        _uuid(snapshot["action_id"])
        _uuid(snapshot["authorization_revision"])
        if (
            snapshot["evidence_contract"] != GATEWAY_VERSION
            or snapshot["event_type"] != "EXPECTED_ACTION"
            or snapshot["source_id"] != "gateway"
            or snapshot["operation"] != OPERATION
            or snapshot["filename"] != FILENAME
        ):
            raise ValueError("unsupported authorization")
        if not snapshot["authorized_at"] <= now < snapshot["authorization_expires_at"]:
            raise EvidenceError("authorization_expired_or_not_yet_valid")
        identity = _identity()
        if (
            snapshot["actor_pseudonym"] != identity.actor()
            or snapshot["resource_pseudonym"] != identity.resource()
            or snapshot["identity_key_version"] != identity.version
        ):
            raise ValueError("identity mismatch")
        principal = snapshot["authorizing_principal_pseudonym"]
        if (
            not isinstance(principal, str)
            or FINGERPRINT_PATTERN.fullmatch(principal) is None
            or principal == "0" * 64
        ):
            raise ValueError("principal binding missing")
        content_hash = digest(snapshot)
        if content_hash != raw["authorization_hash"]:
            raise ValueError("authorization changed")
        return snapshot, content_hash
    except EvidenceError:
        raise
    except (KeyError, ValueError, TypeError):
        raise EvidenceError("invalid_gateway_authorization") from None


def _condition(expression: Any) -> dict[str, Any]:
    built = ConditionExpressionBuilder().build_expression(expression)
    result: dict[str, Any] = {"ConditionExpression": built.condition_expression}
    if built.attribute_name_placeholders:
        result["ExpressionAttributeNames"] = built.attribute_name_placeholders
    if built.attribute_value_placeholders:
        result["ExpressionAttributeValues"] = built.attribute_value_placeholders
    return result


def _persist(
    db: Any,
    snapshot: dict[str, Any],
    content_hash: str,
    registry: dict[str, Any],
    envelope: dict[str, Any],
) -> None:
    expected, tokens, issuance = (
        os.environ[name] for name in ("EXPECTED_TABLE", "TOKEN_TABLE", "ISSUANCE_TABLE")
    )
    if len({expected, tokens, issuance}) != 3:
        raise EvidenceError("invalid_table_configuration")
    sampled_now = int(time.time())
    if not snapshot["authorized_at"] <= sampled_now < snapshot["authorization_expires_at"]:
        raise EvidenceError("authorization_expired_or_not_yet_valid")
    if sampled_now < envelope["recorded_at"]:
        raise EvidenceError("issuance_clock_uncertain")
    expression = Attr("authorization_hash").eq(content_hash)
    expression &= Attr("authorized_at").lte(sampled_now)
    expression &= Attr("authorization_expires_at").gt(sampled_now)
    for name, value in snapshot.items():
        expression &= Attr(name).eq(value)
    claim = {
        "issuance_id": "authorization:" + snapshot["action_id"],
        "record_kind": "issuance_claim",
        "recorded_issuance_id": envelope["issuance_id"],
        "authorization_hash": content_hash,
    }
    try:
        # Resource client marshals native Python values throughout TransactItems.
        db.meta.client.transact_write_items(
            ClientRequestToken=envelope["issuance_id"],
            TransactItems=[
                {
                    "ConditionCheck": {
                        "TableName": expected,
                        "Key": {"action_id": snapshot["action_id"]},
                        **_condition(expression),
                    }
                },
                {
                    "Put": {
                        "TableName": tokens,
                        "Item": registry,
                        **_condition(Attr("token_hash").not_exists()),
                    }
                },
                {
                    "Put": {
                        "TableName": issuance,
                        "Item": envelope,
                        **_condition(Attr("issuance_id").not_exists()),
                    }
                },
                {
                    "Put": {
                        "TableName": issuance,
                        "Item": claim,
                        **_condition(Attr("issuance_id").not_exists()),
                    }
                },
            ],
        )
    except db.meta.client.exceptions.TransactionCanceledException:
        existing = (
            db.Table(issuance)
            .get_item(Key={"issuance_id": claim["issuance_id"]}, ConsistentRead=True)
            .get("Item")
        )
        if existing:
            reason = (
                "issuance_already_recorded"
                if existing.get("authorization_hash") == content_hash
                else "issuance_conflict"
            )
            raise EvidenceError(reason) from None
        raise EvidenceError("issuance_not_committed") from None
    except (BotoCoreError, ClientError):
        # A timeout may occur after commit. Never mint a replacement automatically.
        raise EvidenceError("issuance_outcome_unknown") from None


def issue(event: dict[str, Any], now: int) -> dict[str, Any]:
    try:
        action_id = _uuid(event.get("action_id"))
        if event.get("operation") != OPERATION or event.get("filename") != FILENAME:
            raise EvidenceError("not_authorized")
        db = boto3.resource("dynamodb", config=TX_CONFIG)
        expected_table = db.Table(os.environ["EXPECTED_TABLE"])
        raw = expected_table.get_item(Key={"action_id": action_id}, ConsistentRead=True).get("Item")
        if not raw:
            raise EvidenceError("not_authorized")
        snapshot, content_hash = _authorization(raw, now)
        existing_claim = (
            db.Table(os.environ["ISSUANCE_TABLE"])
            .get_item(Key={"issuance_id": "authorization:" + action_id}, ConsistentRead=True)
            .get("Item")
        )
        if existing_claim:
            reason = (
                "issuance_already_recorded"
                if existing_claim.get("authorization_hash") == content_hash
                else "issuance_conflict"
            )
            raise EvidenceError(reason)
        version, key = _credential_key()
        received_at = now
        now = int(time.time())
        if now < received_at:
            raise EvidenceError("issuance_clock_uncertain")
        if not snapshot["authorized_at"] <= now < snapshot["authorization_expires_at"]:
            raise EvidenceError("authorization_expired_or_not_yet_valid")
        token_id, issuance_id = str(uuid4()), str(uuid4())
        expires = min(now + 300, snapshot["authorization_expires_at"])
        attestation = IssuanceAttestation(
            issuance_id=issuance_id,
            token_id=token_id,
            action_id=action_id,
            actor_pseudonym=snapshot["actor_pseudonym"],
            operation=OPERATION,
            resource_pseudonym=snapshot["resource_pseudonym"],
            issued_at_utc=epoch(now),
            expires_at_utc=epoch(expires),
            credential_fingerprint=credential_fingerprint(
                token_id=token_id, key=key, key_version=version
            ),
            fingerprint_key_version=version,
            authorization_native_id=action_id,
        )
        if not verify_attestation_fingerprint(attestation, keyring={version: key}):
            raise EvidenceError("invalid_issuance_binding")
        reference = {
            "table_arn": expected_table.table_arn,
            "native_id": action_id,
            "revision": snapshot["authorization_revision"],
            "canonical_hash": content_hash,
            "authorized_at_utc": epoch(snapshot["authorized_at"]),
            "authorization_expires_at_utc": epoch(snapshot["authorization_expires_at"]),
        }
        export = attestation.to_evidence_dict()
        envelope = {
            "issuance_id": issuance_id,
            "record_kind": "issuance_evidence",
            "source_id": "issuer",
            "evidence_contract": ISSUANCE_VERSION,
            "attestation": export,
            "authorization_reference": reference,
            "recorded_at": now,
            "request_received_at_utc": epoch(received_at),
            "binding_uncertainty": UNCERTAINTY,
        }
        token = secrets.token_urlsafe(32)
        registry = {
            "token_hash": hashlib.sha256(token.encode()).hexdigest(),
            "registry_contract": REGISTRY_VERSION,
            "private_attestation": asdict(attestation),
            "authorization_reference": reference,
            "scope": OPERATION,
            "filename": FILENAME,
            "audience": "synthetic-saas",
            "expires_at": expires,
            "revoked": False,
        }
        _persist(db, snapshot, content_hash, registry, envelope)
        return {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": expires - now,
            "evidence_contract": ISSUANCE_VERSION,
        }
    except EvidenceError as exc:
        return {"error": str(exc)}
    except (BotoCoreError, ClientError, KeyError, ValueError, TypeError):
        return {"error": "issuance_unavailable"}


def _reference(raw: Any, attestation: IssuanceAttestation) -> dict[str, str]:
    fields = {
        "table_arn",
        "native_id",
        "revision",
        "canonical_hash",
        "authorized_at_utc",
        "authorization_expires_at_utc",
    }
    if (
        not isinstance(raw, dict)
        or set(raw) != fields
        or not all(isinstance(v, str) for v in raw.values())
    ):
        raise ValueError("invalid authorization reference")
    if (
        re.fullmatch(
            r"arn:(aws|aws-cn|aws-us-gov):dynamodb:[a-z0-9-]+:[0-9]{12}:table/[A-Za-z0-9_.-]{3,255}",
            raw["table_arn"],
        )
        is None
    ):
        raise ValueError("invalid authorization resource")
    _uuid(raw["revision"])
    if (
        raw["native_id"] != attestation.action_id
        or FINGERPRINT_PATTERN.fullmatch(raw["canonical_hash"]) is None
    ):
        raise ValueError("invalid authorization binding")
    if not (
        timestamp(raw["authorized_at_utc"])
        <= timestamp(attestation.issued_at_utc)
        < timestamp(attestation.expires_at_utc)
        <= timestamp(raw["authorization_expires_at_utc"])
    ):
        raise ValueError("invalid authorization lifetime")
    return {name: raw[name] for name in fields}


def provider(event: dict[str, Any], now: int) -> dict[str, Any]:
    """Only a provider-owned lookup establishes known credential identity."""
    try:
        received_at = now
        db = boto3.resource("dynamodb", config=SDK_CONFIG)
        token = event.get("access_token")
        row = None
        if isinstance(token, str) and 16 <= len(token) <= 256:
            row = (
                db.Table(os.environ["TOKEN_TABLE"])
                .get_item(
                    Key={"token_hash": hashlib.sha256(token.encode()).hexdigest()},
                    ConsistentRead=True,
                )
                .get("Item")
            )
        attestation = None
        reference = None
        reason = "unknown_credential"
        if row and row.get("registry_contract") == REGISTRY_VERSION:
            try:
                candidate = IssuanceAttestation.parse(row["private_attestation"])
                epoch(row["expires_at"])
                if (
                    row["scope"] != candidate.operation
                    or row["filename"] != FILENAME
                    or row["audience"] != "synthetic-saas"
                    or epoch(row["expires_at"]) != candidate.expires_at_utc
                    or row["authorization_reference"]["native_id"] != candidate.action_id
                    or type(row.get("revoked")) is not bool
                ):
                    raise ValueError("inconsistent registry")
                reference = _reference(row["authorization_reference"], candidate)
                attestation = candidate
            except (KeyError, ValueError, TypeError):
                reason = "unverifiable_registry_record"
        elif row:
            reason = "unverifiable_registry_record"
        now = int(time.time())
        if now < received_at:
            return {"status": "unavailable", "error": "provider_clock_uncertain"}
        known = attestation is not None
        valid = False
        if known and attestation is not None and row is not None:
            reason = (
                "revoked"
                if row.get("revoked") is not False
                else "expired"
                if row["expires_at"] <= now
                else "not_yet_valid"
                if now < timestamp(attestation.issued_at_utc).timestamp()
                else "action_mismatch"
                if event.get("action_id") != attestation.action_id
                else "operation_mismatch"
                if event.get("operation") != OPERATION
                else "resource_mismatch"
                if event.get("filename") != FILENAME
                else "accepted"
            )
            valid = reason == "accepted"
        try:
            requested_action = _uuid(event.get("action_id"))
        except EvidenceError:
            requested_action = None
        receipt_id = str(uuid4())
        receipt = {
            "provider_request_id": receipt_id,
            "event_type": "PROVIDER_ACTION",
            "source_id": "provider",
            "evidence_contract": PROVIDER_VERSION,
            "recorded_at": now,
            "event_time_utc": epoch(now),
            "request_received_at_utc": epoch(received_at),
            "requested_action_id": requested_action,
            "outcome": "success" if valid else "denied",
            "reason_code": reason,
            "synthetic": True,
            "expires_at": now + 86400,
            "credential_fingerprint": attestation.credential_fingerprint if attestation else None,
            "fingerprint_key_version": attestation.fingerprint_key_version if attestation else None,
            "fingerprint_algorithm": attestation.fingerprint_algorithm if attestation else None,
            "credential_issued_at_utc": attestation.issued_at_utc if attestation else None,
            "credential_expires_at_utc": attestation.expires_at_utc if attestation else None,
            "issuance_id": attestation.issuance_id if attestation else None,
            "authorized_action_id": attestation.action_id if attestation else None,
            "actor_pseudonym": attestation.actor_pseudonym if attestation else None,
            "authorized_resource_pseudonym": attestation.resource_pseudonym
            if attestation
            else None,
            "operation": OPERATION if event.get("operation") == OPERATION else None,
            "resource_pseudonym": attestation.resource_pseudonym
            if attestation and event.get("filename") == FILENAME
            else None,
            "authorization_reference": reference if attestation else None,
            "binding_uncertainty": UNCERTAINTY,
        }
        db.Table(os.environ["AUDIT_TABLE"]).put_item(
            Item=receipt, ConditionExpression=Attr("provider_request_id").not_exists()
        )
        return {
            "status": "success" if valid else "denied",
            "provider_request_id": receipt_id,
            "evidence_contract": PROVIDER_VERSION,
        }
    except (BotoCoreError, ClientError, KeyError, ValueError, TypeError):
        return {"status": "unavailable", "error": "provider_evidence_unavailable"}
