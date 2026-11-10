"""Strict, privacy-bounded C2 projections; validation is not source authentication."""

import re
from dataclasses import fields
from decimal import Decimal
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

from sealed_telemetry.four_stage_evidence import epoch
from sealed_telemetry.schema import Evidence, canonical, digest, timestamp

VERSION = "four-stage-collection-3"
OPERATION = "files:upload"
FILENAME = "invoice_101.pdf"
UNCERTAINTY = "Credential binding does not establish application execution or attacker identity."
TABLE_ARN = re.compile(
    r"arn:(aws|aws-cn|aws-us-gov):dynamodb:([a-z0-9-]+):([0-9]{12}):table/([A-Za-z0-9_.-]{3,255})\Z"
)
ROLE_ARN = re.compile(r"arn:(aws|aws-cn|aws-us-gov):iam::([0-9]{12}):role/([A-Za-z0-9_+=,.@/-]+)\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
KEY_VERSION = re.compile(r"v[1-9][0-9]{0,5}\Z")
ATTESTATION_FIELDS = {
    "issuance_id",
    "action_id",
    "actor_pseudonym",
    "operation",
    "resource_pseudonym",
    "issued_at_utc",
    "expires_at_utc",
    "credential_fingerprint",
    "fingerprint_key_version",
    "authorization_native_id",
    "contract_version",
    "fingerprint_algorithm",
}
REFERENCE_FIELDS = {
    "table_arn",
    "native_id",
    "revision",
    "canonical_hash",
    "authorized_at_utc",
    "authorization_expires_at_utc",
}
GATEWAY_FIELDS = {
    "action_id",
    "operation",
    "filename",
    "authorized_at",
    "authorization_expires_at",
    "expires_at",
    "event_type",
    "source_id",
    "evidence_contract",
    "authorization_revision",
    "actor_pseudonym",
    "resource_pseudonym",
    "authorizing_principal_pseudonym",
    "identity_key_version",
    "authorization_hash",
}
ISSUER_FIELDS = {
    "issuance_id",
    "record_kind",
    "source_id",
    "evidence_contract",
    "attestation",
    "authorization_reference",
    "recorded_at",
    "request_received_at_utc",
    "binding_uncertainty",
}
PROVIDER_FIELDS = {
    "provider_request_id",
    "event_type",
    "source_id",
    "evidence_contract",
    "recorded_at",
    "event_time_utc",
    "request_received_at_utc",
    "requested_action_id",
    "outcome",
    "reason_code",
    "synthetic",
    "expires_at",
    "credential_fingerprint",
    "fingerprint_key_version",
    "fingerprint_algorithm",
    "credential_issued_at_utc",
    "credential_expires_at_utc",
    "issuance_id",
    "authorized_action_id",
    "actor_pseudonym",
    "authorized_resource_pseudonym",
    "operation",
    "resource_pseudonym",
    "authorization_reference",
    "binding_uncertainty",
}
BINDING_FIELDS = {
    "credential_fingerprint",
    "fingerprint_key_version",
    "fingerprint_algorithm",
    "credential_issued_at_utc",
    "credential_expires_at_utc",
    "issuance_id",
    "authorized_action_id",
    "actor_pseudonym",
    "authorized_resource_pseudonym",
    "authorization_reference",
}
REASONS = {
    "accepted",
    "unknown_credential",
    "unverifiable_registry_record",
    "revoked",
    "expired",
    "not_yet_valid",
    "action_mismatch",
    "operation_mismatch",
    "resource_mismatch",
}


class InvalidRecord(ValueError):
    """Fixed diagnostic; producer values are never included in rejection output."""


def require(condition: Any) -> None:
    if not condition:
        raise InvalidRecord("INVALID_SOURCE_RECORD")


def uuid(value: Any) -> str:
    require(isinstance(value, str) and len(value) == 36)
    parsed = UUID(value)
    require(str(parsed) == value and parsed.version == 4)
    return str(value)


def hexdigest(value: Any) -> None:
    require(isinstance(value, str) and HEX.fullmatch(value) and value != "0" * 64)


def key_version(value: Any) -> None:
    require(isinstance(value, str) and KEY_VERSION.fullmatch(value))


def exact(value: Any, required: set[str], optional: set[str] | None = None) -> None:
    require(
        isinstance(value, dict)
        and required <= value.keys()
        and value.keys() <= required | (optional or set())
    )


def plain(value: Any) -> Any:
    if isinstance(value, Decimal):
        require(value.is_finite() and value == value.to_integral_value())
        return int(value)
    if isinstance(value, dict):
        require(all(isinstance(key, str) for key in value))
        return {key: plain(item) for key, item in value.items()}
    if isinstance(value, list):
        return [plain(item) for item in value]
    return value


def reference(value: Any, action: str, issued: str, expires: str) -> None:
    exact(value, REFERENCE_FIELDS)
    require(isinstance(value["table_arn"], str) and TABLE_ARN.fullmatch(value["table_arn"]))
    require(value["native_id"] == action)
    uuid(value["revision"])
    hexdigest(value["canonical_hash"])
    require(
        timestamp(value["authorized_at_utc"])
        <= timestamp(issued)
        < timestamp(expires)
        <= timestamp(value["authorization_expires_at_utc"])
    )


def attestation(value: Any) -> None:
    exact(value, ATTESTATION_FIELDS)
    require(uuid(value["issuance_id"]) != uuid(value["action_id"]))
    require(value["authorization_native_id"] == value["action_id"])
    require(
        value["contract_version"] == "four-stage-issuance-1"
        and value["fingerprint_algorithm"] == "HMAC-SHA256"
        and value["operation"] == OPERATION
    )
    for name in ("actor_pseudonym", "resource_pseudonym", "credential_fingerprint"):
        hexdigest(value[name])
    key_version(value["fingerprint_key_version"])
    require(timestamp(value["issued_at_utc"]) < timestamp(value["expires_at_utc"]))


def _gateway(raw: dict[str, Any], native_id: str) -> str:
    exact(raw, GATEWAY_FIELDS, {"gateway_request_id"})
    require(
        raw["source_id"] == "gateway"
        and raw["event_type"] == "EXPECTED_ACTION"
        and raw["evidence_contract"] == "four-stage-gateway-2"
    )
    require(uuid(raw["action_id"]) == native_id)
    uuid(raw["authorization_revision"])
    if "gateway_request_id" in raw:
        uuid(raw["gateway_request_id"])
    require(raw["operation"] == OPERATION and raw["filename"] == FILENAME)
    for name in (
        "actor_pseudonym",
        "resource_pseudonym",
        "authorizing_principal_pseudonym",
        "authorization_hash",
    ):
        hexdigest(raw[name])
    key_version(raw["identity_key_version"])
    event_time = epoch(raw["authorized_at"])
    require(
        timestamp(event_time)
        < timestamp(epoch(raw["authorization_expires_at"]))
        < timestamp(epoch(raw["expires_at"]))
    )
    require(
        digest({key: value for key, value in raw.items() if key != "authorization_hash"})
        == raw["authorization_hash"]
    )
    return event_time


def _issuer(raw: dict[str, Any], native_id: str) -> str | None:
    if raw.get("record_kind") == "issuance_claim":
        exact(raw, {"issuance_id", "record_kind", "recorded_issuance_id", "authorization_hash"})
        require(native_id == raw["issuance_id"] and native_id.startswith("authorization:"))
        uuid(native_id.removeprefix("authorization:"))
        uuid(raw["recorded_issuance_id"])
        hexdigest(raw["authorization_hash"])
        return None  # Claims are not evidence; no private registry table is read.
    exact(raw, ISSUER_FIELDS)
    require(
        raw["source_id"] == "issuer"
        and raw["record_kind"] == "issuance_evidence"
        and raw["evidence_contract"] == "four-stage-issuance-envelope-2"
    )
    require(uuid(raw["issuance_id"]) == native_id)
    attestation(raw["attestation"])
    a = raw["attestation"]
    require(a["issuance_id"] == native_id and epoch(raw["recorded_at"]) == a["issued_at_utc"])
    require(timestamp(raw["request_received_at_utc"]) <= timestamp(a["issued_at_utc"]))
    require(raw["binding_uncertainty"] == UNCERTAINTY)
    reference(
        raw["authorization_reference"], a["action_id"], a["issued_at_utc"], a["expires_at_utc"]
    )
    return str(a["issued_at_utc"])


def _provider(raw: dict[str, Any], native_id: str) -> str:
    exact(raw, PROVIDER_FIELDS)
    require(
        raw["source_id"] == "provider"
        and raw["event_type"] == "PROVIDER_ACTION"
        and raw["evidence_contract"] == "four-stage-provider-2"
    )
    require(uuid(raw["provider_request_id"]) == native_id and raw["synthetic"] is True)
    require(raw["binding_uncertainty"] == UNCERTAINTY and raw["reason_code"] in REASONS)
    event_time = epoch(raw["recorded_at"])
    require(
        raw["event_time_utc"] == event_time
        and timestamp(raw["request_received_at_utc"]) <= timestamp(event_time)
    )
    require(timestamp(epoch(raw["expires_at"])) > timestamp(event_time))
    require(raw["outcome"] == ("success" if raw["reason_code"] == "accepted" else "denied"))
    require(raw["operation"] in {None, OPERATION})
    if raw["requested_action_id"] is not None:
        uuid(raw["requested_action_id"])
    if raw["credential_fingerprint"] is None:
        require(all(raw[name] is None for name in BINDING_FIELDS))
        require(
            raw["reason_code"] in {"unknown_credential", "unverifiable_registry_record"}
            and raw["resource_pseudonym"] is None
        )
        return event_time
    require(all(raw[name] is not None for name in BINDING_FIELDS))
    for name in ("credential_fingerprint", "actor_pseudonym", "authorized_resource_pseudonym"):
        hexdigest(raw[name])
    key_version(raw["fingerprint_key_version"])
    require(raw["fingerprint_algorithm"] == "HMAC-SHA256")
    uuid(raw["issuance_id"])
    uuid(raw["authorized_action_id"])
    require(raw["resource_pseudonym"] in {None, raw["authorized_resource_pseudonym"]})
    reference(
        raw["authorization_reference"],
        raw["authorized_action_id"],
        raw["credential_issued_at_utc"],
        raw["credential_expires_at_utc"],
    )
    if raw["reason_code"] == "accepted":
        require(
            raw["requested_action_id"] == raw["authorized_action_id"]
            and raw["operation"] == OPERATION
            and raw["resource_pseudonym"] == raw["authorized_resource_pseudonym"]
        )
        require(
            timestamp(raw["credential_issued_at_utc"])
            <= timestamp(event_time)
            < timestamp(raw["credential_expires_at_utc"])
        )
    elif raw["reason_code"] == "expired":
        require(timestamp(event_time) >= timestamp(raw["credential_expires_at_utc"]))
    elif raw["reason_code"] == "not_yet_valid":
        require(timestamp(event_time) < timestamp(raw["credential_issued_at_utc"]))
    else:
        require(
            raw["reason_code"]
            in {"revoked", "action_mismatch", "operation_mismatch", "resource_mismatch"}
        )
        if raw["reason_code"] != "revoked":
            require(
                timestamp(raw["credential_issued_at_utc"])
                <= timestamp(event_time)
                < timestamp(raw["credential_expires_at_utc"])
            )
        if raw["reason_code"] == "action_mismatch":
            require(raw["requested_action_id"] != raw["authorized_action_id"])
        elif raw["reason_code"] == "operation_mismatch":
            require(
                raw["requested_action_id"] == raw["authorized_action_id"]
                and raw["operation"] is None
            )
        elif raw["reason_code"] == "resource_mismatch":
            require(
                raw["requested_action_id"] == raw["authorized_action_id"]
                and raw["operation"] == OPERATION
                and raw["resource_pseudonym"] is None
            )
    return event_time


def normalize(
    source: str,
    contract: str,
    resource_arn: str,
    native_id: str,
    payload: dict[str, Any],
    archive_roles: tuple[tuple[str, str], ...] = (),
) -> dict[str, Any] | None:
    """Called only after read-through authentication. No receipt fields come from payload."""
    try:
        if contract == "aws-events-1":
            from sealed_telemetry.four_stage_archive import events_v1

            require(source == "archive" and len(canonical(plain(payload))) <= 65536)
            event = events_v1(payload, native_id, dict(archive_roles))
            result = normalize(event["source_id"], "iber-1", resource_arn, event["event_id"], event)
            require(result is not None)
            assert result is not None
            return {
                **result,
                "contract": contract,
                "data": plain(payload),
                "canonical_evidence": event,
                "normalization_version": "aws-events-table-1",
            }
        if contract == "c4":
            from sealed_telemetry.four_stage_c4_schema import normalize as normalize_c4

            return normalize_c4(source, resource_arn, native_id, payload)
        raw = plain(payload)
        require(isinstance(raw, dict) and len(canonical(raw)) <= 16384)
        if contract == "c2":
            event_time = {"gateway": _gateway, "issuer": _issuer, "provider": _provider}[source](
                raw, native_id
            )
            if event_time is None:
                return None
            kind = source
        elif contract == "iber-1":
            exact(raw, {item.name for item in fields(Evidence)})
            evidence = Evidence.parse(raw, source)
            require(evidence.event_id == uuid(native_id) and evidence.trace_context is None)
            uuid(evidence.run_id)
            require(evidence.scenario_id == "lab-v1")
            expected_type = {
                "gateway": "EXPECTED_ACTION",
                "app": "INTENT_CREATED",
                "provider": "PROVIDER_ACTION",
                "health": "SOURCE_HEALTH",
            }[source]
            require(evidence.event_type == expected_type)
            if source == "health":
                require(
                    evidence.invocation_id is None
                    and evidence.action_id is None
                    and evidence.provider_request_id is None
                    and evidence.outcome == "success"
                )
                require(
                    evidence.actor_pseudonym == "security-monitor"
                    and evidence.operation == "health:check"
                    and evidence.resource_pseudonym == "lab-telemetry"
                    and evidence.credential_fingerprint == "0" * 64
                )
                kind = "health"
            else:
                require(evidence.operation == OPERATION)
                for value in (
                    evidence.actor_pseudonym,
                    evidence.resource_pseudonym,
                    evidence.credential_fingerprint,
                ):
                    hexdigest(value)
                if evidence.action_id is not None:
                    uuid(evidence.action_id)
                if evidence.invocation_id is not None:
                    uuid(evidence.invocation_id)
                if evidence.provider_request_id is not None:
                    uuid(evidence.provider_request_id)
                kind = "canonical"
            event_time = evidence.event_time_utc
        else:
            raise InvalidRecord("UNSUPPORTED_CONTRACT")
        return {
            "source_id": source,
            "contract": contract,
            "kind": kind,
            "event_time_utc": event_time,
            "event_id": str(uuid5(NAMESPACE_URL, canonical([resource_arn, native_id]).decode())),
            "data": raw,
            "normalization_version": VERSION,
        }
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError, RecursionError):
        raise InvalidRecord("INVALID_SOURCE_RECORD") from None
