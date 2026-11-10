"""Strict C4 projections; no producer identity or receipt is authentication."""

from typing import Any
from uuid import NAMESPACE_URL, uuid5

from sealed_telemetry.four_stage_c3_schema import (
    InvalidRecord,
    exact,
    hexdigest,
    key_version,
    plain,
    require,
    uuid,
)
from sealed_telemetry.four_stage_health import SOURCES, classify
from sealed_telemetry.schema import canonical, timestamp

FUNCTION_PATTERN = (
    r"arn:(aws|aws-cn|aws-us-gov):lambda:([a-z0-9-]+):([0-9]{12}):function:([A-Za-z0-9_-]{1,64})"
)


def normalize(source: str, arn: str, native: str, payload: dict[str, Any]) -> dict[str, Any]:
    try:
        raw = plain(payload)
        require(len(canonical(raw)) <= 16384 and raw["source_id"] == source)
        common = {"evidence_contract", "source_id", "event_time_utc"}
        if source == "health":
            exact(
                raw,
                common
                | {
                    "event_id",
                    "health_for_source",
                    "function_arn",
                    "function_state",
                    "update_status",
                    "metrics",
                    "diagnostic",
                    "source_health",
                },
            )
            require(uuid(raw["event_id"]) == native)
            require(raw["evidence_contract"] == "four-stage-health-4")
            require(raw["health_for_source"] in SOURCES)
            require(raw["diagnostic"] in {"OBSERVED", "OBSERVATION_UNAVAILABLE"})
            require(raw["function_state"] in {None, "Pending", "Active", "Inactive", "Failed"})
            require(raw["update_status"] in {None, "Successful", "InProgress", "Failed"})
            require(
                isinstance(raw["metrics"], dict)
                and set(raw["metrics"]) <= {"Invocations", "Errors", "Throttles"}
            )
            for item in raw["metrics"].values():
                exact(item, {"timestamp", "sum"})
                timestamp(item["timestamp"])
                require(type(item["sum"]) is int and item["sum"] >= 0)
            require(raw["source_health"] == classify(raw, raw["event_time_utc"]))
        else:
            require(raw["evidence_contract"] == "four-stage-context-4")
            kind = raw["record_kind"]
            fields: set[str]
            if source == "gateway" and kind == "authorization_context":
                fields = {
                    "record_id",
                    "record_kind",
                    "action_id",
                    "authorization_hash",
                    "run_id",
                    "scenario_id",
                    "api_gateway_request_id",
                    "gateway_lambda_invocation_id",
                }
                require(native == "authorization:" + uuid(raw["action_id"]))
                uuid(raw["run_id"])
                require(raw["scenario_id"] == "lab-v1")
                import re

                api_id = raw["api_gateway_request_id"]
                require(
                    api_id is None
                    or (
                        isinstance(api_id, str) and re.fullmatch(r"[A-Za-z0-9_+=/-]{1,128}", api_id)
                    )
                )
                hexdigest(raw["authorization_hash"])
                uuid(raw["gateway_lambda_invocation_id"])
            elif source == "gateway" and kind == "dispatch_observation":
                fields = {
                    "record_id",
                    "record_kind",
                    "action_id",
                    "context_hash",
                    "gateway_lambda_invocation_id",
                    "reported_app_invocation_id",
                }
                require(native == "dispatch:" + uuid(raw["action_id"]))
                uuid(raw["gateway_lambda_invocation_id"])
                if raw["reported_app_invocation_id"] is not None:
                    uuid(raw["reported_app_invocation_id"])
                hexdigest(raw["context_hash"])
            elif source == "app" and kind == "application_intent":
                fields = {
                    "record_id",
                    "record_kind",
                    "app_invocation_id",
                    "action_id",
                    "run_id",
                    "scenario_id",
                    "context_hash",
                    "authorization_hash",
                }
                require(native == "intent:" + uuid(raw["app_invocation_id"]))
                uuid(raw["action_id"])
                uuid(raw["run_id"])
                require(raw["scenario_id"] == "lab-v1")
                hexdigest(raw["context_hash"])
                hexdigest(raw["authorization_hash"])
            elif source == "app" and kind == "application_credential_observation":
                fields = {
                    "record_id",
                    "record_kind",
                    "app_invocation_id",
                    "action_id",
                    "intent_hash",
                    "issuance_id",
                    "credential_fingerprint",
                    "fingerprint_key_version",
                    "context_request_id",
                    "context_key_version",
                }
                require(native == "binding:" + uuid(raw["app_invocation_id"]))
                uuid(raw["action_id"])
                uuid(raw["issuance_id"])
                hexdigest(raw["intent_hash"])
                hexdigest(raw["credential_fingerprint"])
                key_version(raw["fingerprint_key_version"])
                uuid(raw["context_request_id"])
                key_version(raw["context_key_version"])
            elif source == "provider" and kind == "context_request_claim":
                fields = {
                    "provider_request_id",
                    "record_kind",
                    "context_request_id",
                    "app_invocation_id",
                    "provider_lambda_invocation_id",
                }
                require(native == "request:" + uuid(raw["context_request_id"]))
                uuid(raw["app_invocation_id"])
                uuid(raw["provider_lambda_invocation_id"])
            elif source == "provider" and kind == "provider_context":
                fields = {
                    "provider_request_id",
                    "record_kind",
                    "provider_lambda_invocation_id",
                    "verified_app_invocation_id",
                    "intent_hash",
                    "binding_hash",
                    "audit_hash",
                    "context_request_id",
                    "context_key_version",
                }
                require(uuid(raw["provider_request_id"]) == native)
                uuid(raw["provider_lambda_invocation_id"])
                hexdigest(raw["audit_hash"])
                if raw["verified_app_invocation_id"] is None:
                    require(raw["intent_hash"] is None and raw["binding_hash"] is None)
                    require(
                        raw["context_request_id"] is None and raw["context_key_version"] is None
                    )
                else:
                    uuid(raw["verified_app_invocation_id"])
                    hexdigest(raw["intent_hash"])
                    hexdigest(raw["binding_hash"])
                    uuid(raw["context_request_id"])
                    key_version(raw["context_key_version"])
            else:
                raise InvalidRecord("INVALID_C4_RECORD")
            exact(raw, common | fields)
            require(raw.get("record_id", raw.get("provider_request_id")) == native)
        timestamp(raw["event_time_utc"])
        return {
            "source_id": source,
            "contract": "c4",
            "kind": "c4-" + source,
            "event_time_utc": raw["event_time_utc"],
            "data": raw,
            "event_id": str(uuid5(NAMESPACE_URL, canonical([arn, native]).decode())),
            "normalization_version": "four-stage-collection-4",
        }
    except (KeyError, ValueError, TypeError, AttributeError, OverflowError, RecursionError):
        raise InvalidRecord("INVALID_C4_RECORD") from None
