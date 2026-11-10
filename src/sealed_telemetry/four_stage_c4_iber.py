"""Source-preserving C4 joins around the unchanged reconciliation engine."""

import json
from dataclasses import replace
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from sealed_telemetry.four_stage_collection import Configuration
from sealed_telemetry.reconciliation import reconcile
from sealed_telemetry.schema import Evidence, digest, timestamp


def prepare(
    config: Configuration, control: dict[str, Any], rows: list[dict[str, Any]], now: str
) -> dict[str, Any]:
    from sealed_telemetry.four_stage_iber import prepare as prepare_c3

    base = replace(
        config, sources=tuple(s for s in config.sources if s.contract == "c2"), health_functions=()
    )
    result = prepare_c3(base, control, [r for r in rows if r["contract"] == "c2"], now)
    blockers = set(result["blockers"]) - {
        "INCOMPLETE_C2_EVIDENCE",
        "NO_COMPLETE_IBER_EVIDENCE",
        "SOURCE_HEALTH_UNHEALTHY_OR_UNKNOWN",
    }
    markers = json.loads(control["collections"])
    for configured_source in config.sources:
        marker = markers.get(configured_source.table_arn)
        if (
            not marker
            or not marker["ok"]
            or not 0
            <= (timestamp(now) - timestamp(marker["attempted_at_utc"])).total_seconds()
            <= 130
        ):
            blockers.add("SOURCE_COLLECTION_INCOMPLETE")
    if any(r["status"] != "accepted" for r in rows):
        blockers.add("QUARANTINED_EVIDENCE")
    accepted = [
        (row, json.loads(row["body"])["normalized"]) for row in rows if row["status"] == "accepted"
    ]
    c2 = {
        role: {
            record["data"].get(key): (row, record["data"])
            for row, record in accepted
            if record["contract"] == "c2" and record["kind"] == role
        }
        for role, key in (
            ("gateway", "action_id"),
            ("issuer", "issuance_id"),
            ("provider", "provider_request_id"),
        )
    }
    groups: dict[str, dict[str, tuple[dict[str, Any], dict[str, Any]]]] = {}
    for row, record in accepted:
        if record["contract"] != "c4" or record["source_id"] == "health":
            continue
        data = record["data"]
        groups.setdefault(data["record_kind"], {})[row["record_id"]] = (row, data)

    def find(kind: str, field: str, value: str) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        return [entry for entry in groups.get(kind, {}).values() if entry[1][field] == value]

    events: list[Evidence] = []
    manifest: list[dict[str, Any]] = []
    used: set[str] = set()
    context_by_action: dict[str, tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = {}
    provenance_by_action: dict[str, list[dict[str, Any]]] = {}

    def emit(
        source: str,
        kind: str,
        native: str,
        time: str,
        fields: dict[str, Any],
        refs: list[dict[str, Any]],
        **extra: Any,
    ) -> None:
        event = Evidence.parse(
            {
                "event_id": str(uuid5(NAMESPACE_URL, "c4:" + source + ":" + native)),
                "source_id": source,
                "event_type": kind,
                "event_time_utc": time,
                **fields,
                **extra,
            },
            source,
        )
        events.append(event)
        manifest.append(
            {
                "event_id": event.event_id,
                "source_record_ids": sorted({r["record_id"] for r in refs}),
                "invocation_identity_origin": "application Lambda runtime context",
                "credential_identity_origin": "issuer and provider-owned C2 observations",
            }
        )
        used.update(r["record_id"] for r in refs)

    for action, (gateway_row, gateway) in c2["gateway"].items():
        contexts = find("authorization_context", "action_id", action)
        dispatches = find("dispatch_observation", "action_id", action)
        intents = find("application_intent", "action_id", action)
        issued = [
            entry
            for entry in c2["issuer"].values()
            if entry[1]["attestation"]["action_id"] == action
        ]
        if not (len(contexts) == len(dispatches) == len(intents) == len(issued) == 1):
            blockers.add("MISSING_OR_AMBIGUOUS_APPLICATION_CONTEXT")
            continue
        context_row, context = contexts[0]
        dispatch_row, dispatch = dispatches[0]
        intent_row, intent = intents[0]
        issuer_row, issuer = issued[0]
        bindings = find(
            "application_credential_observation", "app_invocation_id", intent["app_invocation_id"]
        )
        if len(bindings) != 1:
            blockers.add("MISSING_OR_AMBIGUOUS_APPLICATION_BINDING")
            continue
        binding_row, binding = bindings[0]
        att = issuer["attestation"]
        if not (
            context["authorization_hash"]
            == intent["authorization_hash"]
            == gateway["authorization_hash"]
            and dispatch["context_hash"] == intent["context_hash"] == digest(context)
            and dispatch["gateway_lambda_invocation_id"] == context["gateway_lambda_invocation_id"]
            and dispatch["reported_app_invocation_id"] == intent["app_invocation_id"]
            and intent["run_id"] == context["run_id"]
            and intent["scenario_id"] == context["scenario_id"]
            and binding["action_id"] == action
            and binding["intent_hash"] == digest(intent)
            and binding["issuance_id"] == att["issuance_id"]
            and binding["credential_fingerprint"] == att["credential_fingerprint"]
            and binding["fingerprint_key_version"] == att["fingerprint_key_version"]
            and timestamp(gateway_time := issuer["authorization_reference"]["authorized_at_utc"])
            <= timestamp(context["event_time_utc"])
            <= timestamp(intent["event_time_utc"])
            <= timestamp(att["issued_at_utc"])
            <= timestamp(binding["event_time_utc"])
            <= timestamp(dispatch["event_time_utc"])
        ):
            blockers.add("APPLICATION_CONTEXT_MISMATCH")
            continue
        fields = {
            "run_id": context["run_id"],
            "scenario_id": context["scenario_id"],
            "actor_pseudonym": att["actor_pseudonym"],
            "credential_fingerprint": att["credential_fingerprint"],
            "operation": att["operation"],
            "resource_pseudonym": att["resource_pseudonym"],
            "invocation_id": intent["app_invocation_id"],
            "action_id": action,
        }
        refs = [gateway_row, context_row, dispatch_row, intent_row, binding_row, issuer_row]
        emit("gateway", "EXPECTED_ACTION", action, gateway_time, fields, refs)
        emit(
            "app",
            "INTENT_CREATED",
            intent["app_invocation_id"],
            intent["event_time_utc"],
            fields,
            refs,
        )
        context_by_action[action] = (fields, intent, binding)
        provenance_by_action[action] = refs
    for receipt_id, (provider_row, provider) in c2["provider"].items():
        contexts = find("provider_context", "provider_request_id", receipt_id)
        owner = context_by_action.get(provider["authorized_action_id"])
        if len(contexts) != 1 or owner is None:
            blockers.add("INCOMPLETE_PROVIDER_CONTEXT")
            continue
        context_row, context = contexts[0]
        fields, intent, binding = owner
        claims = find("context_request_claim", "context_request_id", binding["context_request_id"])
        if len(claims) != 1:
            blockers.add("MISSING_OR_AMBIGUOUS_PROVIDER_REQUEST_CLAIM")
            continue
        claim_row, claim = claims[0]
        if not (
            context["audit_hash"] == digest(provider)
            and context["verified_app_invocation_id"] == intent["app_invocation_id"]
            and context["intent_hash"] == digest(intent)
            and context["binding_hash"] == digest(binding)
            and context["context_request_id"] == binding["context_request_id"]
            and context["context_key_version"] == binding["context_key_version"]
            and claim["app_invocation_id"] == intent["app_invocation_id"]
            and claim["provider_lambda_invocation_id"] == context["provider_lambda_invocation_id"]
            and timestamp(binding["event_time_utc"])
            <= timestamp(claim["event_time_utc"])
            <= timestamp(provider["event_time_utc"])
            <= timestamp(context["event_time_utc"])
        ):
            blockers.add("PROVIDER_CONTEXT_MISMATCH")
            continue
        if provider["operation"] is None or provider["resource_pseudonym"] is None:
            blockers.add("INCOMPLETE_PROVIDER_ACTION")
            continue
        emit(
            "provider",
            "PROVIDER_ACTION",
            receipt_id,
            provider["event_time_utc"],
            {
                **fields,
                "operation": provider["operation"],
                "resource_pseudonym": provider["resource_pseudonym"],
                "action_id": provider["requested_action_id"],
            },
            [
                provider_row,
                context_row,
                claim_row,
                *provenance_by_action[provider["authorized_action_id"]],
            ],
            provider_request_id=receipt_id,
            outcome=provider["outcome"],
        )
    # All supporting records must participate; never silently drop orphan/late evidence.
    for row, record in accepted:
        if record["source_id"] != "health" and row["record_id"] not in used:
            blockers.add("UNMATCHED_SUPPORTING_EVIDENCE")
    health: dict[str, bool | None] = {s: None for s in ("gateway", "app", "provider", "collector")}
    functions = dict(config.health_functions)
    for source in health:
        records = [
            record["data"]
            for _, record in accepted
            if record["kind"] == "c4-health" and record["data"]["health_for_source"] == source
        ]
        if any(record["function_arn"] != functions[source] for record in records):
            blockers.add("HEALTH_RESOURCE_IDENTITY_MISMATCH")
            continue
        if not records:
            continue
        latest_time = max(timestamp(record["event_time_utc"]) for record in records)
        states = {
            record["source_health"]
            for record in records
            if timestamp(record["event_time_utc"]) == latest_time
        }
        if len(states) == 1 and 0 <= (timestamp(now) - latest_time).total_seconds() <= 130:
            state = next(iter(states))
            # Re-evaluate measurement freshness at admission, not just collection time.
            from sealed_telemetry.four_stage_health import classify

            current = {
                classify(record, now)
                for record in records
                if timestamp(record["event_time_utc"]) == latest_time
            }
            health[source] = (
                True
                if current == {"healthy"} and state == "healthy"
                else (False if state == "unhealthy" else None)
            )
    if any(value is not True for value in health.values()):
        blockers.add("SOURCE_HEALTH_UNHEALTHY_OR_UNKNOWN")
    if not events:
        blockers.add("NO_COMPLETE_IBER_EVIDENCE")
    ready = not blockers
    return {
        **result,
        "ready": ready,
        "blockers": sorted(blockers),
        "submitted_count": len(events) if ready else 0,
        "source_health_snapshot": health,
        "decisions": reconcile(events, now, {s: value is True for s, value in health.items()})
        if ready
        else [],
        "admission_manifest": manifest,
        "health_scope": "independently observed runtime availability; not delivery completeness",
        "application_execution_proven": False,
    }
