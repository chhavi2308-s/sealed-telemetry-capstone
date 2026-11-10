"""Readiness and provenance gates around the existing, unchanged IBER algorithm."""

import json
from typing import Any

from sealed_telemetry.four_stage_collection import Configuration
from sealed_telemetry.reconciliation import reconcile
from sealed_telemetry.schema import Evidence, timestamp


def _gateway_reference(
    gateway: dict[str, Any], receipt: dict[str, Any], ref: dict[str, Any]
) -> bool:
    from sealed_telemetry.four_stage_evidence import epoch

    return bool(
        ref["table_arn"] == receipt["resource_arn"]
        and ref["native_id"] == gateway["action_id"]
        and ref["canonical_hash"] == gateway["authorization_hash"]
        and ref["revision"] == gateway["authorization_revision"]
        and ref["authorized_at_utc"] == epoch(gateway["authorized_at"])
        and ref["authorization_expires_at_utc"] == epoch(gateway["authorization_expires_at"])
    )


def prepare(
    config: Configuration, control: dict[str, Any], rows: list[dict[str, Any]], now: str
) -> dict[str, Any]:
    """Complete canonical records may enter IBER; partial C2 records never borrow fields.

    A scan and source availability are not global completeness attestations. Results
    always describe only this observed ledger view, with immutable prior assessments.
    """
    if any(source.contract == "c4" for source in config.sources):
        from sealed_telemetry.four_stage_c4_iber import prepare as prepare_c4

        return prepare_c4(config, control, rows, now)
    blockers: set[str] = set()
    markers = json.loads(control["collections"])
    for source in config.sources:
        marker = markers.get(source.table_arn)
        if not marker or not marker["ok"]:
            blockers.add("SOURCE_COLLECTION_INCOMPLETE")
        elif (
            not 0 <= (timestamp(now) - timestamp(marker["attempted_at_utc"])).total_seconds() <= 130
        ):
            blockers.add("SOURCE_COLLECTION_STALE")
    if any(row["status"] != "accepted" for row in rows):
        blockers.add("QUARANTINED_EVIDENCE")
    accepted = [(row, json.loads(row["body"])) for row in rows if row["status"] == "accepted"]
    gateways = {
        (env["receipt"]["resource_arn"], env["receipt"]["native_id"]): env
        for _, env in accepted
        if env["normalized"]["kind"] == "gateway"
    }
    issuers = {
        env["receipt"]["native_id"]: env
        for _, env in accepted
        if env["normalized"]["kind"] == "issuer"
    }
    counts: dict[tuple[str, str], int] = {}
    for env in issuers.values():
        ref = env["normalized"]["data"]["authorization_reference"]
        key = (ref["table_arn"], ref["native_id"])
        counts[key] = counts.get(key, 0) + 1
    if any(count > 1 for count in counts.values()):
        blockers.add("AMBIGUOUS_ISSUANCE_BINDING")
    issuer_checks: dict[str, str] = {}
    for identity, env in issuers.items():
        data = env["normalized"]["data"]
        ref, att = data["authorization_reference"], data["attestation"]
        gateway = gateways.get((ref["table_arn"], ref["native_id"]))
        status = "WAITING_FOR_GATEWAY"
        if gateway:
            raw = gateway["normalized"]["data"]
            valid = _gateway_reference(raw, gateway["receipt"], ref) and all(
                att[name] == raw[name]
                for name in ("action_id", "actor_pseudonym", "resource_pseudonym", "operation")
            )
            status = "REFERENCE_CONSISTENT" if valid else "GATEWAY_REFERENCE_MISMATCH"
        issuer_checks[identity] = status
        if status != "REFERENCE_CONSISTENT":
            blockers.add(status)
    bindings = []
    canonical_events = []
    health: dict[str, bool | None] = {
        source: None for source in ("gateway", "provider", "app", "collector")
    }
    observations: dict[str, list[dict[str, Any]]] = {source: [] for source in health}
    for row, env in accepted:
        record = env["normalized"]
        data, kind = record.get("canonical_evidence", record["data"]), record["kind"]
        if kind == "health":
            if record["contract"] == "aws-events-1":
                blockers.add("ARCHIVE_HEALTH_OBSERVATION_BASIS_UNKNOWN")
                continue
            observations[data["health_for_source"]].append(data)
            continue
        if kind == "canonical":
            canonical_events.append(Evidence.parse(data, record["source_id"]))
            continue
        missing = ["run_id", "scenario_id"]
        status = "SUPPORTING_RECORD_ONLY"
        if kind == "gateway":
            missing.append("invocation_id")
            candidates = [
                env
                for env in issuers.values()
                if env["normalized"]["data"]["authorization_reference"]["table_arn"]
                == row["resource_arn"]
                and env["normalized"]["data"]["attestation"]["action_id"] == data["action_id"]
            ]
            if not candidates:
                missing.append("credential_fingerprint")
                status = "WAITING_FOR_ISSUANCE"
            elif len(candidates) != 1:
                status = "AMBIGUOUS_ISSUANCE_BINDING"
            else:
                identity = candidates[0]["normalized"]["data"]["issuance_id"]
                status = issuer_checks[identity]
        elif kind == "issuer":
            missing = []
            status = issuer_checks[data["issuance_id"]]
        elif kind == "provider":
            status = "UNBOUND_CREDENTIAL"
            if data["credential_fingerprint"] is None:
                missing.extend(["credential_fingerprint", "actor_pseudonym", "resource_pseudonym"])
            else:
                issuer = issuers.get(data["issuance_id"])
                status = "WAITING_FOR_ISSUANCE"
                if issuer:
                    issued = issuer["normalized"]["data"]
                    att = issued["attestation"]
                    pairs = {
                        "credential_fingerprint": "credential_fingerprint",
                        "fingerprint_key_version": "fingerprint_key_version",
                        "fingerprint_algorithm": "fingerprint_algorithm",
                        "issuance_id": "issuance_id",
                        "authorized_action_id": "action_id",
                        "actor_pseudonym": "actor_pseudonym",
                        "authorized_resource_pseudonym": "resource_pseudonym",
                        "credential_issued_at_utc": "issued_at_utc",
                        "credential_expires_at_utc": "expires_at_utc",
                    }
                    consistent = (
                        all(data[left] == att[right] for left, right in pairs.items())
                        and data["authorization_reference"] == issued["authorization_reference"]
                        and issuer_checks[data["issuance_id"]] == "REFERENCE_CONSISTENT"
                    )
                    status = (
                        "BINDING_CONSISTENT" if consistent else "ISSUER_PROVIDER_BINDING_MISMATCH"
                    )
                if status != "BINDING_CONSISTENT":
                    blockers.add(status)
            if data["operation"] is None:
                missing.append("operation")
            if data["resource_pseudonym"] is None and "resource_pseudonym" not in missing:
                missing.append("resource_pseudonym")
        if kind != "issuer":
            blockers.add("INCOMPLETE_C2_EVIDENCE")
        bindings.append(
            {
                "record_id": row["record_id"],
                "source_id": record["source_id"],
                "status": status,
                "missing_iber_fields": missing,
                "invocation_id": None,
                "event_time_utc": record["event_time_utc"],
            }
        )
    for health_source, entries in observations.items():
        if not entries:
            continue
        latest_time = max(timestamp(entry["event_time_utc"]) for entry in entries)
        states = {
            entry["source_health"]
            for entry in entries
            if timestamp(entry["event_time_utc"]) == latest_time
        }
        age = (timestamp(now) - latest_time).total_seconds()
        if len(states) == 1 and 0 <= age <= 130:
            state = next(iter(states))
            health[health_source] = (
                True if state == "healthy" else False if state == "unhealthy" else None
            )
    if any(value is not True for value in health.values()):
        blockers.add("SOURCE_HEALTH_UNHEALTHY_OR_UNKNOWN")
    if not canonical_events:
        blockers.add("NO_COMPLETE_IBER_EVIDENCE")
    expected_credentials = {
        event.credential_fingerprint for event in canonical_events if event.source_id == "gateway"
    }
    if any(
        event.source_id == "provider" and event.credential_fingerprint not in expected_credentials
        for event in canonical_events
    ):
        blockers.add("PROVIDER_ONLY_COVERAGE_NOT_ESTABLISHED")
    if len({event.event_id for event in canonical_events}) != len(canonical_events):
        blockers.add("AMBIGUOUS_EVENT_ID")
    ready = not blockers
    decisions = (
        reconcile(canonical_events, now, {key: value is True for key, value in health.items()})
        if ready
        else []
    )
    return {
        "assessed_at_utc": now,
        "snapshot_revision": int(control["revision"]),
        "ready": ready,
        "submitted_count": len(canonical_events) if ready else 0,
        "coverage_complete": False,
        "coverage_scope": "observed ledger only",
        "blockers": sorted(blockers),
        "bindings": bindings,
        "source_health_snapshot": health,
        "decisions": decisions,
        "application_execution_proven": False,
        "notice": (
            "Source consistency and IBER findings do not establish physical application "
            "execution or global coverage."
        ),
    }
