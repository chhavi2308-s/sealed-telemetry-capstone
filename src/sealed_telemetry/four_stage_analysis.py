"""Small local demo analyzer; no SDK calls and no full IBER integration.

Inputs must be independently collected, sanitized records. Completeness and observation
watermarks are explicit caller assertions, not facts inferred from missing records.
"""

from typing import Any


def analyze(
    expected: list[dict[str, Any]],
    intents: list[dict[str, Any]],
    audits: list[dict[str, Any]],
    *,
    now: int,
    complete: bool = False,
    settle_seconds: int = 5,
) -> list[dict[str, Any]]:
    results = []
    by_id: dict[str, list[dict[str, Any]]] = {}
    for row in audits:
        by_id.setdefault(row["provider_request_id"], []).append(row)
    unique = [rows[0] for rows in by_id.values()]
    for audit in unique:
        reasons = []
        category = "AUTHORIZED"
        conflict = any(row != audit for row in by_id[audit["provider_request_id"]])
        candidates = [e for e in expected if e.get("action_id") == audit.get("action_id")]
        settled = complete and now >= audit["recorded_at"] + settle_seconds
        if conflict or len(candidates) > 1:
            category = "INCONCLUSIVE"
            reasons.append("CONFLICTING_EVIDENCE")
        elif not candidates:
            category = "UNAUTHORIZED_ACTION" if settled else "INCONCLUSIVE"
            reasons.append("NO_MATCHING_AUTHORIZATION" if settled else "AUTHORIZATION_NOT_OBSERVED")
        else:
            exp = candidates[0]
            matches = all(exp.get(k) == audit.get(k) for k in ("operation", "filename"))
            within = exp["authorized_at"] <= audit["recorded_at"] < exp["authorization_expires_at"]
            if not matches or not within:
                category = "UNAUTHORIZED_ACTION"
                reasons.append(
                    "RESOURCE_OR_OPERATION_MISMATCH" if not matches else "OUTSIDE_AUTHORIZATION"
                )
            elif audit.get("outcome") != "success":
                category = "INCONCLUSIVE"
                reasons.append("PROVIDER_DENIED_ATTEMPT")
            else:
                successes = [
                    a
                    for a in unique
                    if a.get("action_id") == exp["action_id"]
                    and a.get("outcome") == "success"
                    and all(a.get(k) == exp.get(k) for k in ("operation", "filename"))
                ]
                if len(successes) > 1:
                    category = "SUSPICIOUS_REPLAY"
                    reasons.extend(["MULTIPLE_PROVIDER_OPERATIONS", "RETRY_OR_REPLAY_UNRESOLVED"])
            matching_intents = [
                i
                for i in intents
                if i.get("event_type") == "APP_INTENT"
                and i.get("action_id") == exp["action_id"]
                and all(i.get(k) == exp.get(k) for k in ("operation", "filename"))
                and exp["authorized_at"]
                <= i.get("recorded_at", -1)
                < exp["authorization_expires_at"]
            ]
            if not matching_intents:
                reasons.append("APP_INTENT_MISSING" if settled else "APP_INTENT_NOT_YET_OBSERVED")
                if category == "AUTHORIZED":
                    category = "INCONCLUSIVE"
        if not settled and category == "AUTHORIZED":
            category = "INCONCLUSIVE"
            reasons.append("OBSERVATION_WINDOW_OPEN")
        results.append(
            {
                "category": category,
                "reason_codes": reasons or ["MATCHED_SINGLE_OPERATION"],
                "action_id": audit.get("action_id"),
                "provider_request_id": audit["provider_request_id"],
                "recorded_at": audit["recorded_at"],
                "analyzed_at": now,
                "intent_event_ids": [
                    i["event_id"]
                    for i in intents
                    if i.get("action_id") == audit.get("action_id") and "event_id" in i
                ],
                "uncertainty": "Does not establish token theft, attacker identity, or intent.",
            }
        )
    for exp in expected:
        if not any(a.get("action_id") == exp["action_id"] for a in unique):
            results.append(
                {
                    "category": "INCONCLUSIVE",
                    "reason_codes": ["PROVIDER_AUDIT_MISSING"],
                    "action_id": exp["action_id"],
                    "authorized_at": exp["authorized_at"],
                    "analyzed_at": now,
                }
            )
    return results
