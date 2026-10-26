"""Pure IBER rules: labels and scenario ground truth are deliberately absent."""

import math
from dataclasses import dataclass
from typing import Any

from sealed_telemetry.schema import Evidence, timestamp


@dataclass(frozen=True)
class Policy:
    provider_deadline: float = 15
    gateway_deadline: float = 15
    app_deadline: float = 10
    matching_window: float = 60
    clock_skew: float = 30

    def __post_init__(self) -> None:
        for value in (
            self.provider_deadline,
            self.gateway_deadline,
            self.app_deadline,
            self.matching_window,
            self.clock_skew,
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError("numeric reconciliation parameters required")
            if not math.isfinite(value) or value < 0:
                raise ValueError("finite non-negative reconciliation parameters required")


DEFAULT_POLICY = Policy()


def reconcile(
    events: list[Evidence], now: str, health: dict[str, bool], policy: Policy = DEFAULT_POLICY
) -> list[dict[str, Any]]:
    """One case per provider observation or unmatched trusted expectation.

    A trusted expectation is consumable once. Duplicate provider actions with the
    same action ID cannot borrow the same authorization. Ambiguous candidates
    remain inconclusive. Worst case O(n²); batch sizes must be bounded by callers.
    """
    expected = [e for e in events if e.event_type == "EXPECTED_ACTION"]
    observed = [e for e in events if e.event_type == "PROVIDER_ACTION"]
    intents = [e for e in events if e.event_type == "INTENT_CREATED"]
    results = []
    candidates: dict[str, list[Evidence]] = {}
    for obs in observed:
        candidates[obs.event_id] = [exp for exp in expected if matches(exp, obs, policy)]
    # Reserve exact invocation/action bindings before attempting lower confidence fallback.
    # An external replay cannot consume an expectation already used by its legitimate call.
    exact_owners: dict[str, set[str]] = {}
    for obs in observed:
        for exp in candidates[obs.event_id]:
            if obs.action_id == exp.action_id and obs.invocation_id == exp.invocation_id:
                exact_owners.setdefault(exp.event_id, set()).add(obs.event_id)
    for obs in observed:
        candidates[obs.event_id] = [
            exp
            for exp in candidates[obs.event_id]
            if exp.event_id not in exact_owners or obs.event_id in exact_owners[exp.event_id]
        ]
    uses = {e.event_id: sum(e in group for group in candidates.values()) for e in expected}
    covered: set[str] = set()

    def decide(
        anchor: Evidence,
        state: str,
        reason: str,
        evidence: list[Evidence],
        missing: list[str],
        confidence: str,
    ) -> None:
        results.append(
            {
                "case_id": anchor.run_id + ":" + anchor.event_id,
                "finding_id": anchor.run_id + ":" + anchor.event_id,
                "residual_uncertainty": (
                    "Evidence does not establish theft mechanism or attacker identity"
                ),
                "run_id": anchor.run_id,
                "credential_fingerprint": anchor.credential_fingerprint,
                "affected_identity": anchor.actor_pseudonym,
                "state": state,
                "reason_codes": [reason],
                "rule_version": "iber-1",
                "decided_at": now,
                "first_observed_at": anchor.event_time_utc,
                "correlated_event_ids": sorted({e.event_id for e in evidence}),
                "missing_expected_sources": missing,
                "source_health_snapshot": health,
                "confidence_category": confidence,
                "response_policy": "approval_required",
                "response_status": "not_requested",
                "reconstruction_status": "partial",
            }
        )

    for obs in observed:
        group = candidates[obs.event_id]
        covered.update(e.event_id for e in group)
        elapsed = (timestamp(now) - timestamp(obs.event_time_utc)).total_seconds()
        if elapsed < -policy.clock_skew:
            decide(obs, "INCONCLUSIVE", "CLOCK_SKEW", [obs], [], "low")
        elif obs.outcome != "success":
            decide(obs, "CONSISTENT", "PROVIDER_DENIED_NO_SUCCESS_CLAIM", [obs], [], "medium")
        elif not health.get("provider", False) or not health.get("gateway", False):
            decide(obs, "INCONCLUSIVE", "SOURCE_UNHEALTHY_OR_UNKNOWN", [obs, *group], [], "low")
        elif any(
            rev.source_id == "responder"
            and rev.event_type == "RESPONSE_ACTION"
            and rev.operation == "token:revoke:verify"
            and rev.outcome == "success"
            and rev.credential_fingerprint == obs.credential_fingerprint
            and (timestamp(obs.event_time_utc) - timestamp(rev.event_time_utc)).total_seconds()
            > policy.clock_skew
            for rev in events
        ):
            revocations = [
                rev
                for rev in events
                if rev.source_id == "responder"
                and rev.event_type == "RESPONSE_ACTION"
                and rev.outcome == "success"
                and rev.operation == "token:revoke:verify"
                and rev.credential_fingerprint == obs.credential_fingerprint
                and timestamp(rev.event_time_utc) < timestamp(obs.event_time_utc)
            ]
            decide(
                obs,
                "CORROBORATED_SUSPECTED_ABUSE",
                "SUCCESS_AFTER_VERIFIED_REVOCATION",
                [obs, *revocations],
                [],
                "high",
            )
        elif len(group) > 1 or (group and uses[group[0].event_id] > 1):
            decide(
                obs, "INCONCLUSIVE", "AMBIGUOUS_OR_REUSED_AUTHORIZATION", [obs, *group], [], "low"
            )
        elif not group:
            if elapsed < policy.gateway_deadline + policy.clock_skew:
                decide(obs, "PENDING", "WAITING_FOR_EXPECTATION", [obs], ["gateway"], "low")
            else:
                decide(obs, "SUSPICIOUS", "UNMATCHED_PROVIDER_ACTION", [obs], ["gateway"], "medium")
        else:
            exp = group[0]
            claims = [i for i in intents if matches(exp, i, policy)]
            if not claims:
                state = "PENDING" if elapsed < policy.app_deadline else "INCONCLUSIVE"
                decide(obs, state, "APPLICATION_TELEMETRY_GAP", [exp, obs], ["app"], "medium")
            else:
                exact = bool(
                    exp.action_id
                    and obs.action_id == exp.action_id
                    and exp.invocation_id == obs.invocation_id
                )
                decide(
                    obs,
                    "CONSISTENT" if exact else "INCONCLUSIVE",
                    "MATCHED_EXPECTATION" if exact else "BOUNDED_FALLBACK_ONLY",
                    [exp, obs, *claims],
                    [],
                    "high" if exact else "low",
                )
    for exp in expected:
        if exp.event_id not in covered:
            elapsed = (timestamp(now) - timestamp(exp.event_time_utc)).total_seconds()
            pending = elapsed < policy.provider_deadline + policy.clock_skew
            decide(
                exp,
                "PENDING" if pending else "INCONCLUSIVE",
                "WAITING_FOR_PROVIDER" if pending else "PROVIDER_EVIDENCE_GAP",
                [exp],
                ["provider"],
                "low",
            )
    return results


def matches(expected: Evidence, observed: Evidence, policy: Policy) -> bool:
    if (
        expected.credential_fingerprint,
        expected.operation,
        expected.resource_pseudonym,
        expected.actor_pseudonym,
    ) != (
        observed.credential_fingerprint,
        observed.operation,
        observed.resource_pseudonym,
        observed.actor_pseudonym,
    ):
        return False
    if (
        abs(
            (
                timestamp(expected.event_time_utc) - timestamp(observed.event_time_utc)
            ).total_seconds()
        )
        > policy.matching_window + policy.clock_skew
    ):
        return False
    for field in ("provider_request_id", "action_id", "invocation_id"):
        left, right = getattr(expected, field), getattr(observed, field)
        if left and right and left != right:
            return False
    return True
