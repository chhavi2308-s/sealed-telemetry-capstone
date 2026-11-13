"""Pure IBER rules: labels and scenario ground truth are deliberately absent."""

import math
from bisect import bisect_left, bisect_right
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from sealed_telemetry.graph_matching import competing_graph_diagnostics
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


MatchKey = tuple[str, str, str, str]


def _match_key(event: Evidence) -> MatchKey:
    """Fields that must be exactly equal before an authoritative match can succeed."""
    return (
        event.credential_fingerprint,
        event.operation,
        event.resource_pseudonym,
        event.actor_pseudonym,
    )


def exhaustive_candidates(
    expected: list[Evidence], observed: Evidence, policy: Policy
) -> list[Evidence]:
    """Original exhaustive candidate generator retained as the reference fallback."""
    return [candidate for candidate in expected if matches(candidate, observed, policy)]


class ExpectedActionIndex:
    """Temporal index that narrows expected-action candidates without deciding matches.

    Each bucket is keyed only by fields which `matches()` requires to be identical.
    It is time-sorted so range selection honours the same inclusive clock-skew
    boundary. The original predicate remains the final authority, including IDs.
    """

    def __init__(self, expected: list[Evidence]) -> None:
        self.expected = tuple(expected)
        buckets: dict[MatchKey, list[tuple[float, int, Evidence]]] = defaultdict(list)
        for position, event in enumerate(expected):
            buckets[_match_key(event)].append(
                (timestamp(event.event_time_utc).timestamp(), position, event)
            )
        self._buckets: dict[
            MatchKey, tuple[tuple[float, ...], tuple[tuple[int, Evidence], ...]]
        ] = {}
        for key, values in buckets.items():
            values.sort(key=lambda value: (value[0], value[1]))
            self._buckets[key] = (
                tuple(value[0] for value in values),
                tuple((value[1], value[2]) for value in values),
            )

    def candidates(self, observed: Evidence, policy: Policy) -> list[Evidence]:
        bucket = self._buckets.get(_match_key(observed))
        if bucket is None:
            return []
        times, entries = bucket
        observed_at = timestamp(observed.event_time_utc).timestamp()
        bound = policy.matching_window + policy.clock_skew
        start = bisect_left(times, observed_at - bound)
        end = bisect_right(times, observed_at + bound)
        # Restore input order so the index is a drop-in replacement for the old loop.
        plausible = sorted(entries[start:end], key=lambda value: value[0])
        return [event for _, event in plausible if matches(event, observed, policy)]

    def exhaustive_candidates(self, observed: Evidence, policy: Policy) -> list[Evidence]:
        """Reference fallback for callers/tests requiring the original full scan."""
        return exhaustive_candidates(list(self.expected), observed, policy)


def reconcile(
    events: list[Evidence],
    now: str,
    health: dict[str, bool],
    policy: Policy = DEFAULT_POLICY,
    *,
    candidate_mode: str = "indexed",
    graph_diagnostics: bool = True,
) -> list[dict[str, Any]]:
    """One case per provider observation or unmatched trusted expectation.

    A trusted expectation is consumable once. Duplicate provider actions with the
    same action ID cannot borrow the same authorization. Ambiguous candidates
    remain inconclusive. Worst case O(n²); batch sizes must be bounded by callers.
    """
    if candidate_mode not in {"indexed", "exhaustive"}:
        raise ValueError("candidate mode must be indexed or exhaustive")
    if not isinstance(graph_diagnostics, bool):
        raise ValueError("graph diagnostics flag must be boolean")
    expected = [e for e in events if e.event_type == "EXPECTED_ACTION"]
    observed = [e for e in events if e.event_type == "PROVIDER_ACTION"]
    intents = [e for e in events if e.event_type == "INTENT_CREATED"]
    results = []
    candidates: dict[str, list[Evidence]] = {}
    if observed and candidate_mode == "indexed":
        index = ExpectedActionIndex(expected)
        for obs in observed:
            candidates[obs.event_id] = index.candidates(obs, policy)
    elif observed:
        for obs in observed:
            candidates[obs.event_id] = exhaustive_candidates(expected, obs, policy)
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
    candidate_ids = {
        observation_id: [event.event_id for event in group]
        for observation_id, group in candidates.items()
    }
    seen_expectations: set[str] = set()
    competing = False
    for candidate_id_group in candidate_ids.values():
        if len(candidate_id_group) > 1 or any(
            event_id in seen_expectations for event_id in candidate_id_group
        ):
            competing = True
            break
        seen_expectations.update(candidate_id_group)
    if competing and graph_diagnostics:
        # This bounded Hopcroft--Karp pass is diagnostic-only.  Its edges were
        # already admitted by the selected candidate generator and `matches()`.
        # It neither assigns an observation nor promotes a credential/action
        # relation into proof of application execution; decisions stay intact.
        competing_graph_diagnostics(candidate_ids)
    uses = {e.event_id: 0 for e in expected}
    for group in candidates.values():
        for expectation in group:
            uses[expectation.event_id] += 1
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
                "correlated_evidence_refs": sorted(
                    {e.source_id + ":" + e.event_id for e in evidence}
                ),
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
