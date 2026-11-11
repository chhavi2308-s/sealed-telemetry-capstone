"""Experimental bipartite matching diagnostics for IBER authorization evidence.

This module does NOT issue or modify security findings. A graph assignment is a
possible explanation for provider observations, not proof that a request was
legitimate or that a bearer token was not copied.
"""

from collections import deque
from dataclasses import dataclass
from typing import Any

from sealed_telemetry.reconciliation import DEFAULT_POLICY, Policy, matches, reconcile
from sealed_telemetry.schema import Evidence

# Fail explicitly on overly large research graphs rather than silently taking a prefix.
MAX_NODES = 800
MAX_EDGES = 40_000
MAX_UNIQUENESS_PAIRS = 48


@dataclass(frozen=True)
class GraphMatchingAnalysis:
    """A maximal possible one-to-one explanation, not an authorization verdict."""

    provider_count: int
    expectation_count: int
    candidate_edge_count: int
    maximum_matching_size: int
    assignments: tuple[tuple[str, str], ...]  # (provider event ID, lease event ID)
    unmatched_provider_ids: tuple[str, ...]
    competing_provider_ids: tuple[str, ...]
    forced_assignments: tuple[tuple[str, str], ...] | None
    alternative_maximum_exists: bool | None

    @property
    def all_provider_events_covered(self) -> bool:
        return self.provider_count == self.maximum_matching_size


def _maximum_matching(adjacency: dict[str, tuple[str, ...]]) -> dict[str, str]:
    """Hopcroft-Karp maximum cardinality matching, left provider IDs to lease IDs.

    O(E * sqrt(V)) for a bipartite graph. Inputs and neighbor order are sorted for
    reproducible diagnostics; an assignment is not necessarily unique.
    """
    left = sorted(adjacency)
    match_left: dict[str, str] = {}
    match_right: dict[str, str] = {}
    inf = len(left) + 1

    while True:
        distances: dict[str, int] = {}
        queue: deque[str] = deque()
        for provider_id in left:
            if provider_id not in match_left:
                distances[provider_id] = 0
                queue.append(provider_id)
            else:
                distances[provider_id] = inf
        shortest_path = inf
        while queue:
            provider_id = queue.popleft()
            if distances[provider_id] >= shortest_path:
                continue
            for lease_id in adjacency[provider_id]:
                owner = match_right.get(lease_id)
                if owner is None:
                    shortest_path = min(shortest_path, distances[provider_id] + 1)
                elif distances[owner] == inf:
                    distances[owner] = distances[provider_id] + 1
                    queue.append(owner)
        if shortest_path == inf:
            return match_left

        def augment(provider_id: str) -> bool:
            for lease_id in adjacency[provider_id]:
                owner = match_right.get(lease_id)
                if owner is None and distances[provider_id] + 1 == shortest_path:
                    match_left[provider_id] = lease_id
                    match_right[lease_id] = provider_id
                    return True
                if owner is not None and (
                    distances[owner] == distances[provider_id] + 1 and augment(owner)
                ):
                    match_left[provider_id] = lease_id
                    match_right[lease_id] = provider_id
                    return True
            distances[provider_id] = inf
            return False

        for provider_id in left:
            if provider_id not in match_left:
                augment(provider_id)


def analyze_iber_matching(
    events: list[Evidence],
    policy: Policy = DEFAULT_POLICY,
    *,
    check_uniqueness: bool = True,
) -> GraphMatchingAnalysis:
    """Build an evidence-compatible graph and analyze possible lease assignments.

    Only successful provider actions participate: a denied operation is not a
    successful unauthorized use. The underlying ``matches`` predicate retains
    token/actor/action/resource/time/identifier compatibility. Exact invocation
    and action bindings reserve leases before fallback edges, exactly as IBER-1.

    The graph models one possible provider use per expectation, not OAuth-side
    enforcement, physical-request identity, or user attribution. In particular,
    even a unique maximum matching cannot upgrade an INCONCLUSIVE IBER finding.
    """
    expectations = [e for e in events if e.event_type == "EXPECTED_ACTION"]
    providers = [
        e for e in events if e.event_type == "PROVIDER_ACTION" and e.outcome == "success"
    ]
    if len(expectations) + len(providers) > MAX_NODES:
        raise ValueError("graph matching capacity exceeded: nodes")
    if len({e.event_id for e in expectations + providers}) != len(expectations) + len(providers):
        raise ValueError("graph matching requires distinct provider/expectation event IDs")

    expectation_by_id = {e.event_id: e for e in expectations}
    candidate_ids: dict[str, list[str]] = {}
    exact_owners: dict[str, set[str]] = {}
    for provider in providers:
        matched = []
        for expectation in expectations:
            if matches(expectation, provider, policy):
                matched.append(expectation.event_id)
                if (
                    provider.action_id
                    and provider.invocation_id
                    and provider.action_id == expectation.action_id
                    and provider.invocation_id == expectation.invocation_id
                ):
                    exact_owners.setdefault(expectation.event_id, set()).add(
                        provider.event_id
                    )
        candidate_ids[provider.event_id] = matched

    adjacency: dict[str, tuple[str, ...]] = {}
    edge_count = 0
    incoming: dict[str, int] = {}
    for provider in providers:
        neighbors = tuple(
            sorted(
                lease_id
                for lease_id in candidate_ids[provider.event_id]
                if lease_id not in exact_owners
                or provider.event_id in exact_owners[lease_id]
            )
        )
        adjacency[provider.event_id] = neighbors
        edge_count += len(neighbors)
        if edge_count > MAX_EDGES:
            raise ValueError("graph matching capacity exceeded: edges")
        for lease_id in neighbors:
            incoming[lease_id] = incoming.get(lease_id, 0) + 1
    # This records possible competition, not mathematically proven ambiguity.
    competing = tuple(
        sorted(
            provider_id
            for provider_id, neighbors in adjacency.items()
            if len(neighbors) > 1 or any(incoming[lease_id] > 1 for lease_id in neighbors)
        )
    )
    matched = _maximum_matching(adjacency)
    assignments = tuple(sorted(matched.items()))
    unmatched = tuple(sorted(set(adjacency) - set(matched)))

    forced: tuple[tuple[str, str], ...] | None = None
    alternatives: bool | None = None
    if check_uniqueness and len(matched) <= MAX_UNIQUENESS_PAIRS:
        # An edge is forced if removing it reduces the maximum matching size.
        # Re-matching is intentionally capped: O(U * E * sqrt(V)) here.
        always_used = []
        alternatives = False
        for provider_id, lease_id in assignments:
            without_edge = dict(adjacency)
            without_edge[provider_id] = tuple(
                n for n in adjacency[provider_id] if n != lease_id
            )
            if len(_maximum_matching(without_edge)) < len(matched):
                always_used.append((provider_id, lease_id))
            else:
                alternatives = True
        forced = tuple(always_used)

    return GraphMatchingAnalysis(
        provider_count=len(providers),
        expectation_count=len(expectation_by_id),
        candidate_edge_count=edge_count,
        maximum_matching_size=len(matched),
        assignments=assignments,
        unmatched_provider_ids=unmatched,
        competing_provider_ids=competing,
        forced_assignments=forced,
        alternative_maximum_exists=alternatives,
    )


def reconcile_with_matching_analysis(
    events: list[Evidence],
    now: str,
    health: dict[str, bool],
    policy: Policy = DEFAULT_POLICY,
) -> tuple[list[dict[str, Any]], GraphMatchingAnalysis]:
    """Return unchanged IBER-1 findings plus separate research graph diagnostics."""
    findings = reconcile(events, now, health, policy)
    analysis = analyze_iber_matching(events, policy)
    return findings, analysis
