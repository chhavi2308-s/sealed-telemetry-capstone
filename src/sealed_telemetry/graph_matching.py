"""Deterministic, diagnostic-only matching over already-authoritative candidates.

This module never creates candidate edges.  Callers must build those edges with
the authoritative reconciliation predicate first.  A maximum matching is useful
for explaining the shape of a competing component, but is not evidence that an
application execution identity was proven and must not resolve IBER ambiguity.
"""

from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

MAX_DIAGNOSTIC_VERTICES = 10_000
MAX_DIAGNOSTIC_EDGES = 100_000


@dataclass(frozen=True)
class CandidateComponent:
    """One connected, competing observation-to-expectation component."""

    observation_ids: tuple[str, ...]
    expectation_ids: tuple[str, ...]
    edge_count: int
    maximum_matching_size: int | None


@dataclass(frozen=True)
class GraphDiagnostics:
    """Bounded graph facts only; no assignment is exposed as a reconciliation result."""

    components: tuple[CandidateComponent, ...]
    capacity_exceeded: bool = False


def _normalized_edges(edges: Mapping[str, Sequence[str]]) -> dict[str, tuple[str, ...]]:
    """Canonicalize input so traversal and matching do not depend on input order."""
    return {
        observation_id: tuple(sorted(set(expectation_ids)))
        for observation_id, expectation_ids in sorted(edges.items())
        if expectation_ids
    }


def _maximum_matching(edges: Mapping[str, Sequence[str]]) -> int:
    """Return a deterministic Hopcroft--Karp maximum-cardinality matching size."""
    normalized = _normalized_edges(edges)
    observations = tuple(normalized)
    matched_observation: dict[str, str | None] = {node: None for node in observations}
    matched_expectation: dict[str, str | None] = {
        node: None for targets in normalized.values() for node in targets
    }

    def breadth_first() -> tuple[dict[str, int], bool]:
        distances: dict[str, int] = {}
        queue: deque[str] = deque()
        for observation_id in observations:
            if matched_observation[observation_id] is None:
                distances[observation_id] = 0
                queue.append(observation_id)
        reached_free_expectation = False
        while queue:
            observation_id = queue.popleft()
            for expectation_id in normalized[observation_id]:
                owner = matched_expectation[expectation_id]
                if owner is None:
                    reached_free_expectation = True
                elif owner not in distances:
                    distances[owner] = distances[observation_id] + 1
                    queue.append(owner)
        return distances, reached_free_expectation

    def depth_first(observation_id: str, distances: dict[str, int]) -> bool:
        for expectation_id in normalized[observation_id]:
            owner = matched_expectation[expectation_id]
            if owner is None or (
                owner in distances
                and distances[owner] == distances[observation_id] + 1
                and depth_first(owner, distances)
            ):
                matched_observation[observation_id] = expectation_id
                matched_expectation[expectation_id] = observation_id
                return True
        distances.pop(observation_id, None)
        return False

    cardinality = 0
    while True:
        distances, reached_free_expectation = breadth_first()
        if not reached_free_expectation:
            return cardinality
        for observation_id in observations:
            if matched_observation[observation_id] is None and depth_first(
                observation_id, distances
            ):
                cardinality += 1


def competing_graph_diagnostics(edges: Mapping[str, Sequence[str]]) -> GraphDiagnostics:
    """Analyze only components with actual competition, subject to fixed bounds.

    A component competes when an observation has alternatives or an expectation
    has more than one possible observation.  Isolated one-edge components are
    intentionally omitted: the ordinary reconciliation path already handles them.
    """
    normalized = _normalized_edges(edges)
    reverse: dict[str, set[str]] = {}
    for observation_id, expectation_ids in normalized.items():
        for expectation_id in expectation_ids:
            reverse.setdefault(expectation_id, set()).add(observation_id)
    visited_observations: set[str] = set()
    components: list[CandidateComponent] = []
    vertices = 0
    edge_count = 0
    for initial in normalized:
        if initial in visited_observations:
            continue
        observations: set[str] = set()
        expectations: set[str] = set()
        queue: deque[tuple[bool, str]] = deque([(True, initial)])
        while queue:
            is_observation, node = queue.popleft()
            if is_observation:
                if node in observations:
                    continue
                observations.add(node)
                visited_observations.add(node)
                queue.extend((False, target) for target in normalized[node])
            else:
                if node in expectations:
                    continue
                expectations.add(node)
                queue.extend((True, owner) for owner in reverse[node])
        if len(observations) == len(expectations) == 1:
            continue
        component_edges = {
            observation_id: tuple(
                target for target in normalized[observation_id] if target in expectations
            )
            for observation_id in sorted(observations)
        }
        component_edge_count = sum(len(targets) for targets in component_edges.values())
        vertices += len(observations) + len(expectations)
        edge_count += component_edge_count
        if vertices > MAX_DIAGNOSTIC_VERTICES or edge_count > MAX_DIAGNOSTIC_EDGES:
            return GraphDiagnostics(tuple(components), capacity_exceeded=True)
        components.append(
            CandidateComponent(
                observation_ids=tuple(sorted(observations)),
                expectation_ids=tuple(sorted(expectations)),
                edge_count=component_edge_count,
                maximum_matching_size=_maximum_matching(component_edges),
            )
        )
    return GraphDiagnostics(tuple(components))
