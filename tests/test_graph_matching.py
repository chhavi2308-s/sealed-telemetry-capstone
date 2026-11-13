"""Reference and security tests for diagnostic-only graph matching."""

from dataclasses import replace
from random import Random
from typing import Any

import pytest

from sealed_telemetry.graph_matching import (
    MAX_DIAGNOSTIC_EDGES,
    CandidateComponent,
    competing_graph_diagnostics,
)
from sealed_telemetry.reconciliation import (
    ExpectedActionIndex,
    Policy,
    exhaustive_candidates,
    reconcile,
)
from sealed_telemetry.schema import Evidence


def brute_force_size(edges: dict[str, list[str]]) -> int:
    """Small exhaustive reference independent of Hopcroft--Karp."""
    observations = sorted(edges)

    def visit(position: int, used: set[str]) -> int:
        if position == len(observations):
            return 0
        observation_id = observations[position]
        return max(
            [visit(position + 1, used)]
            + [
                1 + visit(position + 1, used | {expectation_id})
                for expectation_id in edges[observation_id]
                if expectation_id not in used
            ]
        )

    return visit(0, set())


def test_hopcroft_karp_matches_bruteforce_reference_for_seeded_small_graphs() -> None:
    rng = Random(20261113)  # noqa: S311 - deterministic test corpus, not a secret
    for _ in range(120):
        edges = {
            f"o{observation}": [
                f"e{expectation}" for expectation in range(4) if rng.random() < 0.45
            ]
            for observation in range(4)
        }
        diagnostic = competing_graph_diagnostics(edges)
        for component in diagnostic.components:
            component_edges = {
                observation_id: [
                    expectation_id
                    for expectation_id in edges[observation_id]
                    if expectation_id in component.expectation_ids
                ]
                for observation_id in component.observation_ids
            }
            assert component.maximum_matching_size == brute_force_size(component_edges)


def test_component_diagnostics_are_deterministic_and_skip_non_competing_edges() -> None:
    edges = {"o2": ["e2", "e1"], "o1": ["e1"], "single": ["alone"]}
    baseline = competing_graph_diagnostics(edges)
    assert baseline == competing_graph_diagnostics(
        {key: list(value) for key, value in reversed(list(edges.items()))}
    )
    assert baseline.components == (CandidateComponent(("o1", "o2"), ("e1", "e2"), 3, 2),)


def test_diagnostic_capacity_stops_without_producing_an_assignment() -> None:
    edges = {"o": [f"e{index}" for index in range(MAX_DIAGNOSTIC_EDGES + 1)]}
    diagnostic = competing_graph_diagnostics(edges)
    assert diagnostic.capacity_exceeded
    assert diagnostic.components == ()


def test_dense_component_is_deterministic_and_has_full_capacity() -> None:
    edges = {
        f"observation-{index}": [f"expectation-{target}" for target in range(8)]
        for index in range(8)
    }
    expected = competing_graph_diagnostics(edges)
    assert expected.components[0].maximum_matching_size == 8
    for _ in range(20):
        assert competing_graph_diagnostics(dict(reversed(list(edges.items())))) == expected


def event(event_id: str, source: str, event_type: str, **changes: Any) -> Evidence:
    raw: dict[str, Any] = {
        "event_id": event_id,
        "run_id": "graph-run",
        "scenario_id": "graph",
        "source_id": source,
        "event_type": event_type,
        "event_time_utc": "2026-11-13T10:00:00+00:00",
        "actor_pseudonym": "actor",
        "credential_fingerprint": "a" * 64,
        "operation": "files:upload",
        "resource_pseudonym": "file",
        "invocation_id": "invoke",
        "action_id": "action",
        "provider_request_id": None,
    }
    raw.update(changes)
    return Evidence(**raw)


def test_graph_diagnostics_do_not_assign_ambiguous_or_replayed_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = event("expected", "gateway", "EXPECTED_ACTION")
    alternative = replace(expected, event_id="alternative")
    intent = replace(expected, event_id="intent", source_id="app", event_type="INTENT_CREATED")
    observed = replace(
        expected,
        event_id="provider",
        source_id="provider",
        event_type="PROVIDER_ACTION",
        provider_request_id="provider-request",
    )
    captured = []

    def observe(edges: dict[str, list[str]]) -> object:
        captured.append(edges)
        return competing_graph_diagnostics(edges)

    monkeypatch.setattr("sealed_telemetry.reconciliation.competing_graph_diagnostics", observe)
    findings = reconcile(
        [expected, alternative, intent, observed],
        "2026-11-13T10:00:30+00:00",
        {"gateway": True, "provider": True, "app": True},
    )
    assert captured == [{"provider": ["expected", "alternative"]}]
    assert findings[0]["state"] == "INCONCLUSIVE"
    assert findings[0]["reason_codes"] == ["AMBIGUOUS_OR_REUSED_AUTHORIZATION"]


def test_reconciliation_skips_graph_diagnostics_without_competing_candidates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = event("expected", "gateway", "EXPECTED_ACTION")
    intent = replace(expected, event_id="intent", source_id="app", event_type="INTENT_CREATED")
    observed = replace(
        expected,
        event_id="provider",
        source_id="provider",
        event_type="PROVIDER_ACTION",
        provider_request_id="provider-request",
    )

    def fail_if_called(_: dict[str, list[str]]) -> object:
        raise AssertionError("non-competing candidates must not run graph diagnostics")

    monkeypatch.setattr(
        "sealed_telemetry.reconciliation.competing_graph_diagnostics", fail_if_called
    )
    assert (
        reconcile(
            [expected, intent, observed],
            "2026-11-13T10:00:30+00:00",
            {"gateway": True, "provider": True, "app": True},
        )[0]["state"]
        == "CONSISTENT"
    )


def test_indexed_and_exhaustive_findings_remain_equivalent_with_graph_diagnostics() -> None:
    expected = event("expected", "gateway", "EXPECTED_ACTION")
    intent = replace(expected, event_id="intent", source_id="app", event_type="INTENT_CREATED")
    observed = replace(
        expected,
        event_id="provider",
        source_id="provider",
        event_type="PROVIDER_ACTION",
        provider_request_id="provider-request",
    )
    replay = replace(observed, event_id="replay", provider_request_id="replay-request")
    events = [expected, intent, observed, replay]
    health = {"gateway": True, "provider": True, "app": True}
    now = "2026-11-13T10:00:30+00:00"
    assert reconcile(events, now, health, candidate_mode="indexed") == reconcile(
        events, now, health, candidate_mode="exhaustive"
    )


def test_diagnostics_switch_preserves_candidate_sets_and_all_finding_states() -> None:
    health = {"gateway": True, "provider": True, "app": True}
    now = "2026-11-13T10:00:30+00:00"
    expected = event("expected", "gateway", "EXPECTED_ACTION")
    intent = replace(expected, event_id="intent", source_id="app", event_type="INTENT_CREATED")
    consistent = replace(
        expected,
        event_id="consistent",
        source_id="provider",
        event_type="PROVIDER_ACTION",
        provider_request_id="consistent-request",
    )
    pending = replace(
        consistent,
        event_id="pending",
        provider_request_id="pending-request",
        action_id=None,
        invocation_id=None,
        event_time_utc="2026-11-13T10:00:25+00:00",
    )
    suspicious = replace(
        pending,
        event_id="suspicious",
        provider_request_id="suspicious-request",
        event_time_utc="2026-11-13T09:00:00+00:00",
    )
    ambiguous = replace(expected, event_id="ambiguous")
    corroborating = event(
        "revocation",
        "responder",
        "RESPONSE_ACTION",
        operation="token:revoke:verify",
        invocation_id=None,
        action_id=None,
        event_time_utc="2026-11-13T09:58:00+00:00",
    )
    corroborated = replace(
        pending,
        event_id="corroborated",
        provider_request_id="corroborated-request",
        event_time_utc="2026-11-13T10:00:00+00:00",
    )
    cases = [
        ([expected, intent, consistent], "CONSISTENT"),
        ([pending], "PENDING"),
        ([suspicious], "SUSPICIOUS"),
        ([expected, ambiguous, intent, consistent], "INCONCLUSIVE"),
        ([corroborating, corroborated], "CORROBORATED_SUSPECTED_ABUSE"),
    ]
    for events, state in cases:
        indexed = reconcile(events, now, health, graph_diagnostics=True)
        disabled = reconcile(events, now, health, graph_diagnostics=False)
        exhaustive = reconcile(
            events,
            now,
            health,
            candidate_mode="exhaustive",
            graph_diagnostics=True,
        )
        assert indexed == disabled == exhaustive
        assert state in {row["state"] for row in indexed}
        expectations = [row for row in events if row.event_type == "EXPECTED_ACTION"]
        observations = [row for row in events if row.event_type == "PROVIDER_ACTION"]
        index = ExpectedActionIndex(expectations)
        for observation in observations:
            assert [row.event_id for row in index.candidates(observation, Policy())] == [
                row.event_id for row in exhaustive_candidates(expectations, observation, Policy())
            ]
