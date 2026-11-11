"""Safety and graph-theory checks for the opt-in IBER matching diagnostic."""

from dataclasses import replace
from uuid import uuid4

import pytest

from sealed_telemetry.graph_matching import (
    _maximum_matching,
    analyze_iber_matching,
    reconcile_with_matching_analysis,
)
from sealed_telemetry.reconciliation import reconcile
from sealed_telemetry.schema import new_event

NOW = "2026-10-26T10:00:00+00:00"
LATER = "2026-10-26T10:02:00+00:00"
HEALTH = {"gateway": True, "provider": True, "app": True}


def make(source: str, kind: str, **changes):
    fields = dict(
        run_id="graph-demo",
        scenario_id="neutral",
        event_time_utc=NOW,
        actor_pseudonym="actor",
        credential_fingerprint="a" * 64,
        operation="read",
        resource_pseudonym="file_a",
        action_id="act",
        invocation_id="inv",
    )
    fields.update(changes)
    return new_event(source, kind, **fields)


def test_hopcroft_karp_finds_global_assignment_not_first_fit():
    # E1 -> L1,L2; E2 -> L1 only: maximum matching must cover both.
    adjacency = {"e1": ("l1", "l2"), "e2": ("l1",)}
    assert _maximum_matching(adjacency) == {"e1": "l2", "e2": "l1"}


def test_matching_does_not_upgrade_iber_uncertain_verdict():
    lease1 = make("gateway", "EXPECTED_ACTION", action_id="a1", invocation_id="i1")
    lease2 = make("gateway", "EXPECTED_ACTION", action_id="a2", invocation_id="i2")
    # No binding IDs: both are fallback candidates, and a maximum matching exists.
    p1 = make("provider", "PROVIDER_ACTION", action_id=None, invocation_id=None,
              provider_request_id="req1")
    p2 = make("provider", "PROVIDER_ACTION", action_id=None, invocation_id=None,
              provider_request_id="req2")
    records = [lease1, lease2, p1, p2]
    findings, analysis = reconcile_with_matching_analysis(records, LATER, HEALTH)
    assert findings == reconcile(records, LATER, HEALTH)
    assert analysis.maximum_matching_size == 2
    assert analysis.all_provider_events_covered
    assert analysis.alternative_maximum_exists is True
    assert not analysis.forced_assignments
    assert {f["state"] for f in findings} == {"INCONCLUSIVE"}


def test_forced_global_assignment_is_still_not_proof_of_authorization():
    lease_a = make("gateway", "EXPECTED_ACTION", action_id="a1", invocation_id="i1",
                   event_time_utc=NOW)
    lease_b = make("gateway", "EXPECTED_ACTION", action_id="a2", invocation_id="i2",
                   event_time_utc="2026-10-26T10:00:40+00:00")
    # Both are in a 90s time window, but E2 is incompatible with lease_a via action_id.
    event1 = make("provider", "PROVIDER_ACTION", action_id=None, invocation_id=None,
                  provider_request_id="req1")
    event2 = make("provider", "PROVIDER_ACTION", action_id="a2", invocation_id=None,
                  provider_request_id="req2")
    analysis = analyze_iber_matching([lease_a, lease_b, event1, event2])
    assert analysis.all_provider_events_covered
    assert analysis.alternative_maximum_exists is False
    assert len(analysis.forced_assignments or ()) == 2
    states = [f["state"] for f in reconcile([lease_a, lease_b, event1, event2], LATER, HEALTH)]
    assert states == ["INCONCLUSIVE", "INCONCLUSIVE"]


def test_exact_binding_prevents_fallback_replay_consuming_lease():
    lease = make("gateway", "EXPECTED_ACTION")
    exact = make("provider", "PROVIDER_ACTION", provider_request_id="exact")
    replay = make("provider", "PROVIDER_ACTION", action_id=None, invocation_id=None,
                  provider_request_id="replay")
    analysis = analyze_iber_matching([lease, exact, replay])
    assert analysis.candidate_edge_count == 1
    assert analysis.maximum_matching_size == 1
    assert analysis.assignments == ((exact.event_id, lease.event_id),)
    assert analysis.unmatched_provider_ids == (replay.event_id,)


def test_denied_operations_are_excluded():
    lease = make("gateway", "EXPECTED_ACTION")
    denied = make("provider", "PROVIDER_ACTION", provider_request_id="denied", outcome="denied")
    assert analyze_iber_matching([lease, denied]).provider_count == 0


def test_identifiers_and_input_order_are_stable():
    lease = make("gateway", "EXPECTED_ACTION")
    observed = make("provider", "PROVIDER_ACTION", provider_request_id="p")
    a = analyze_iber_matching([lease, observed])
    b = analyze_iber_matching([observed, lease])
    assert a == b
    assert a.assignments == ((observed.event_id, lease.event_id),)
    assert a.forced_assignments == a.assignments


def test_conflicting_ids_are_not_eligible():
    lease = make("gateway", "EXPECTED_ACTION", action_id="a1")
    obs = make("provider", "PROVIDER_ACTION", provider_request_id="req",
               action_id="other")
    analysis = analyze_iber_matching([lease, obs])
    assert analysis.candidate_edge_count == 0
    assert analysis.unmatched_provider_ids == (obs.event_id,)


def test_duplicate_ids_fail_explicitly():
    lease = make("gateway", "EXPECTED_ACTION")
    obs = make("provider", "PROVIDER_ACTION", provider_request_id="req")
    with pytest.raises(ValueError, match="distinct"):
        analyze_iber_matching([lease, replace(obs, event_id=lease.event_id)])


def test_node_capacity_fails_closed():
    lease = make("gateway", "EXPECTED_ACTION")
    events = [replace(lease, event_id=str(uuid4())) for _ in range(801)]
    with pytest.raises(ValueError, match="capacity"):
        analyze_iber_matching(events)
