from dataclasses import replace
from datetime import UTC, datetime, timedelta
from random import Random
from uuid import NAMESPACE_URL, uuid5

import pytest

from sealed_telemetry.reconciliation import (
    ExpectedActionIndex,
    Policy,
    exhaustive_candidates,
    reconcile,
)
from sealed_telemetry.schema import Evidence

BASE = datetime(2026, 11, 12, 10, 0, tzinfo=UTC)
HEALTH = {"gateway": True, "provider": True, "app": True}


def evidence(index: int, source: str, kind: str, seconds: float, **changes: str | None) -> Evidence:
    raw = {
        "event_id": str(uuid5(NAMESPACE_URL, f"esa-index:{source}:{kind}:{index}")),
        "run_id": "esa-run",
        "scenario_id": "esa",
        "source_id": source,
        "event_type": kind,
        "event_time_utc": (BASE + timedelta(seconds=seconds)).isoformat(),
        "actor_pseudonym": "actor-" + str(index % 5),
        "credential_fingerprint": f"{index % 7:064x}",
        "operation": "records:read" if index % 2 else "records:export",
        "resource_pseudonym": "resource-" + str(index % 3),
        "invocation_id": "invoke-" + str(index),
        "action_id": "action-" + str(index),
        "provider_request_id": "provider-" + str(index) if kind == "PROVIDER_ACTION" else None,
    }
    raw.update(changes)
    return Evidence(**raw)


def candidate_ids(values: list[Evidence]) -> list[str]:
    return [value.event_id for value in values]


def test_seeded_randomized_index_is_equivalent_to_exhaustive_candidates():
    rng = Random(20261112)  # noqa: S311 - deterministic equivalence corpus, not a secret
    expected = [
        evidence(i, "gateway", "EXPECTED_ACTION", rng.randint(-300, 300)) for i in range(240)
    ]
    observed = []
    for index in range(300, 520):
        peer = expected[rng.randrange(len(expected))]
        observation = evidence(
            index,
            "provider",
            "PROVIDER_ACTION",
            (datetime.fromisoformat(peer.event_time_utc) - BASE).total_seconds()
            + rng.uniform(-130, 130),
            actor_pseudonym=peer.actor_pseudonym if rng.random() < 0.7 else "other-actor",
            credential_fingerprint=peer.credential_fingerprint if rng.random() < 0.7 else "f" * 64,
            operation=peer.operation if rng.random() < 0.8 else "other-operation",
            resource_pseudonym=peer.resource_pseudonym if rng.random() < 0.8 else "other-resource",
            action_id=peer.action_id if rng.random() < 0.4 else "other-action",
            invocation_id=peer.invocation_id if rng.random() < 0.4 else "other-invocation",
        )
        observed.append(observation)
    policy = Policy(matching_window=60, clock_skew=30)
    index = ExpectedActionIndex(expected)
    for observation in observed:
        assert candidate_ids(index.candidates(observation, policy)) == candidate_ids(
            exhaustive_candidates(expected, observation, policy)
        )


def test_temporal_boundaries_are_inclusive_and_source_qualified():
    expected = evidence(1, "gateway", "EXPECTED_ACTION", 0)
    inside = replace(
        expected,
        event_id=str(uuid5(NAMESPACE_URL, "inside")),
        source_id="provider",
        event_type="PROVIDER_ACTION",
        provider_request_id="inside",
        event_time_utc=(BASE + timedelta(seconds=90)).isoformat(),
    )
    outside = replace(
        inside,
        event_id=str(uuid5(NAMESPACE_URL, "outside")),
        provider_request_id="outside",
        event_time_utc=(BASE + timedelta(seconds=90, microseconds=1)).isoformat(),
    )
    wrong_actor = replace(
        inside, event_id=str(uuid5(NAMESPACE_URL, "wrong-actor")), actor_pseudonym="other"
    )
    index = ExpectedActionIndex([expected])
    policy = Policy(matching_window=60, clock_skew=30)
    assert candidate_ids(index.candidates(inside, policy)) == [expected.event_id]
    assert index.candidates(outside, policy) == []
    assert index.candidates(wrong_actor, policy) == []


def test_conflicting_populated_identifiers_never_enter_candidate_set():
    expected = evidence(2, "gateway", "EXPECTED_ACTION", 0)
    conflicting = replace(
        expected,
        event_id=str(uuid5(NAMESPACE_URL, "conflict")),
        source_id="provider",
        event_type="PROVIDER_ACTION",
        provider_request_id="conflict",
        action_id="other-action",
    )
    assert ExpectedActionIndex([expected]).candidates(conflicting, Policy()) == []


def test_indexed_reconciliation_decisions_match_the_exhaustive_fallback():
    expected = evidence(20, "gateway", "EXPECTED_ACTION", 0)
    duplicate = replace(expected, event_id=str(uuid5(NAMESPACE_URL, "fallback-duplicate")))
    intent = replace(
        expected,
        event_id=str(uuid5(NAMESPACE_URL, "fallback-intent")),
        source_id="app",
        event_type="INTENT_CREATED",
    )
    observed = replace(
        expected,
        event_id=str(uuid5(NAMESPACE_URL, "fallback-observed")),
        source_id="provider",
        event_type="PROVIDER_ACTION",
        provider_request_id="fallback-provider",
    )
    external = replace(
        observed,
        event_id=str(uuid5(NAMESPACE_URL, "fallback-external")),
        provider_request_id="fallback-external-provider",
        action_id=None,
        invocation_id=None,
    )
    events = [expected, duplicate, intent, observed, external]
    now = (BASE + timedelta(seconds=50)).isoformat()
    indexed = reconcile(events, now, HEALTH, candidate_mode="indexed")
    exhaustive = reconcile(events, now, HEALTH, candidate_mode="exhaustive")
    assert indexed == exhaustive
    with pytest.raises(ValueError, match="candidate mode"):
        reconcile(events, now, HEALTH, candidate_mode="unsupported")


def test_ambiguity_retry_and_delayed_evidence_decisions_are_preserved():
    expected = evidence(3, "gateway", "EXPECTED_ACTION", 0)
    duplicate = replace(expected, event_id=str(uuid5(NAMESPACE_URL, "duplicate")))
    observed = replace(
        expected,
        event_id=str(uuid5(NAMESPACE_URL, "observed")),
        source_id="provider",
        event_type="PROVIDER_ACTION",
        provider_request_id="one",
    )
    intent = replace(
        expected,
        event_id=str(uuid5(NAMESPACE_URL, "intent")),
        source_id="app",
        event_type="INTENT_CREATED",
    )
    assert (
        reconcile(
            [expected, duplicate, observed, intent],
            (BASE + timedelta(seconds=50)).isoformat(),
            HEALTH,
        )[0]["state"]
        == "INCONCLUSIVE"
    )
    retry = replace(
        observed,
        event_id=str(uuid5(NAMESPACE_URL, "retry")),
        provider_request_id="two",
        invocation_id=None,
        action_id=None,
    )
    retry_decisions = reconcile(
        [expected, observed, retry, intent], (BASE + timedelta(seconds=50)).isoformat(), HEALTH
    )
    assert {row["state"] for row in retry_decisions} == {"CONSISTENT", "SUSPICIOUS"}
    assert any(row["reason_codes"] == ["UNMATCHED_PROVIDER_ACTION"] for row in retry_decisions)
    delayed = replace(
        observed,
        event_id=str(uuid5(NAMESPACE_URL, "delayed")),
        event_time_utc=(BASE + timedelta(seconds=200)).isoformat(),
    )
    decision = reconcile([expected, delayed], (BASE + timedelta(seconds=250)).isoformat(), HEALTH)[
        0
    ]
    assert decision["state"] == "SUSPICIOUS" and decision["reason_codes"] == [
        "UNMATCHED_PROVIDER_ACTION"
    ]
