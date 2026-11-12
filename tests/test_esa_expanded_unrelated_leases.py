from scripts.esa_expanded_unrelated_leases import HEALTH, case_events
from sealed_telemetry.reconciliation import reconcile

NOW = "2026-11-12T00:02:00+00:00"


def states(events, mode):
    return [
        (decision["state"], decision["reason_codes"][0])
        for decision in reconcile(events, NOW, HEALTH, candidate_mode=mode)
    ]


def test_unrelated_valid_leases_do_not_authorize_external_provider_action():
    events = case_events("unrelated_lease_unmatched_provider", 8201, 0)
    indexed = states(events, "indexed")
    exhaustive = states(events, "exhaustive")
    assert indexed == exhaustive
    assert ("SUSPICIOUS", "UNMATCHED_PROVIDER_ACTION") in indexed
    assert all(state != "CONSISTENT" for state, _ in indexed), (
        "unrelated lease must not authorize the external provider action"
    )


def test_unrelated_valid_lease_control_remains_benign():
    events = case_events("unrelated_lease_benign_control", 8201, 0)
    indexed = states(events, "indexed")
    assert indexed == states(events, "exhaustive")
    assert indexed == [
        ("CONSISTENT", "MATCHED_EXPECTATION"),
        ("CONSISTENT", "MATCHED_EXPECTATION"),
    ]
