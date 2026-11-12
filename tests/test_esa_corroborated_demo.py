from scripts.esa_corroborated_demo import run


def test_corroborated_demo_uses_real_engine_and_preserves_mode_equivalence(tmp_path):
    result = run(tmp_path / "corroborated")
    assert result["indexed_exhaustive_equal"] is True
    assert result["findings"] == [
        {
            "state": "CORROBORATED_SUSPECTED_ABUSE",
            "reason_codes": ["SUCCESS_AFTER_VERIFIED_REVOCATION"],
            "correlated_event_ids": result["findings"][0]["correlated_event_ids"],
        }
    ]
