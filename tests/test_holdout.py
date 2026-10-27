import json

from sealed_telemetry.holdout import run


def test_holdout_reproducible_and_labels_separate(tmp_path):
    one = run(tmp_path / "one", [1901], 1)
    two = run(tmp_path / "two", [1901], 1)
    assert one == two
    assert one["runs"] == 14
    inputs = json.loads((tmp_path / "one/detector-inputs.json").read_text())
    assert all("attack" not in r and "case" not in r for r in inputs)
    assert one["metrics"]["iber"]["fn"] == 1
    assert one["cloud_detection_latency"] is None


def test_scenario_disjoint_calibration_freezes_policy_without_attack_labels(tmp_path):
    from sealed_telemetry.schema import digest
    from sealed_telemetry.study import study

    result = study(tmp_path / "study", trials=1)
    protocol = json.loads((tmp_path / "study/study-protocol.json").read_text())
    assert not set(protocol["calibration_cases"]) & set(protocol["test_cases"])
    assert result["test"]["metrics"]["iber"]["fn"] >= 3
    frozen = json.loads((tmp_path / "study/frozen-policy.json").read_text())
    assert result["frozen_policy_sha256"] == digest(frozen)
    calibrated_inputs = (tmp_path / "study/test/detector-inputs.json").read_bytes()
    fixed_inputs = (tmp_path / "study/fixed-policy-test/detector-inputs.json").read_bytes()
    assert calibrated_inputs == fixed_inputs
