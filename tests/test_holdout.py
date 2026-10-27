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
