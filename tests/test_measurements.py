from sealed_telemetry.measurements import calibrate, percentile, reconstruction


def test_calibration_and_reconstruction():
    assert percentile([1, 2, 3, 4], 0.95) == 4
    assert calibrate({"provider": [1, 2, 3]}, margin=2)["provider"]["deadline_seconds"] == 5
    assert reconstruction(["a", "b"], ["a", "a"])["completeness"] == 0.5
    assert percentile([], 0.95) is None
