from sealed_telemetry.evaluation import experiment, metrics


def test_metrics_denominators():
    data = [
        dict(attack=True, prediction=True, pending=False, inconclusive=False),
        dict(attack=False, prediction=True, pending=False, inconclusive=False),
        dict(attack=True, prediction=False, pending=True, inconclusive=False),
        dict(attack=False, prediction=False, pending=False, inconclusive=True),
    ]
    result = metrics(data)
    assert result["precision"] == result["recall"] == result["f1"] == 0.5
    assert result["false_positive_rate"] == 0.5
    assert result["alert_count"] == 2
    assert result["alert_coverage"] == 0.5
    assert result["pending_count"] == result["inconclusive_count"] == 1
    assert result["pending_rate"] == result["inconclusive_rate"] == 0.25
    assert result["uncertainty_count"] == 2
    assert result["uncertainty_rate"] == 0.5
    assert metrics([])["precision"] is None


def test_experiment_outputs(tmp_path):
    summary = experiment(tmp_path / "experiment", 2026, 1)
    assert len(summary["metrics"]) == 8
    assert summary["metrics"]["iber"]["n"] == 16
    assert summary["aws_cost"] is None
    assert summary["mode"] == "local_smoke"
