import json
from unittest.mock import MagicMock, patch

from sealed_telemetry.cloud_health import monitor


def test_independent_health_outbox_lag_and_queue_failure(monkeypatch):
    for name, value in {
        "MONITORED_FUNCTIONS": json.dumps({"provider": ["saas"]}),
        "DLQ_URL": "dlq",
        "AUDIT_FAILURE_URL": "audit-dlq",
        "QUEUE_NAME": "intake",
        "OUTBOX_TABLE": "outbox",
        "INTAKE_URL": "https://synthetic.example",
    }.items():
        monkeypatch.setenv(name, value)
    client = MagicMock()
    client.get_function_configuration.return_value = {"State": "Active"}
    client.get_queue_attributes.return_value = {"Attributes": {"ApproximateNumberOfMessages": "0"}}
    client.get_metric_statistics.return_value = {"Datapoints": []}
    resource = MagicMock()
    resource.Table.return_value.query.return_value = {
        "Items": [{"created_at": "2026-10-26T09:00:00+00:00"}]
    }
    with (
        patch("sealed_telemetry.cloud_health.boto3.client", return_value=client),
        patch("sealed_telemetry.cloud_health.boto3.resource", return_value=resource),
        patch("sealed_telemetry.cloud_health.utcnow", return_value="2026-10-26T10:00:00+00:00"),
        patch("sealed_telemetry.cloud_health.emit") as emit,
    ):
        result = monitor({}, None)
        assert result["provider"] == "unhealthy"
        assert emit.call_count == 4
        client.get_metric_statistics.return_value = {"Datapoints": [{"Maximum": 180}]}
        assert monitor({}, None)["collector"] == "unhealthy"
