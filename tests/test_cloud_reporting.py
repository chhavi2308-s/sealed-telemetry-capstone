import json
from unittest.mock import patch

from sealed_telemetry.cloud_reporting import handler


def test_private_report_endpoint_checks_identity_and_integrity(monkeypatch):
    event = {"body": json.dumps({"run_id": "run"})}
    with patch("sealed_telemetry.cloud_reporting.authorized", side_effect=ValueError):
        assert handler(event, None)["statusCode"] == 403
    monkeypatch.setenv("ARCHIVE_BUCKET", "archive")
    monkeypatch.setenv("EVENT_TABLE", "events")
    monkeypatch.setenv("DECISION_TABLE", "decisions")
    with (
        patch("sealed_telemetry.cloud_reporting.authorized"),
        patch("sealed_telemetry.cloud_reporting.boto3.resource"),
        patch("sealed_telemetry.cloud_reporting.boto3.client") as client,
        patch("sealed_telemetry.cloud_reporting.export", return_value={"integrity_valid": False}),
    ):
        assert handler(event, None)["statusCode"] == 409
        client.return_value.put_object.assert_not_called()
    with (
        patch("sealed_telemetry.cloud_reporting.authorized"),
        patch("sealed_telemetry.cloud_reporting.boto3.resource"),
        patch("sealed_telemetry.cloud_reporting.boto3.client") as client,
        patch(
            "sealed_telemetry.cloud_reporting.export",
            return_value={"integrity_valid": True, "timeline": []},
        ),
    ):
        client.return_value.put_object.return_value = {"VersionId": "version"}
        result = handler(event, None)
        assert result["statusCode"] == 201
        assert json.loads(result["body"])["version_id"] == "version"
        assert client.return_value.put_object.call_args.kwargs["IfNoneMatch"] == "*"
