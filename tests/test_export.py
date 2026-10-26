import io
from unittest.mock import MagicMock

from test_core import event

from scripts.export_incident import export
from sealed_telemetry.schema import canonical, digest


def test_export_pins_archive_version_and_detects_tamper():
    raw = event().to_dict()
    receipt = {"canonical_hash": digest(raw)}
    envelope = {"raw": raw, "receipt": receipt}
    item = {
        "event_id": raw["event_id"],
        "canonical_hash": digest(raw),
        "archive_key": "evidence/event.json",
        "archive_version": "version-1",
    }
    events, decisions, s3 = MagicMock(), MagicMock(), MagicMock()
    events.query.return_value = {"Items": [item]}
    decisions.query.return_value = {"Items": []}
    s3.get_object.side_effect = lambda **kwargs: {"Body": io.BytesIO(canonical(envelope))}
    assert export("run", events, decisions, s3, "archive")["integrity_valid"]
    assert s3.get_object.call_args.kwargs["VersionId"] == "version-1"
    raw["operation"] = "modified"
    assert not export("run", events, decisions, s3, "archive")["integrity_valid"]
