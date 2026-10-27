from unittest.mock import MagicMock, patch

import pytest

from sealed_telemetry.cloud_response import restore


@pytest.mark.parametrize(
    "old_reason,fresh_status,expected",
    [("revoked", 200, "verified"), ("expired", 200, "unverified"), ("revoked", 500, "unverified")],
)
def test_recovery_verifies_old_and_new_and_fails_closed(
    monkeypatch, old_reason, fresh_status, expected
):
    monkeypatch.setenv("ISSUER_FUNCTION", "issuer")
    monkeypatch.setenv("SAAS_URL", "https://synthetic.example/records")
    table = MagicMock()
    table.query.return_value = {"Items": [{"token_hash": "old-hash"}]}
    table.get_item.return_value = {"Item": {"revoked": True}}
    with (
        patch(
            "sealed_telemetry.cloud_response.invoke",
            return_value={"access_token": "fresh-disposable", "credential_fingerprint": "b" * 64},
        ),
        patch("sealed_telemetry.cloud_response.emit"),
        patch(
            "sealed_telemetry.cloud_response.https_json",
            side_effect=[
                {
                    "status": 403,
                    "body": {"reason": old_reason, "provider_request_id": "old-request"},
                },
                {"status": fresh_status, "body": {"provider_request_id": "fresh-request"}},
            ],
        ),
    ):
        result = restore(table, "old-disposable", "a" * 64, "records:read", {"run_id": "run"})
    assert result["status"] == expected
    assert "disposable" not in str(result)
    assert table.put_item.call_args.kwargs["Item"]["enabled"] is (expected == "verified")


def test_recovery_rejects_unrevoked_credential(monkeypatch):
    table = MagicMock()
    table.query.return_value = {"Items": [{"token_hash": "old-hash"}]}
    table.get_item.return_value = {"Item": {"revoked": False}}
    with pytest.raises(ValueError, match="previously revoked"):
        restore(table, "old-disposable", "a" * 64, "records:read", {"run_id": "run"})
    table.put_item.assert_not_called()
