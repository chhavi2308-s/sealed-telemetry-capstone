"""Controlled response: explicit approval and subsequent provider enforcement proof."""

from typing import Any

from sealed_telemetry.provider import Provider


def contain(
    provider: Provider,
    token: str,
    now: str,
    run_id: str,
    scenario_id: str,
    approved: bool = False,
    inject_failure: bool = False,
) -> dict[str, Any]:
    if not approved:
        return {"status": "approval_required", "verified_at": None}
    try:
        provider.revoke(token, fail=inject_failure)
        result = provider.call(token, now, run_id, scenario_id)
    except TimeoutError:
        return {"status": "unverified", "verified_at": None, "reason": "provider_timeout"}
    verified = result["status"] == 403
    return {
        "status": "verified" if verified else "failed",
        "verified_at": now if verified else None,
        "verification_request_id": result["provider_request_id"],
    }
