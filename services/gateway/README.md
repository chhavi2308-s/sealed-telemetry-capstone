# gateway

Entrypoint: sealed_telemetry.cloud_lab.gateway.

Contract: IAM caller request -> independently registered expectation and internal app invocation.

Required environment names: `INTAKE_URL`, `ISSUER_FUNCTION`, `APP_FUNCTION`, `LAB_EXPOSURE_ENABLED`. Exact resource references and permissions: infra/template.yaml, GatewayFunction and GatewayRole/GatewayPolicy. Never put token values in logs.

Deploy only through the approved SAM change-set procedure in docs/runbook.md. Test locally with `pytest -q`; use the runbook for live smoke tests. Inspect Lambda errors, queue/source-health signals and stable event IDs on failure. Cleanup and rollback require the same account/retention checks as the stack runbook.
