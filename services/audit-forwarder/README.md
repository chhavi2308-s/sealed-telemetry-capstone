# audit-forwarder

Entrypoint: sealed_telemetry.cloud_lab.audit_forwarder.

Contract: Provider DynamoDB INSERT -> authenticated intake; acknowledged delivery removes sparse pending marker.

Required environment names: `INTAKE_URL`, `OUTBOX_TABLE`. Exact resource references and permissions: infra/template.yaml, AuditForwarderFunction and AuditForwarderRole/AuditForwarderPolicy. Never put token values in logs.

Deploy only through the approved SAM change-set procedure in docs/runbook.md. Test locally with `pytest -q`; use the runbook for live smoke tests. Inspect Lambda errors, queue/source-health signals and stable event IDs on failure. Cleanup and rollback require the same account/retention checks as the stack runbook.
