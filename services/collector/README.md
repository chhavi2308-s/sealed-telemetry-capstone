# collector

Entrypoint: `sealed_telemetry.aws_handlers.collector` in src/sealed_telemetry.

Contract: SigV4 producer evidence; output 202 intake receipt after SQS durability.

Environment variables and exact permissions are defined in `infra/template.yaml` under the corresponding Function and `CollectorRole` resources; do not copy credentials into environment files.

Deployment: approved `sam build` and reviewed change set from repository root; see docs/runbook.md. Local verification: `pytest -q` from the root (Moto for AWS calls, no deployed-account claims).

Expected logs: sanitized event or message IDs and service failures; no bearer values. Check Lambda errors, queue age, outbox pending index, failure queues and source-health freshness when troubleshooting.

Cleanup/rollback: docs/runbook.md and scripts/cleanup.py; retained evidence and KMS keys need separate owner authorization.
