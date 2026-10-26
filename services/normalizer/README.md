# normalizer

Entrypoint: `sealed_telemetry.aws_handlers.normalizer` in src/sealed_telemetry.

Contract: SQS envelopes; output partial batch failures; versioned S3 archive and conditional DynamoDB indexes.

Environment variables and exact permissions are defined in `infra/template.yaml` under the corresponding Function and `NormalizerRole` resources; do not copy credentials into environment files.

Deployment: approved `sam build` and reviewed change set from repository root; see docs/runbook.md. Local verification: `pytest -q` from the root (Moto for AWS calls, no deployed-account claims).

Expected logs: sanitized event or message IDs and service failures; no bearer values. Check Lambda errors, queue age, outbox pending index, failure queues and source-health freshness when troubleshooting.

Cleanup/rollback: docs/runbook.md and scripts/cleanup.py; retained evidence and KMS keys need separate owner authorization.
