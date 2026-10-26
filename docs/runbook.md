# Operator runbook

## Local reproduction

Use README commands in a fresh virtual environment. Test/demo output is synthetic. Do not reuse a demo directory. Normal, delayed-audit, duplicate, out-of-order and bulk scenarios should be consistent; replay-suppression suspicious with a separate inconclusive app-gap case; benign-log-failure inconclusive; bound-replay corroborated under the one-use policy; tampering fails integrity. `response-failure` must remain unverified. Token expiry, wrong scope/audience and successful/failed revocation are covered by tests.

## Deployment gate

No live deploy has been tested or authorized. Need an isolated account ID, region, temporary deployment role/SSO profile, Owner, expiry date, approved spending cap, budget name with notifications, and approval for governance retention and retained resources. Account-wide API Gateway logging role must already exist; this project will not change it automatically. Install AWS CLI and SAM CLI separately. Never paste access keys into files or chat.

```text
aws sso login --profile LAB
aws sts get-caller-identity --profile LAB
python scripts/preflight.py --account ACCOUNT --region REGION --budget-name NAME --max-budget-usd CAP --output preflight.json
sam build --template-file infra/template.yaml
sam validate --template-file infra/template.yaml --lint
sam deploy --stack-name sealed-telemetry-lab --region REGION --capabilities CAPABILITY_IAM --resolve-s3 --no-execute-changeset --parameter-overrides Owner=OWNER ExpiresOn=YYYY-MM-DD LabExposureEnabled=false --tags Project=SealedTelemetry Environment=Lab Owner=OWNER ExpiresOn=YYYY-MM-DD
```

Set AWS_PROFILE and AWS_DEFAULT_REGION in the shell; preflight uses the SDK credential chain. Values above are operator-supplied, not defaults to copy verbatim. Build/validation is local. `sam deploy` stages resources and requires cloud-spending authorization even with no-execute-changeset. Review the generated change set, IAM resources, resource count, retained S3/KMS/DynamoDB resources and costs before separately authorizing execution. Governance retention defaults to one day; bucket, keys, evidence, decisions, responses and provider outbox are retained. Do not enable compliance mode without a new ADR and approval.

`LabExposureEnabled=true` is only for the approved disposable Review-2 build. IAM callers invoke WorkloadUrl with SigV4 POST JSON. Body `{}` runs normal. Body `{"suppress_log":true,"expose_test_token":true}` returns the disposable test token only with exposure enabled. Use scripts/cloud_demo.py; it keeps the token in memory and writes sanitized observations. The mock SaaS uses HTTPS GET with Bearer auth and X-Run-Id; replay omits invocation/action headers.

## Live acceptance before declaring Review-2 complete

Record stack ARN, account, region, commit, AWS request IDs and deployed resource list. Verify healthy Lambda and queue alarms. Use an investigator principal to query EvidenceTable RunIndex for the demo run and DecisionTable for its cases, retrieve archived objects by archive_version, and recompute canonical hashes. Wait for the asynchronous outbox and one-minute detector schedule; do not promise instant results. Confirm normal, suppressed replay and benign logging failure. Then use the actual app role to attempt archive put/delete, index changes and provider evidence forgery; expect denial. Moto and static checks do not establish these denials. Capture deployment screenshots and video only after this succeeds.

## Queue/outbox recovery

If queue age or DLQ alarm fires, inspect consumer error metrics and message IDs, never dump payloads into shared logs. Resolve IAM/schema/KMS faults first. Retry legitimate events with their original event IDs; changed payload under the same ID is rejected. S3-first persistence means an archive-only object after an index outage is repaired on redelivery. Start DLQ redrive only after explicit operator approval; do not purge. Provider stream exhaustion enters AuditFailureQueue with stream metadata; recover raw records from ProviderOutbox using event IDs and resend original body as the audit-forwarder role. Pending: a fully automated operator redrive command and rehearsed stream-expiry recovery.

## Containment and recovery

EventBridge starts a Step Functions workflow that ends at ApprovalRequired by default. This is alert-only, not containment success or a human callback UI. Operator reviews evidence, health, scope and uncertainty, then starts a new execution with the sanitized finding, decision_id and `approved:true`. No bearer token is placed in workflow input/history. Responder decrypts only the relevant lab token under a separate KMS key, marks the registry revoked, calls the real mock SaaS endpoint and requires 403 before reporting verified. A timeout is retryable; failed verification is never successful. Response evidence is collected independently. Cached response results are idempotent by decision_id; an unverified cached result requires investigation/new authorized action rather than silent success.

Recovery: redeploy a reviewed known-good commit, disable exposure, invoke gateway to issue a fresh token and verify a new synthetic read succeeds. Verify the revoked old credential still fails. Local tests cover rotation old/new behavior; cloud clean-deployment recovery remains unverified. Synthetic resources are read-only, so no fabricated restore is reported. Disabling the entire integration is an unfinished containment action.

## Rollback and teardown

Rollback application code with `sam build` from the previously reviewed commit and a reviewed change set. Do not roll back evidence tables or reuse another environment's HMAC key. Keep saved evidence version manifests. CloudFormation rollback and partial-failure recovery must be rehearsed after approval.

Run `python scripts/cleanup.py --stack STACK --account ACCOUNT --region REGION --output cleanup-plan.json` for a read-only resource inventory. Deleting resources requires `--execute --approve-account ACCOUNT`; this command has NOT been run. It requests stack deletion but never deletes retained resources, bypasses retention, purges queues or schedules KMS deletion. Wait for stack completion and compare retained resources, staging buckets, logs, secrets recovery state and remaining charges. Only the owner can separately approve disposal of retained evidence/keys. Budget alerts do not cap AWS spend.
