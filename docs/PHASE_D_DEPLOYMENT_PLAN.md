# Phase D AWS deployment plan — approval required, not applied

Target supplied by the project owner: account `011237053677`, region `ap-south-1`.
This plan is based on repository code/templates, not a live resource inventory.
Existing deployed stack names, physical resource IDs, role IDs, boundaries and secret
ARNs must be read and verified after approval; placeholders below are not invented
deployed resources. Nothing in this document authorizes deployment or IAM changes.

## Approval packages and scope

1. Read-only live inventory and drift review: deployed function versions/configuration,
   API IAM authorization, native table ARNs/schemas, archive versioning, queue routes,
   writer identities, boundaries, encryption and retention. No credentials enter
   reports. The local teammate-dev profile is not assumed accessible to ChatGPT.
2. Review a separate infrastructure/IAM change set with resolved ARNs, generated and
   reviewed policies, cost estimate, rollback package, retention settings and owners.
3. Only after explicit approval: provision/configure, deploy immutable versions and
   run independent live acceptance. No main merge is required for this plan.

## Resource changes to propose

Preserve the existing API Gateway and four-stage authorization/application/issuer/
mock SaaS functions. Keep private handlers private; only IAM-protected authorization
has an HTTP integration. Keep existing external role permissions boundaries intact.

| Logical resource / configuration | Required change |
| --- | --- |
| Existing ExpectedActions / OAuthTokens / SaasAudit | Keep native keys action_id / token_hash / provider_request_id. Enable C2 only after verifying its already-required permissions/config. Never expose OAuthTokens to collector or monitor. |
| C2 IssuanceEvidence | If not deployed, add HASH issuance_id (S), on-demand capacity, retention/encryption and issuer-only writes. Confirm C2 atomic write/condition-check support before enabling it. |
| C4 GatewayContext | New HASH record_id (S), immutable gateway-only conditional writes. |
| C4 ApplicationContext | New HASH record_id (S), immutable app-only conditional writes. |
| C4 ProviderContext | New HASH provider_request_id (S), provider-only conditional claims/context writes. Retain claims through token/context replay windows. |
| C4 IndependentHealth | New HASH event_id (S), monitor-only conditional writes; no producer/app writes. |
| C4 EvidenceState | New HASH record_id (S), collector-only reads/conditional writes/transactions. Do not reuse the old C3 policy-bound ledger. No TTL on current quarantine/control/history without an approved archival design. |
| Dedicated context signing secret | Secrets Manager JSON keyring; independently generated >=32-byte versioned keys, isolated from C2 identity/fingerprint keys; no values in templates or Lambda logs. |
| C4 collector Lambda | Handler sealed_telemetry.four_stage_collection.handler, exact C3_COLLECTION_CONFIG, private invocations only; bounded scans and explicit collection/reconcile operations. |
| Independent monitor Lambda | Handler sealed_telemetry.four_stage_health.handler, empty event, exact C4_HEALTH_FUNCTIONS and health table. Separate execution role. Proposed one-minute schedule, disabled until approved. |
| Logs, schedule, alarms | Pre-created bounded-retention logs; schedule invoke permission scoped to monitor; failures/denials/lag/quarantine/capacity alarms. No sensitive wire/debug logging. |
| Legacy archive compatibility | Separate policy-bound archive ledger using exact Events table and source-role mapping. Preserve S3 bucket versioning and first-receipt semantics; standalone S3/SQS mappings are not deployed ingestion paths. |

Use AWS-managed encryption by default or a separately approved customer-managed key;
make the encryption choice explicit. Existing SSEEnabled=false does not establish
that customer-managed protection is configured. Set retain-on-replacement/delete for
evidence and state; do not add automatic cleanup that would remove evidence of conflicts.

## Least-privilege permission changes to review

The following is an API/resource inventory, **not an applied or generated IAM policy**.
Resolve each logical table/secret/function to an exact ARN in account/region above.
No producer may write another source's context table or collector state. Retain
existing boundaries and update their ceilings only through separate explicit approval.

| Principal | Required access and exact resource scope |
| --- | --- |
| Authorization | Existing PutItem on ExpectedActions and InvokeFunction on the app; add PutItem on GatewayContext. Retain GetSecretValue on the exact identity secret required by C2. |
| Application | GetItem on ExpectedActions, GatewayContext and IssuanceEvidence; PutItem on ApplicationContext; InvokeFunction only on issuer/provider; GetSecretValue only on the dedicated context secret. No private registry reads. |
| Issuer | GetItem/ConditionCheckItem on ExpectedActions; GetItem/PutItem on IssuanceEvidence (claim and envelope); PutItem on OAuthTokens; exact identity/fingerprint secret GetSecretValue. DynamoDB transactions use the underlying item action permissions, not a fabricated dynamodb:TransactWriteItems IAM action. |
| Mock provider | Existing GetItem on OAuthTokens and PutItem on SaasAudit; add GetItem on ApplicationContext and SaasAudit, PutItem on ProviderContext, GetSecretValue on dedicated context secret. No registry writes. |
| C4 collector | DescribeTable and Scan on exact seven configured source tables; DescribeTable, Scan, GetItem, PutItem and ConditionCheckItem on its EvidenceState. iam:GetRole only on its own configured role ARN (and configured legacy source roles in separate archive mode). STS GetCallerIdentity authenticates the session; do not grant broad role assumption or private token/secret access. |
| Independent monitor | lambda:GetFunctionConfiguration only on exact gateway/app/provider/collector ARNs; cloudwatch:GetMetricStatistics (the API needs wildcard resource scope; constrain region/role and no write metrics permissions); dynamodb:PutItem only on IndependentHealth. No reads of bearer registry or signing secrets. |
| Legacy archive collector | DescribeTable/Scan on exact Events table, its separate state access as above, iam:GetRole for configured source roles. Optional exact-version S3 reader: s3:GetObjectVersion only on approved evidence prefixes, expected owner check, and KMS decrypt only if the bucket key requires it. No List/Put/Delete or Get-latest fallback for that reader. |
| Logs / scheduler | CreateLogStream and PutLogEvents only for each pre-created function log group. Scheduler role may InvokeFunction only on monitor; add source-bound invocation trust/permission as needed. |
| Deployment operator | Separately reviewed change-set/deployment actions and iam:PassRole only for exact Lambda/scheduler roles with passed-to-service constraints; never grant this to runtime roles. |

For customer-managed KMS encryption, add only required decrypt/data-key operations
and service/resource conditions after reviewing the concrete key policies. Review
queue policies, collector API source roles and bucket/table writer isolation as well
as identity policies. There is no approved wildcard privilege expansion.

Generate a reproducible policy baseline from source before creating the IAM change
set. The SDK/IAM skill recommends IAM Policy Autopilot; it was unavailable here
(uvx absent; isolated package install attempts could not resolve packages). Proposed
command, to be executed by the coding agent in an approved network-enabled workspace:

    uvx iam-policy-autopilot@latest generate-policies <absolute-repo>/src/sealed_telemetry/four_stage.py <absolute-repo>/src/sealed_telemetry/four_stage_binding.py <absolute-repo>/src/sealed_telemetry/four_stage_context.py <absolute-repo>/src/sealed_telemetry/four_stage_health.py <absolute-repo>/src/sealed_telemetry/four_stage_collection.py --region ap-south-1 --account 011237053677 --service-hints dynamodb lambda secretsmanager sts iam cloudwatch --pretty

Review per-handler reachability, resource-variable resolution, condition expressions,
shared helpers, transaction actions and role boundaries against the inventory above.
Do not attach the generated baseline without review or use its upload option.

## Configuration and rollout order

1. Freeze intake and record existing code/version/configuration/alias/boundary hashes.
   Read actual deployed state rather than assuming the latest template is deployed.
2. Provision approved retained tables, secret keyring, isolated roles/log groups,
   collector and monitor disabled schedules. Resolve all ARNs and validate ownership.
3. Validate C2 producer mode and secrets first; preserve its atomic gateway check,
   credential registry, issuance claim and redacted evidence transaction.
4. Deploy C4-capable code without enabling context. Set per-function table/secret
   variables from the permission matrix. For gateway/app/provider set
   FOUR_STAGE_CONTEXT_MODE=c4 only together with FOUR_STAGE_EVIDENCE_MODE=c2 and only
   when all C4 dependencies are ready. Issuer retains the existing C2 handler contract.
5. Configure C3_COLLECTION_CONFIG with exact collector role/state/source ARNs and
   health_functions; no source selection or clock override from request bodies.
   Use a separate config/state for archive_roles and aws-events-1 mode.
6. Configure independent C4_HEALTH_FUNCTIONS with exact unqualified function ARNs;
   monitor env also C4_HEALTH_TABLE. Enable the approved schedule after code/permissions
   are verified. Empty/idle metrics remain unknown, even after deployment.
7. Resume narrowly scoped synthetic intake, collect/reconcile bounded batches and
   review readiness/blockers. Never switch the existing response/containment system on.

Source-state hash includes configuration. A rollback to a different source policy
must use its compatible retained state; never overwrite a policy hash to reuse a ledger.

## Rollback and failure handling

Quiesce API intake, disable monitor/collector schedules and freeze invocations before
rolling versions/configuration back to the recorded C2 baseline. Preserve all source,
claim, quarantine, state and archive history. Snapshot reviewed configuration/assessment
references; do not export secrets. Restore aliases/config only after compatibility
review. Do not reissue credentials or replay an indeterminate provider operation.
Keep signing key verification versions through outstanding lifetimes before rotation.
Rollback cannot undo an already recorded synthetic provider operation; preserve that fact.
No destructive table, role, boundary or key cleanup is included in rollback.

## Cost controls

Propose on-demand DynamoDB for this low-volume capstone, Lambda reserved concurrency
of one for collector/monitor and low caps for existing functions, existing API throttles,
bounded collection (max 1,000 records/20 pages) and short approved log retention. No VPC,
NAT gateway, provisioned concurrency, tracing payload capture or broad archive scans.
Separate state ledgers and retained history grow over time: estimate storage/transaction/
consistent-scan usage before approval and stop at capacity bounds, not partial admission.
For the proposed bounded capstone acceptance run, time-box schedules to at most 30
minutes and disable them afterward. Continuous operation is blocked pending an indexed
window/checkpoint design that preserves historical deduplication/quarantine: append-only
health records and ledger history will eventually exceed the current scan bounds.

Proposed alerts: owner-approved monthly budget (for example USD 5 as a review proposal,
not a predicted bill or hard spending cap), budget thresholds and Lambda/DynamoDB error/
throttle alarms. Recheck current regional prices and actual traffic in the deployment
change set. Disable schedules and quiesce intake when not exercising the demo; an idle
source remains unknown rather than creating fake traffic for healthy status.

## Independent live acceptance criteria

Use an observer identity distinct from app/issuer/provider/collector writers. Record
resource ARNs, role IDs, code/configuration versions, native record IDs and original
timestamps without printing tokens, token IDs, lookup hashes, signatures or keys.

- Verify account/region, API AWS_IAM protection, private Lambda invoke policies,
  boundaries and denied cross-source table writes. Verify app cannot write provider,
  gateway, health or state evidence and cannot read private registry/fingerprint keys.
- Submit one authorized synthetic action. Independently inspect gateway API request ID,
  gateway Lambda ID, app Lambda ID, provider Lambda ID and provider audit request ID;
  show they retain distinct meanings and the admission manifest names all source records.
- Verify issuance atomicity/replay denial, app intent before provider call, provider
  bearer lookup, signed context validation, one-use claim and key-rotation overlap.
- Tamper/omit locator/signature/context, replay a signed request, deny intent/claim/
  audit/sidecar writes and simulate an indeterminate result. Assert no invented identity,
  no automatic action retry, and incomplete/orphan records block readiness.
- Exercise missing intent, delayed dispatch/issuer/provider evidence, duplicated receipts,
  actual extra provider operations, conflicting content and collection in separate batches.
  Verify stable deduplication, sticky quarantine, retained unmatched expectations and
  reassessment after late arrivals. Never erase history to obtain a green demo.
- Observe positive AWS error/throttle data, source access denial, missing/sparse/stale/
  future metrics and monitor failure. Each must remain unhealthy/unknown or absent;
  successful scans alone must not make a source healthy.
- Verify actual SQS trigger route, exact S3 version/owner, collector principal receipts,
  index/archive agreement, unsupported legacy fields and health-basis blockers. No
  standalone decoder output counts as authenticated live ingestion by itself.
- Only claim C4 admission after the real full source set passes. Keep coverage_complete
  false: runtime health and bounded scans do not prove delivery completeness or physical
  application execution. Do not claim end-to-end detection for unsupported archive or
  incomplete/unknown-credential scenarios.

## AWS references used during planning

- [Lambda context and aws_request_id](https://docs.aws.amazon.com/lambda/latest/dg/python-context.html)
- [Lambda invocation/error/throttle metrics](https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics-types.html)
- [DynamoDB transactions](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html)
- [DynamoDB transaction IAM actions](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis-iam.html)
- [CloudWatch IAM actions/resource scoping](https://docs.aws.amazon.com/service-authorization/latest/reference/list_cloudwatch.html)
- [S3 API permissions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-policy-actions.html)
- [IAM policy evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [AWS Budgets](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-managing-costs.html)
- [IAM Policy Autopilot](https://github.com/awslabs/iam-policy-autopilot)
