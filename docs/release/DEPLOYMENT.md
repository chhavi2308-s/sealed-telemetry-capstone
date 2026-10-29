# AWS release and approval runbook

27 October 2026. **No account or deployment region is confirmed. No AWS deployment has been executed.** The commands below are templates requiring owner-supplied values, not authorization to run them.

## Release inventory and ownership

`template-inventory.json`, `security-inventory.json` and `workload-inventory.json` contain every explicit and SAM-generated resource, condition, property and retention rule. Matching `*-permissions.json` files contain the expanded IAM/resource policies and Lambda invoke grants. Expansion uses SAM CLI 1.170.0 / translator 1.115.0 and substitutes an explicitly labelled artifact placeholder; these JSON inventories are not deployable templates.

The single-account profile contains 195 resources when supplementary feeds are enabled, including 18 functions, 19 roles, nine DynamoDB tables, ten queues, three customer-managed KMS keys, two retained buckets, four REST APIs with generated deployments/stages, 19 alarms, a dashboard and a response state machine. Conditional resources are identified individually. The final profile separates the application and its platform adapter from the security account. Regenerate inventories after any template change; use their counts rather than historical checkpoint totals.

Security owns OAuth/provider services, trusted gateway, intake, buffered evidence, detector, approval/response, reporting and central native CloudTrail storage. Workload owns the application, bounded permissions policy, observation role, platform adapter and optional selected native trail. Security must deploy first. Use distinct account IDs and stack names of at most 40 characters. Workload native trail delivery is restricted to its exact ARN and account prefix. App/platform claims remain compromisable; neither extensions nor CloudWatch messages are attestation.

Existing resources outside these inventories: temporary SSO/deployment roles, CloudFormation service roles, regional API Gateway logging role, artifact bucket(s), budgets/subscribers and any organization guardrails. They are owner prerequisites, not silently created by SAM.

## Required target information

Record both account IDs for the final profile, region, SSO profile names, deployment principal, CloudFormation service-role ARN, artifact bucket, Owner, ExpiresOn, budget name/cap, operator and investigator IAM-role ARNs, notification destination and retention acceptance. Never send access keys or session tokens in chat or files. Review ADR 001–003, including the JSON mock OAuth interface, REST APIs, per-record integrity receipts, read-only resources and credential/integration recovery scope.

Regional services: Lambda/Python 3.12, regional API Gateway REST, SQS, DynamoDB, S3, KMS, Secrets Manager, CloudWatch Logs/metrics/alarms/dashboard, EventBridge, Standard Step Functions, CloudTrail and SNS. IAM, STS, Budgets and Account Management are prerequisites. The workload preflight omits the unnecessary regional API Gateway logging-role requirement. Verify native trail availability/quotas in both accounts. Detector reserved concurrency is one; at least 101 currently unreserved units must be available under Lambda's reservation rule.

## Read-only preflight

Build locally first. Fill a copy of `preflight-permissions.example.json` with the confirmed account, region, service-role ARN and resource/context-specific checks. Include caller `iam:PassRole` for that exact service role and CloudFormation creation/update/change-set access. Include service-role checks for the expanded project resources. IAM simulation is not proof of SCPs, resource policies, KMS grants or service propagation; inspect the returned role trust policy and outstanding contexts manually.

```powershell
$env:AWS_PROFILE='CONFIRMED_SSO_PROFILE'
aws sso login --profile CONFIRMED_SSO_PROFILE
python scripts/preflight.py --deployment-profile lab --account ACCOUNT --region REGION --budget-name BUDGET --max-budget-usd CAP --artifact-bucket EXISTING_BUCKET --permission-plan approved-permissions.json --output preflight.json
```

The command performs identity, temporary-credential, enabled-region, regional-service, budget/subscriber, artifact ownership/location/encryption/public-block, IAM role-quota, Lambda reservation and caller/service-role simulation checks. It never uploads, changes IAM, creates a change set or deploys. For the final profile repeat with `security` and `workload` under their own SSO profiles. Account-wide API Gateway logging configuration is not changed automatically. If a prerequisite fails, resolve the exact finding with the owner; do not bypass it.

## Cost and monitoring

`cost-model-30d.json` and `cost-model-7d.json` are reproducible planning models from `scripts/estimate_cost.py`, not bills or regional quotes. The commercial us-east-1 example estimates $22.02 for 30 days, $28.62 with 30% contingency; seven days is $15.84/$20.60. It assumes 1,000 test interactions, scheduled background traffic, one GB of logs, no free tier and a $10 allowance for services not individually priced. Retained keys/secret are charged for a full month in the model. Reprice the actual target and both-account configuration before approval. Public traffic, repeated faults, existing trails, retained growth, taxes and support can increase costs. A proposed $50 alert budget is not approved and is not a spending cap.

Rates and observation date are recorded in the model with primary [Lambda](https://aws.amazon.com/lambda/pricing/), [API Gateway](https://aws.amazon.com/api-gateway/pricing/), [KMS](https://aws.amazon.com/kms/pricing/), [CloudWatch](https://aws.amazon.com/cloudwatch/pricing/) and [Secrets Manager](https://aws.amazon.com/secrets-manager/pricing/) sources. Other-service allowance is explicitly not a verified unit-price quote.

`infra/budget.yaml` is an optional separately approved account-budget stack with 50/80/100% email notifications. An existing owner-managed budget may be used instead. Confirm actual budget and alarm-topic notification delivery. The project alarms cover intake/normalization/detection/response failures, missing detector invocations, queue age and DLQs; dashboard widgets expose core operational metrics. After deployment an explicitly approved SNS subscription is needed for notifications; an unconfirmed email subscription is not a successful alert test.

## Staging and change-set approval

Local commands incur no AWS infrastructure charges:

```powershell
python scripts/generate_profiles.py
cfn-lint infra/template.yaml infra/security.yaml infra/workload.yaml infra/budget.yaml
sam validate --template-file infra/template.yaml --lint --region REGION
sam build --template-file infra/template.yaml
```

On Windows use a short, hash-verified checkout/staging path and non-cached builds; Linux CI is also supported. `--resolve-s3` is deliberately avoided. Staging uploads and creation of a change set require the first explicit spending approval, even with `--no-execute-changeset`.

After that approval, the exact single-account command is:

```powershell
sam deploy --template-file .aws-sam/build/template.yaml --stack-name STACK --region REGION --s3-bucket EXISTING_BUCKET --s3-prefix sealed-telemetry/COMMIT --role-arn CFN_SERVICE_ROLE_ARN --capabilities CAPABILITY_NAMED_IAM --no-execute-changeset --parameter-overrides Owner=OWNER ExpiresOn=YYYY-MM-DD OperatorPrincipalArn=OPERATOR_ROLE_ARN InvestigatorPrincipalArn=INVESTIGATOR_ROLE_ARN LabExposureEnabled=false EnableSupplementary=false Quiesce=false --tags Project=SealedTelemetry Environment=Lab Owner=OWNER ExpiresOn=YYYY-MM-DD
aws cloudformation list-change-sets --stack-name STACK --region REGION
aws cloudformation describe-change-set --change-set-name CHANGE_SET_ARN --region REGION
```

Inspect every action, generated API deployment, IAM trust/grant/boundary, public endpoint, encryption setting, retention rule and replacement. Reject unexpected account/region, wildcard grants, bucket/table/key replacement, unrelated resources or unapproved supplementary/data-event charges. Store the sanitized change-set output and template hash. **Wait for a second explicit approval before execution.**

```powershell
aws cloudformation execute-change-set --change-set-name APPROVED_CHANGE_SET_ARN --region REGION
aws cloudformation wait stack-create-complete --stack-name STACK --region REGION
```

Use the update waiter for updates. Preserve CloudFormation events on failure. Default rollback remains enabled; do not add `--disable-rollback`.

## Final two-account order

Build `infra/security.yaml`, stage/review/approve/execute it first with `WorkloadAccountId` and `WorkloadStackName`. Then build `infra/workload.yaml` under the workload profile. Pass SecurityAccountId/SecurityStackName and the security outputs: WorkloadIntakeUrl -> IntakeUrl, WorkloadIntakeArn -> IntakeArn, SaasRecordsUrl, PlatformQueueUrl/Arn, TrailBucket -> SecurityTrailBucketName, and TelemetryFailureQueueArn. Pass matching Owner/ExpiresOn/LabExposureEnabled/EnableSupplementary/Quiesce. The workload output AppFunctionArn is the actual denial-test target. Each stack has its own artifact bucket, preflight, change-set review and execution approval. No project code assumes a user-selected role is an account administrator.

## Smoke and live security acceptance

Wait for completed stacks, IAM propagation and fresh health records. Save stack/account/region/commit, physical resources and deployed code hashes. Initially verify unsigned workload/issuer/intake/operator requests fail, token issuance is scoped, SaaS rejects unknown tokens and private archives have no public access. Explicitly approve a disposable exposure-enabled update for the Review-2 replay demonstration.

```powershell
python scripts/cloud_acceptance.py --account ACCOUNT --region REGION --stack STACK --output live-acceptance --execute-approved
```

This runner exercises only the three Review-2 core scenarios, verifies indexed archive versions/hashes and records actual client-observed timing. Its result is not final cloud acceptance: complete every remaining check it lists. No live run has occurred.

Invoke `AppFunction` as the actual workload execution role through its `permission_probe` branch, enabled only in the disposable exposure build. Payload keys are operation=permission_probe, archive_bucket, event_table and provider_queue_url from approved stack outputs. All writes target fresh canaries; delete tests use a different nonexistent key. Expected results are DENIED for archive put/delete, index mutation and provider-queue send. UNEXPECTED_ALLOW or UNVERIFIED is a failure; never delete an unexpectedly written retained canary automatically. Also test source forgery through authenticated intake as AppRole. Use the workload SSO profile to invoke its function in the final profile; do not broaden Lambda-role trust just to impersonate it.

Test partial SQS failures, throttling, outbox stream exhaustion, duplicate delivery, KMS denial, provider-buffer outage, collector outage, clock skew, late evidence and recovery. Use reviewed, reversible project-scoped changes and restore them afterward. Confirm source health/alarms degrade and no unverified containment is reported. Validate native CloudTrail log-file digests with the AWS CLI and confirm selected events from both accounts; canonical metadata hashes alone do not validate AWS's digest-signing chain.

## Rollback, draining and cleanup

Before rollback save evidence versions and decision/response histories. Rebuild the last reviewed Git commit, prepare an update change set and inspect replacements. Never replace evidence buckets/tables/keys as a code rollback. If rollback fails, inspect stack events and only use continue-update-rollback after identifying the failed resources; skipping resources needs separate review.

Before cleanup finish or reject pending approvals, complete response verification, stop harness clients, export incidents, then approve a Quiesce=true update in both profiles. Quiescence rejects new lab data actions, disables health production and supplementary subscriptions, and stops the selected trails while consumers/detector continue draining. It is not a containment proof. Observe zero visible/in-flight/delayed messages repeatedly, an empty pending outbox and no running workflows. Approximate queue counts and a quiet interval are not a completeness attestation; delayed native files can still arrive in retained storage.

```powershell
python scripts/cleanup.py --stack STACK --account ACCOUNT --region REGION --output cleanup-plan.json
python scripts/cleanup.py --stack STACK --account ACCOUNT --region REGION --output cleanup-plan.json --execute --approve-account ACCOUNT --approved-plan-hash REVIEWED_HASH
```

The second command requires explicit deletion approval and a matching current plan. It refuses undrained data, non-quiesced producers or running workflows. Delete workload first, then security. Verify deletion completion and reconcile every retained physical ID against the processed-template inventory. The command does not purge queues, bypass Object Lock or schedule KMS deletion.

Retained resources include Archive/TrailBucket and their policies, EvidenceKey/CredentialKey/ApprovalKey, PseudonymSecret, Events, Decisions, ProviderOutbox, Approvals, Responses and ResponseHistory. Operational active/health state, mock token registry, APIs/functions/queues/alarms/dashboard are removed by approved stack cleanup. Evidence retention is indefinite until separate disposition approval; governance protects each new object for one day and does not establish an automatic expiry. Approved/rejected approval metadata and response attempts remain forensic records; pending callback coordination can expire.

Retained KMS keys/secret continue monthly charges, plus retained S3/DynamoDB storage. Losing or deleting EvidenceKey can make locked archive versions unreadable; Object Lock cannot restore a deleted key. Review key-administrator access and recovery before any key disable/deletion. Cancel pending deletion within its permitted window; completed KMS deletion is irreversible. Credential/approval keys have different purposes and must not be substituted for the archive key. Preserve version manifests, policies and physical IDs for import/recovery; recreating a stack does not automatically adopt retained resources.
