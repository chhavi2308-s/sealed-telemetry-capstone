# Four-stage AWS demonstration — prepared, NOT DEPLOYED

Review date: 2026-11-01. Repository: `C:\Users\prana\sealed-telemetry-capstone`.
Local branch: `aws/four-stage-demo`, based on main `20cb72460b2edb7857330ca8c90e8d23e34aa144`.
No AWS account APIs, deployments, budget changes, identity changes, or live requests were executed for this preparation. No commits or pushes were made.

## What already existed, and why a separate template is needed

- `src/sealed_telemetry/cloud_lab.py`: `gateway`, `app`, `issuer`, `saas` already implement the larger synthetic **records:read** flow. `gateway` issues a token before calling `app`; `emit` sends EXPECTED_ACTION/INTENT_CREATED to intake. This is not direct DynamoDB authorization persistence.
- The existing `issuer` stores token hashes plus KMS-encrypted tokens, reads a pseudonym secret, and supports records:read/export. The SaaS handler runs as Lambda behind the existing SaaS REST API, not on a VM or Google Drive. It commits provider events to a DynamoDB outbox before responding.
- `infra/template.yaml`: complete lab (GatewayFunction POST /run, AppFunction, IssuerFunction, SaasFunction GET /records, Tokens, ProviderOutbox and the downstream pipeline). `infra/security.yaml` and `infra/workload.yaml` split that architecture across accounts. None is a four-stage-only deployment.
- `tests/test_cloud_lab.py` covers the existing issuer, provider outbox, gateway and application. `src/requirements.txt` pins boto3/botocore and their dependencies; runtime is Python 3.12.
- A filename upload operation, direct EXPECTED_ACTION table, and four-stage-only template did **not** exist. The new code below supplies these without changing detection or the original handlers/templates.

The new `/demo/upload` URL, stack name and logical resource names below are explicitly **new proposed configuration**, not endpoints discovered in a deployed account.

## Scope and semantics

```text
SigV4 POST /demo/upload
  -> Authorization Lambda: allowlist synthetic filename/action; write EXPECTED_ACTION
  -> Application Lambda
       -> private Issuer Lambda: check authorization; issue 5-minute bearer token
       -> private SaaS Lambda: validate token/action; write PROVIDER_ACTION audit
  <- safe receipt (IDs, filename, operation, status; never token)
```

API Gateway authenticates the AWS caller using IAM. The Authorization Lambda is the application integration that validates the operation and writes its record; it is **not an API Gateway custom Lambda authorizer**. Only the HTTP integration supplies trusted IAM request context. Do not grant demo users direct invocation of the internal functions.

This is a **synthetic upload receipt** for `invoice_101.pdf`: no PDF bytes are uploaded or stored, and no Google credentials/data are involved. Successful audit persistence constitutes the mock operation. Real file storage requires a separately reviewed scope change. The new private issuer is OAuth-like (opaque bearer token with scope/audience/expiry), not an OAuth standards-compliance implementation. It reuses repository parsing, canonical encoding, HTTP response and bounded SDK configuration helpers. No token revocation endpoint is exposed.

The token is bound to the action ID and filename, stored only as SHA-256 in DynamoDB, and passed only in synchronous internal Lambda payloads. Neither handlers nor the client log request bodies or bearer tokens. There is no token output in stack outputs or environment variables. Expiry is enforced in code; DynamoDB TTL is asynchronous housekeeping. Replays within the validity period are not prevented by one-time consumption: replay detection is outside these four stages.

## Files added

| File | Purpose |
|---|---|
| `infra/four-stage.yaml` | Independent minimal SAM template (JSON is valid YAML) |
| `src/sealed_telemetry/four_stage.py` | Four isolated handlers |
| `tests/test_four_stage.py` | Mocked positive/negative flow and template isolation tests |
| `scripts/four_stage_demo.py` | Approval-gated SigV4 request and consistent DynamoDB read-back |
| `docs/FOUR_STAGE_DEPLOYMENT.md` | This guide |

Existing code/templates/locks remain unchanged. SAM packages the existing `src` dependency tree; having library files in a package does not create the detector or other Lambda resources. No existing full-stack preflight or live acceptance tool should be used to deploy this subset: its parameters, roles and permissions differ.

## Exact resource and environment inventory

16 declared resources: 1 HTTP API, 4 Lambda functions, 4 execution roles, 4 Lambda log groups, 3 DynamoDB tables. SAM also generates the HTTP API stage and API-to-authorization Lambda permission (18 expanded resources). The route/integration live in the generated API definition.

| Handler / logical function | Environment | Runtime permissions (plus its own log stream writes) |
|---|---|---|
| `four_stage.authorization` / AuthorizationFunction | EXPECTED_TABLE, APP_FUNCTION | PutItem ExpectedActions; InvokeFunction ApplicationFunction |
| `four_stage.app` / ApplicationFunction | ISSUER_FUNCTION, SAAS_FUNCTION | InvokeFunction IssuerFunction and SaasFunction |
| `four_stage.issuer` / IssuerFunction | EXPECTED_TABLE, TOKEN_TABLE | GetItem ExpectedActions; PutItem OAuthTokens |
| `four_stage.saas` / SaasFunction | TOKEN_TABLE, AUDIT_TABLE | GetItem OAuthTokens; PutItem SaasAudit |

All handlers have the prefix `sealed_telemetry.`. Function names are `${stack}-authorization`, `-application`, `-issuer`, `-saas`. Each role trusts only lambda.amazonaws.com and uses explicit actions scoped to its exact resource. No role can scan/delete tables, assume roles, change IAM, or invoke unrelated functions. Log groups are created explicitly with seven-day retention; runtime roles can only CreateLogStream/PutLogEvents in their own group.

Tables use on-demand billing, AWS-owned encryption and TTL attribute `expires_at`. `SSEEnabled: false` means **AWS-owned encryption**, not unencrypted storage (see official source below). EXPECTED_ACTION and audit rows expire after one day; tokens at most five minutes. All three tables have Retain for deletion/replacement: no existing data is implicitly deleted by stack teardown. Expired items can remain for days; Retain does not disable TTL. No PITR, custom keys, secrets, S3 data bucket, queues, subscriptions, detector, EventBridge, Step Functions or response functions are defined. A separate pre-existing SAM artifact bucket is needed for deployment packages.

Parameters: `Owner` (nonempty string), `ExpiresOn` (YYYY-MM-DD tag; **does not shut resources off**).
Outputs: `UploadUrl`, `InvokeArn`, `ExpectedTable`, `AuditTable`.

No reserved concurrency is configured. The earlier full-system requirement for 101 unreserved executions does not apply here. A successful request nests authorization, application and one issuer/SaaS invocation, so allow at least three available concurrent executions; actual account limits and plan eligibility still require confirmation. Throttle is one request/second, burst two: it is a best-effort throttle, not a spending cap. Run requests sequentially; occasional throttles can occur with low concurrency.

## Local validation

See final validation record below. Tests use moto and mocked Lambda transport, not AWS or a local Docker Lambda runtime. They prove the application logic and record matching, not real AWS IAM, deployed routing, account eligibility, delivery or latency. SAM build installs pinned dependencies into its ignored build artifacts only; no global/project environment packages were installed. No Docker Lambda invocation was performed.

## Owner prerequisites — stop if any is missing

1. Confirm the intended 12-digit account, Mumbai region, owner label, end date and spending ceiling. Earlier root-only account observations are dated evidence, not proof of current access.
2. Approve a console/MFA-backed **non-root assumed role** and its separately reviewed access policies. Do not use root or create access keys. Existing full-stack IAM drafts are not an approved policy package for this new stack; do not attach them unchanged.
3. Provide a private encrypted existing artifact bucket in ap-south-1 and a reviewed CloudFormation execution-role ARN. If absent, obtain separate approval to create them. This guide never uses `--resolve-s3`, which could create SAM-managed resources.
4. Confirm an appropriate monthly budget and verified notification recipient. Prior evidence named `My Monthly Cost Budget` with USD10; do not assume it still exists or change it automatically. Budgets are delayed alerts, not hard caps.
5. Separately approve IAM prerequisites, the artifact bucket, artifact upload, change-set creation and exact change-set execution. A live synthetic write request and cleanup also require separate approval.

Human deployer permissions need exact stack-scoped CloudFormation change-set operations/read operations, prefix-scoped artifact upload/read, bucket metadata access and PassRole of only the reviewed CFN role to cloudformation.amazonaws.com. The CFN role needs resource lifecycle operations for just this template's Lambda, IAM execution roles/inline policies, DynamoDB/TTL/tags, log groups and API Gateway **HTTP APIs**; no detector/KMS/SQS/Step Functions permissions. The older REST-API policies are insufficient for `/apis` resources. Creating/updating runtime IAM policies is privileged delegation: review the template and role scope before granting it. Account-bound policy JSON and live permission verification are still pending owner identifiers/approval; no claim of deployment-ready IAM is made.

The demo caller needs `execute-api:Invoke` on the exact `InvokeArn`, `cloudformation:DescribeStacks` on this stack and `dynamodb:GetItem` on only ExpectedActions/SaasAudit (plus GetCallerIdentity). It does not need token-table access or direct Lambda invocation. Logs investigation needs DescribeLogStreams/GetLogEvents/FilterLogEvents limited to the four log groups. Budget read permissions are separate. No AdministratorAccess policy is proposed.

## Windows PowerShell — run in order, stop at every failed check

### 1. Location and installed tools (safe now)

```powershell
Set-Location 'C:\Users\prana\sealed-telemetry-capstone'
$ErrorActionPreference = 'Stop'
aws --version
if ($LASTEXITCODE -ne 0) { throw 'AWS CLI is unavailable' }
sam --version
if ($LASTEXITCODE -ne 0) { throw 'SAM CLI is unavailable' }
git status --short
```

### 2. Secure login (only after the non-root role exists and is approved)

Sign into the AWS console with the MFA-protected non-root identity and switch to the approved role. AWS browser login needs the Sign-In localhost OAuth permissions reviewed for that role. Do not select a root console session. This command changes local profile/cache state; it does not create an IAM identity:

```powershell
$Profile = 'sealed-telemetry-dev'
$Region = 'ap-south-1'
$Account = Read-Host 'Owner-confirmed 12-digit AWS account ID'
if ($Account -notmatch '^\d{12}$') { throw 'Invalid account ID' }
aws login --profile $Profile --region $Region
if ($LASTEXITCODE -ne 0) { throw 'Login failed; do not fall back to root or access keys' }
$Caller = aws sts get-caller-identity --profile $Profile --region $Region --output json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Identity check failed' }
if ($Caller.Account -ne $Account -or $Caller.Arn -notmatch ':assumed-role/') {
    throw 'STOP: expected account and non-root role required'
}
$Caller | Select-Object Account,Arn
aws account get-region-opt-status --region-name $Region --profile $Profile --region $Region
if ($LASTEXITCODE -ne 0) { throw 'Region check unresolved; request owner confirmation' }
aws lambda get-account-settings --profile $Profile --region $Region --query 'AccountLimit.UnreservedConcurrentExecutions'
if ($LASTEXITCODE -ne 0) { throw 'Concurrency check unresolved' }
```

If Account/Lambda reads are denied, stop; do not add broad permissions simply to make checks pass. Confirm the region is enabled and at least three executions are available for a sequential run. No quota increase is performed by this guide.

### 3. Budget alert before deployment

Read-only inspection (requires approved budget read access):

```powershell
$BudgetName = 'My Monthly Cost Budget'
aws budgets describe-budget --account-id $Account --budget-name $BudgetName --profile $Profile --region us-east-1 --query 'Budget.{Name:BudgetName,Limit:BudgetLimit,Period:TimeUnit,Type:BudgetType}'
if ($LASTEXITCODE -ne 0) { throw 'Budget absent or unreadable; owner review needed' }
aws budgets describe-notifications-for-budget --account-id $Account --budget-name $BudgetName --profile $Profile --region us-east-1
if ($LASTEXITCODE -ne 0) { throw 'Budget notification check unresolved' }
```

In Billing → Budgets, the owner should confirm the monthly USD limit, actual/forecast alert thresholds and intended email recipient, including required email verification. If missing, **pause for separate approval** to create a monthly cost budget and notification using the official AWS guide linked below. Do not apply `infra/budget.yaml` or enable billing features as a side effect. Opening the console is safe; changing its settings requires approval:

```powershell
Start-Process 'https://console.aws.amazon.com/billing/home#/budgets'
```

This intentionally supplies no unattended budget-creation command: the limit/recipient have not been approved for a change, and earlier instructions forbid changing billing settings. A confirmed existing alert satisfies this gate.

### 4. Local build and validation (safe before deployment)

```powershell
$env:SAM_CLI_TELEMETRY = '0'
sam validate --lint --template-file infra\four-stage.yaml --region ap-south-1
if ($LASTEXITCODE -ne 0) { throw 'Template validation failed' }
sam build --template-file infra\four-stage.yaml --build-dir .aws-sam\four-stage --region ap-south-1
if ($LASTEXITCODE -ne 0) { throw 'Build failed; do not deploy' }
```

The installed test runtime used for this review is outside this checkout; no package install is needed on this computer:

```powershell
$TestPython = 'C:\Users\prana\Downloads\sealed-telemetry-capstone-implementation\.venv\Scripts\python.exe'
& $TestPython -m pytest tests\test_four_stage.py tests\test_cloud_lab.py -q
if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
```

### 5. Five separate approvals — no AWS writes authorized

The owner confirmed a **USD5 total planning ceiling** for the initial demo. It is not approval to create, upload or deploy. Existing USD10 monthly budget alerts are not a hard cap.

1. Approve the exact deployment-role and CloudFormation-role trust/permission JSON and IAM creation commands.
2. Separately approve the private Mumbai artifact bucket configuration and creation commands.
3. Separately approve `sam package` artifact uploads to that bucket/prefix.
4. Separately approve `aws cloudformation create-change-set` using the packaged template.
5. Review the actual resulting change-set ARN and resource/IAM changes, then separately approve execution.

Never combine steps3–4 under `sam deploy --no-execute-changeset`; it performs both writes. Do not run `sam deploy --guided` or `--resolve-s3`. Exact commands, policies, costs and proposed identifiers are in the external four-stage-review-package directory linked in the review response. They are drafts and were not executed.

Keep `sealed-telemetry-dev` for the non-root administrator's approved prerequisite setup only. After approval, switch to the reviewed deployment role and use a separate profile `sealed-telemetry-deploy` for package/change-set/execution and demonstration operations. Set `$Profile = 'sealed-telemetry-deploy'` in the following examples only after verifying its exact assumed-role ARN and account. Preserve all existing assumed-role guards.

Parameters remain Owner and ExpiresOn; confirm their values before any change set. Stack proposal: sealed-telemetry-four-stage; region ap-south-1. First deployment must contain only Add actions; stop if an existing stack or Modify/Remove changes appear.

### 6. Find the URL, send invoice operation and verify both tables

After successful deployment, exact caller permissions must reference the returned InvokeArn and two table ARNs. Plain `Invoke-RestMethod` without SigV4 will fail IAM authentication; use the included signer. Browser-login Boto3 requires CRT. The already-installed SAM Python runtime has boto3 and CRT; it is used only for this helper, not to change Lambda's Python 3.12 runtime. If unavailable, pause for an approved tooling solution—no credential export or static-key workaround.

```powershell
$DemoPython = 'C:\Program Files\Amazon\AWSSAMCLI\runtime\python.exe'
& $DemoPython -c 'import boto3, awscrt; print("Boto3 and CRT available")'
if ($LASTEXITCODE -ne 0) { throw 'Approved SDK login runtime unavailable' }
& $DemoPython scripts\four_stage_demo.py --help
aws cloudformation describe-stacks --stack-name $Stack --profile $Profile --region $Region --query "Stacks[0].Outputs[?OutputKey=='UploadUrl'].OutputValue" --output text
# Sending the request writes synthetic records and needs explicit approval.
$DemoRequestApproved = $false
if (-not $DemoRequestApproved) { throw 'STOP: synthetic AWS request approval required' }
& $DemoPython scripts\four_stage_demo.py --profile $Profile --account $Account --stack $Stack --execute-approved
if ($LASTEXITCODE -ne 0) { throw 'AWS flow verification FAILED or unresolved' }
```

The helper performs STS GetCallerIdentity, CloudFormation DescribeStacks, one signed POST, then strongly consistent GetItem on ExpectedActions and SaasAudit. It validates matching action ID, operation, filename, provider request ID and successful audit outcome. It never scans or reads the token table. Only output `aws_verified: true` from an actual successful run is AWS success evidence. This guide has **no such result**.

Example request (synthetic, not executed):

```json
{"operation":"files:upload","filename":"invoice_101.pdf"}
```

Illustrative response/records (IDs and times will differ; not AWS results):

```json
{
  "response": {"status":"success","action_id":"<generated UUID>","provider_request_id":"<generated UUID>","synthetic":true},
  "expected": {"event_type":"EXPECTED_ACTION","action_id":"<same action UUID>","operation":"files:upload","filename":"invoice_101.pdf","authorized_at":1793530800},
  "audit": {"event_type":"PROVIDER_ACTION","action_id":"<same action UUID>","provider_request_id":"<same provider UUID>","operation":"files:upload","filename":"invoice_101.pdf","outcome":"success","synthetic":true,"recorded_at":1793530801}
}
```

### 7. Logs and evidence

After an approved run, view only these function log groups, e.g.:

```powershell
aws logs tail "/aws/lambda/$Stack-authorization" --since 10m --profile $Profile --region $Region
aws logs tail "/aws/lambda/$Stack-application" --since 10m --profile $Profile --region $Region
aws logs tail "/aws/lambda/$Stack-issuer" --since 10m --profile $Profile --region $Region
aws logs tail "/aws/lambda/$Stack-saas" --since 10m --profile $Profile --region $Region
```

Capture CREATE_COMPLETE, exact resources, API route AWS_IAM configuration, safe helper output and Lambda REPORT duration/billed-duration/memory lines. Redact account identifiers as needed; never capture credentials/login cache or internal invocation payloads. No AWS API access logging is enabled in this minimal first step. Lambda service logs and durable table receipts provide the requested demonstration observations.

HTTP403 usually means missing route invocation permissions or invalid signing; HTTP400 means the request was not exactly the allowlisted synthetic operation. HTTP5xx can mean missing runtime permission, throttling, timeout or a persistence error. An EXPECTED_ACTION without an audit is an **incomplete attempt**, not success. Do not blindly repeat timed-out requests: this demo is not idempotent across repeated HTTP submissions, so each repeat creates a new action ID and can create another audit receipt.

## Costs, retention and stopping

No precise quote is claimed. For one approved sequential request, the normal path is one HTTP API request, four Lambda invocations, two token/authorization reads, three table writes and two verification reads, plus stack lookup/logging. Billed DynamoDB units depend on item size and consistent reads; logs/storage/artifact uploads also cost money. Setup, retries and other account activity add charges. Use current Mumbai pricing for HTTP APIs, Lambda, DynamoDB, CloudWatch Logs and S3 before owner approval. Earlier full-system dollar estimates do not describe this subset.

There is no scheduled producer, provisioned concurrency, NAT gateway, custom key or secret. Idle storage in retained tables, seven-day log retention and the artifact bucket can still incur charges. TTL is approximate and does not delete tables. End-date tags and budget alerts do not turn resources off. Do not run bulk traffic.

No deletion commands are provided or executed. After the demonstration, stop sending requests and obtain a separate cleanup approval listing the stack, retained tables, logs and artifact prefix. Deleting a stack would retain all three tables but normally remove its functions/roles/API/log groups; exported evidence and retention requirements must be decided first. Existing resources must not be deleted under this preparation request.

## Official references used

- [HTTP API IAM authentication and SigV4](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-access-control-iam.html)
- [SAM HTTP API IAM configuration](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-property-httpapi-httpapiauth.html)
- [DynamoDB AWS-owned encryption setting](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-dynamodb-table-ssespecification.html)
- [AWS CLI browser login](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sign-in.html)
- [SDK login provider and CRT requirement](https://docs.aws.amazon.com/sdkref/latest/guide/feature-login-credentials.html)
- [Creating and reviewing budget alerts](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-create.html)

## Approval status

Prepared for local/code review. **NOT deployed; no live four-stage success claimed.** Owner confirmation is still required for non-root identities/policies, artifact bucket, CFN role, account eligibility, budget, maximum spend, retention and each AWS write phase. Approving this code does not apply IAM or authorize all later AWS actions.

## Final local verification record

- Focused tests: **15 passed** (new four-stage tests plus existing cloud-lab regression tests).
- Ruff: all three new Python files passed.
- SAM CLI 1.170.0: minimal template lint passed; Python 3.12 build passed.
- Offline SAM expansion: **18 resources**, only the seven resource types inventoried above; generated POST /upload security is AWS_IAM. The expansion used a dummy S3 URI in memory because the transformer expects packaged input; no S3 bucket/object was accessed.
- CLI help imports successfully with the installed SAM Python runtime; no live SDK login was attempted.
- Original files/templates/locks unchanged; five new review files on the local branch, no commit/push.
- No AWS API operations, live HTTP requests, IAM policy simulation, deployment, account mutation or resource deletion performed. Cloud permissions, actual routing, budget delivery, runtime behavior and AWS evidence remain **NOT VERIFIED**.

Source anchors: original `cloud_lab.py` issuer/saas/gateway/app and new `four_stage.py` authorization/app/issuer/saas are identified by exact function names above. The new issuer deliberately avoids the original encrypted-token persistence used by later response workflows.

## Current local correction review

The HTTP client now explicitly passes timeout=35 to the HTTPS opener. The deployment guide now separates all five approval gates. Current validation results and USD5 workload model are in the external review package. Historical results above describe the earlier preparation; no AWS end-to-end success is claimed.


## Local controlled replay extension (not deployed)

The local harness `scripts/four_stage_attack_local.py` replaces Lambda transport and
DynamoDB access with in-memory doubles. Its default run completes one legitimate
operation without capturing a token. `--simulate-copy` enables capture only inside
that fixture, waits until the legitimate app call returns, then reuses that issued
synthetic token against the local SaaS handler. A second negative case requests
`invoice_102.pdf`; binding checks deny it. Tokens are never accepted as CLI inputs,
printed, returned in reports, or persisted in plaintext. The harness returns only
sanitized receipts and analysis; its token closure is cleared when it finishes.
It cannot import an actual bearer credential for replay. Network connections are
blocked inside the fixture. Do not use this harness as an AWS invocation client.

The application now logs a safe `APP_INTENT` event before issuer/SaaS calls. The
internal `suppress_app_intent` option takes effect only when
`FOUR_STAGE_LAB_ENABLED=true`; that environment variable is absent from the approved
SAM template. The public request schema still rejects simulation fields. Suppression
omits only this application event; it does not modify logging configuration, Lambda
platform logs, or provider audit persistence. The module logger enables INFO so the
normal intent event is emitted with the standard logging handler.

`four_stage_analysis.analyze` is a separate, pure local demo analyzer. It deduplicates
identical provider request IDs, treats conflicting duplicate records as inconclusive,
checks operation/resource/time bindings, flags multiple successes for one expected
action as SUSPICIOUS_REPLAY, and identifies absent app intent. That warning does not
prove token theft or attacker identity: retries can cause the same observation.
Missing authorization is conclusive only when the caller asserts a complete evidence
snapshot after the settling interval. Missing or delayed evidence otherwise remains
INCONCLUSIVE. AUTHORIZED describes only the supplied snapshot; later evidence may
change it. This is not full IBER reconciliation.

Legitimate: IAM API -> authorization/EXPECTED_ACTION -> app/APP_INTENT -> issuer ->
SaaS/token validation -> SaasAudit -> safe receipt.
Local attack: complete legitimate app -> copy held in local memory -> same-token SaaS
call -> distinct audit -> different-invoice denial/audit -> local analysis.

No safe Lambda-to-local token handoff is added. AWS replay remains an integration gap:
there is no public SaaS endpoint or token exposure API, and a synthetic token alone
does not grant lambda:InvokeFunction. Any future cloud test needs separately reviewed
transport, permissions, code upload, deployment, and invocation approvals.

Packaging proposal: refresh only four_stage.py in a NEW isolated six-file staging
package; the local analyzer and harness are not Lambda dependencies. Existing Gate 4
ZIPs, hashes and upload-only script remain historical and unchanged. The new source
requires new artifacts/manifests and review before upload. No SAM resources, handler
names, runtime IAM actions, boundaries or DynamoDB schemas are changed. Existing log
permissions suffice for APP_INTENT. There is a small additional log-ingestion cost;
no new AWS service is required for this local exercise. USD5 remains a planning
ceiling, not a cap. Gates 4, 5 and 6 remain BLOCKED and NOT APPROVED.
