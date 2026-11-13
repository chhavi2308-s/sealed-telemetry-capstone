# Four-stage C2/C4 infrastructure source

`infra/four-stage-c2c4.yaml` is the version-controlled source for an update of
the existing four-stage synthetic upload stack. It is an offline artifact, not
evidence that the corresponding resources are deployed or that the effective
AWS permissions boundary permits every requested operation.

## Safety defaults

- `GrantProducerEvidencePermissions=false`
- `EvidenceMode=legacy`
- `ContextMode=disabled`
- No EventBridge or Scheduler resource, schedule, public observer route, or
  Lambda Function URL is declared.
- Secret and observer-boundary values are required ARN parameters. The template
  stores neither a secret value nor a deployment-specific ARN.
- New evidence tables use deterministic `${AWS::StackName}`-derived names,
  on-demand capacity, DynamoDB SSE, deletion protection, and `Retain` deletion
  and replacement policies. `C4EvidenceState` deliberately has no TTL because
  its control, conflict, quarantine, and history records are evidence.
- All legacy and new evidence tables carry the Project/Owner/ExpiresOn tags.
  Observer roles carry the same governance tags; function tags come from SAM
  Globals.
- CloudFormation rejects `ContextMode=c4` unless `EvidenceMode=c2`; the safe
  default remains `disabled` with `legacy`.

The legacy `infra/four-stage.yaml` remains unchanged. Its legacy DynamoDB
encryption settings are deliberately not altered by this source template.

## Resource and source-operation contract

| Component | Table/role scope | Required operations |
| --- | --- | --- |
| Authorization producer | Expected actions; gateway context | Existing expected-action write/invoke; conditional C2/C4 gateway-context write and identity-secret read |
| Application producer | Expected actions, issuance evidence, gateway/application context | Exact reads; application-context writes; context-secret read |
| Issuer producer | Expected actions, token registry, issuance evidence | Legacy `GetItem` only on expected actions and `PutItem` only on token registry; conditional C2/C4 transaction reads/writes/condition check; identity/credential secret reads |
| SaaS producer | Token registry, audit, application/provider context | Exact reads/writes and context-secret read |
| Collector | Seven evidence sources plus collector state | Source describe/scan; collector-state read/write/condition/transaction only; no OAuth-token or secret access |
| Monitor | Four named function ARNs and health table | Function configuration and CloudWatch metric reads; independent-health writes only |

Producer evidence policies exist only under the named
`GrantProducerPermissions` condition. The IAM permissions boundary remains a
separate deployment-time dependency: its effective allow/deny intersection must
be checked before enabling the condition or a C2/C4 mode.

`TransactWriteItems` is explicitly included for issuer and collector because
the source invokes DynamoDB transaction APIs. The identity policies are not a
claim that the external boundaries already permit those calls.

The KMS `Decrypt` resource is necessarily `*` because the key is external to
this template, but it is constrained to the Secrets Manager service in the
current region and the exact secret ARN encryption context. A later live review
must still prove the secret-key policy and the identity-policy/boundary
intersection; offline checks cannot do so.

## Deployment-owned configuration

Same-stack table ARNs are supplied using intrinsic `GetAtt` references:

- Issuer: `EXPECTED_TABLE_ARN`
- Application: `EXPECTED_TABLE_ARN`, `ISSUANCE_TABLE_ARN`

This supports the fail-closed ARN validation introduced by the C4 ARN-fix
commit without runtime `DescribeTable` or `GetCallerIdentity` discovery. Secret
environment variables contain secret ARNs, not values; handlers retrieve their
own allowed secret at runtime.

The collector configuration describes the bounded direct DynamoDB C2 and C4
sources and its exact monitor function identities. Collector and monitor have
reserved concurrency one, but are unscheduled and privately invoked only.

## Intentionally incomplete archive capability

The collector code has an `aws-events-1` archive contract, but the recovered
artifacts do not establish a deployable version-pinned S3/SQS archive path.
This template deliberately creates no S3, SQS, archive role, bucket policy, or
event-source mapping. That capability needs its own source identity, exact
object-version/owner checks, retention design, and IAM review.

## Offline validation

Run from the integration worktree:

```powershell
& ..\test-env\Scripts\pytest.exe -q tests/test_four_stage_c2c4_infrastructure.py tests/test_four_stage_binding.py tests/test_four_stage_context.py tests/test_four_stage_collection.py
& ..\test-env\Scripts\ruff.exe check src tests
& ..\test-env\Scripts\ruff.exe format --check src tests
& ..\test-env\Scripts\mypy.exe --strict src
& ..\test-env\Scripts\cfn-lint.exe infra/four-stage-c2c4.yaml infra/four-stage.yaml
git diff --check
```

CloudFormation Guard remains deferred and SAM CLI is unavailable. cfn-lint and
offline contract tests validate template structure only; they do not validate
live stack drift, parameter values, external boundaries, secret ownership,
artifact availability, or actual AWS permissions.

## Deployment gate and rollback constraints

Before any deployment, separately authorize a read-only inventory and change
set inspection. Confirm logical-ID continuity, no API or legacy-role drift,
correct immutable artifact version, exact external ARN parameters, external
boundary/key ownership, and the identity-policy/boundary intersection. Inspect
whether the deterministic new table and API access-log-group names collide with
already-existing resources before creating a change set. A future rollback must
preserve retained tables and evidence; it must not delete or overwrite collector
state or quarantined records. Enabling a collector/monitor schedule is a
separate change requiring source-bound invocation permissions and an explicit
approval.
