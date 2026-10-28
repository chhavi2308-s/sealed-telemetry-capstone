# Live demo runbook

BLOCKED: no AWS credentials, confirmed account, region, stack or deployment outputs. Commands below are parameterized candidate commands, not commands verified against a deployed environment. Never invent endpoint values. Complete ../release/DEPLOYMENT.md first.

## Authentication and release gate

Install AWS CLI v2, then run `aws configure sso --profile sealed-sandbox`, enter your organization's IAM Identity Center start URL and SSO region, select the authorized sandbox account/role and set the intended workload region. Run `aws sso login --profile sealed-sandbox`, set `$env:AWS_PROFILE="sealed-sandbox"`, then `aws sts get-caller-identity`. Do not paste keys or session tokens into chat. If your organization uses temporary roles, use its credential broker instead. Identity Center setup/role provisioning requires your AWS administrator.

Supply a preferred region (ap-south-1, ap-south-2 or us-east-1), account ownership, alert threshold, retention days, artifact bucket and deployment role. They have not yet been selected. Review exact resources, permissions, change set, regional cost and retained keys before approving execution.

## Approved live execution

```powershell
aws cloudformation describe-stacks --stack-name $Stack --region $Region --query 'Stacks[0].Outputs'
aws cloudformation list-stack-resources --stack-name $Stack --region $Region
python scripts/cloud_acceptance.py --account $Account --region $Region --stack $Stack --output evidence/live --execute-approved
```

The acceptance command sends synthetic requests and requires approval; it is not read-only. It covers three core scenarios and does not establish full final acceptance. In Console, open CloudFormation stack Resources to navigate to Lambda functions, API Gateway stages, CloudWatch log groups, SQS queues and the archive. Do not display bearer tokens or raw secret values.

For the normal request, show the gateway invocation, app action and independent provider request ID. Explain that matching observations support consistency. For replay with suppression, show the missing app security event alongside the actual provider event and the resulting finding. Missing logs alone are not the evidence of replay. For benign logging failure, show the uncertain state and absence of a confirmed-theft claim.

Save acceptance-summary.json, sanitized request/evidence IDs, receipt times and detector revisions. Independently export archive versions with scripts/export_incident.py (see --help); a valid hash result is required. Display S3 version IDs/receipts and compare detection timestamp to provider receipt time. Use actual ISO timestamps, never simulator times. Capture console screenshots only from the authorized sandbox after redacting identifiers as needed.

Run workload permission_probe, collector outage/DLQ recovery and approved response/recovery using ../runbook.md and ../release/DEPLOYMENT.md. Generic HTTP403 is insufficient revocation proof. Preserve failed attempts and unresolved results. Full cloud performance needs paired measurements and billing scope with scripts/analyze_measurements.py.

## Offline fallback

```powershell
./docs/final-review-demo.ps1 -Python .venv/Scripts/python.exe -OutputRoot demo-final
```

Clearly announce “local synthetic demonstration”. Saved docs/results/clean-install-demo reports are local recordings, not AWS recordings. No live AWS recording currently exists. Use EVIDENCE_INDEX.md to avoid mixing categories.
