# Operator runbook

See `release/DEPLOYMENT.md` for account gates, exact staging/change-set commands, inventory, cost assumptions, live acceptance, rollback and cleanup. Nothing in this runbook authorizes an AWS deployment.

## Local demonstrations

From a fresh environment follow README. Each output directory must be new. Run normal, replay-suppression and benign-log-failure through `sealed_telemetry.cli demo`; verify reports with `cli verify`. The replay omits invocation/action IDs. Provider audit remains present when app intent is suppressed. A benign missing app log is inconclusive. The local boundary is a software model, not an AWS security boundary.

## Approval and containment

The findings dispatcher deduplicates executions. The Standard workflow waits for an operator callback; an input approved=true never bypasses it. Configure OperatorPrincipalArn explicitly. Callback tokens remain encrypted and are never returned by the API. InvestigatorPrincipalArn may read cases/generate reports but cannot approve response.

```powershell
python scripts/operator_cli.py list --url OPERATOR_API_URL --region REGION
python scripts/operator_cli.py show --approval-id ID --url OPERATOR_API_URL --region REGION
python scripts/operator_cli.py approve --approval-id ID --response-action contain --disable-integration --url OPERATOR_API_URL --region REGION
```

The last command prints a concrete plan and hash. Review subject, case/revision, action and integration impact, then repeat with `--execute --approved-plan-hash HASH`. Reject uses the same flow with mode reject. Writes are bound to that exact plan. An approval applies only to the current decision and expires for starting an attempt after 15 minutes. Superseded decisions cannot authorize registry changes; the mutation checks the current revision atomically. Do not work around a stale decision error by changing a boolean or hash.

Inspect the actual workflow and response records. Revocation is probed before optional global integration disabling, so a global denial cannot masquerade as verified per-token revocation. Generic 403, expired/unknown tokens, lookup failures and network errors do not prove revocation. An already disabled integration can mask verification; preserve an unverified outcome and investigate rather than reopening it automatically. Response leases bound concurrent effects, with at most three completed attempts; started negative attempt keys preserve interruption evidence before side effects. No token enters workflow outputs or response audit records.

A failed broker/workflow can be restarted manually under a new execution name with the current sanitized finding, after review; it requires a fresh approval. Repeated findings do not silently create duplicate executions. If callback acknowledgement is uncertain, the API checks execution history; it never assumes delivery. Approval status approved is not a containment-success claim. A decision that changes after an effect is preserved as a new revision; do not automatically undo a security action.

## Recovery

Deploy/review known-good workload code first. Request a new workflow for the current case and approve response-action recover without disable-integration. Recovery requires the old credential to be revoked, issues a fresh disposable credential, records trusted recovery expectations, reopens the synthetic integration and verifies old rejection plus fresh success. Failure closes it again. Credentials remain internal. Recovery demonstrates credential/integration restoration for read-only synthetic records; arbitrary modified-data restoration is not claimed. Clean-code deployment requires separate change-set review and live verification.

## Evidence, failed delivery and forensics

Queue receipt means buffered, not archived. Check DLQ/oldest-message alarms, pending provider outbox and source health. Inspect IDs/error classes; do not dump original messages or tokens to shared logs. Invalid intake stores only rejection metadata/body-representation hashes. Poison-message quarantine is under the private archive quarantine/ prefix, with no raw producer payload; failed messages still follow DLQ handling. Never call metadata-only quarantine a full payload reconstruction.

For an approved SQS redrive:

```powershell
python -m sealed_telemetry.redrive --region REGION --source-url DLQ_URL --destination-url ORIGINAL_QUEUE_URL --plan redrive.json
python -m sealed_telemetry.redrive --region REGION --plan redrive.json --approved-plan-hash REVIEWED_HASH
```

Planning checks account/region and the configured DLQ relationship. Execution rechecks the same plan, refuses an active move and rate-limits native redrive. Enqueued is not archive-verified. Inspect move-task status, queue age, hashes and indexes afterward. Do not redrive stream failure metadata as canonical evidence. Invoke ReplayFunction first with selected original ProviderOutbox event_ids for a dry plan, then with its approved_plan_hash. It preserves event IDs/bodies and never removes original outbox records. For expired stream metadata use a scoped read-only outbox inspection to identify records; do not purge or invent replacement observations.

Generate a version-pinned core report through operator_cli report or scripts/export_incident.py. If investigation spans attacker-assigned run IDs, use credential-fingerprint scope. Each archived version's original, canonical and normalized hashes are verified; timestamps do not prove causal order. Export detailed response attempts separately:

```powershell
python scripts/export_response.py --account ACCOUNT --region REGION --table RESPONSE_HISTORY_TABLE --approval-id APPROVAL_ID --output response-history.json
```

A started record without completion is an interrupted/unknown outcome. To repair lost final evidence delivery, an authorized security operator may invoke ResponderFunction with operation=reemit, approval_id and completed attempt (1..3). This reads retained evidence and enqueues the original event only; it does not repeat containment and explicitly does not verify current enforcement. Keep all failed/completed attempts and late/revised decisions in the incident bundle.

Evidence exports may be cross-service snapshots rather than one atomic instant. APIs mark bounded/truncated results; use the paginated SDK exports for full scoped reconstruction. Health proves operational observations, not completeness. Neither healthy current components nor valid hashes establish that no historical evidence was lost. Record outages, retention gaps, unknown coverage and scale bounds in every report.
