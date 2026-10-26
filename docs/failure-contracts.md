# Critical component failure contracts

All cloud controls below need live rehearsal; test coverage is recorded by name, not implied from architecture.

| Component | Expected/failure detection | Retry, idempotency, recovery | Data/security effect | Acceptance |
|---|---|---|---|---|
| Issuer/registry | Scoped expiring synthetic token; reject wrong scope/audience/revoked/expired | SDK connect=2s/read=5s, 3 total standard attempts; issuance may create unused tokens after timeout; retry is not exactly once | No raw tokens in audit; encrypted cloud copy only responder decrypts | test_provider_security_and_verified_response; test_issuer_and_provider_outbox |
| SaaS/outbox | Audit commit before synthetic data returned; DynamoDB errors fail invocation | Stream retries 5, age 1h, failure queue; retained raw outbox permits recovery | No successful response without durable audit; read-only resources | test_outbox_recovery; cloud fault rehearsal pending |
| Intake | AWS_IAM role to source binding, schema/size rejection; 5xx on SQS failure | Caller may resend stable ID; queue durable before 202 | A receipt acknowledges intake, not archive completion | test_principal_boundaries; test_intake_to_archive_and_duplicate |
| Queue/consumer | Queue age, errors and DLQ depth alarms | 180s visibility vs 25s consumer, maxReceiveCount 5, partial batch responses | Poison messages isolated; prolonged outage may exhaust retention | test_partial_batch_and_conflicting_id |
| Archive/index | Archive first, conditional index second | Conditional put, hash equality on duplicates; redelivery repairs index | Archive-only objects recoverable; no index before archive; retained KMS required | test_archive_failure_does_not_commit_index; test_index_failure_recovers_from_existing_archive |
| Reconciler | Pending/uncertainty on missing/delayed sources; bounds fail visibly | Minute sweep, stable case/decision IDs; late state changes append | No missing-log-only theft verdict; global credential grouping bounded to lab scan | test_late_revisions_and_sweep_idempotency; test_ambiguity_and_concurrent_invocations |
| Finding bus | PutEvents FailedEntryCount raises | Sweep republishes; subscribers dedup decision ID | Repeated alerts possible; policy gate cannot auto-revoke | Cloud event routing test pending |
| Responder | Explicit approval and actual provider rejection proof | Workflow retry 2, backoff; repeated revoke idempotent; response record dedup | Unknown verification remains unverified; no token in workflow | Local response tests; cloud responder test |
| Health | Missing/stale/unknown evidence degrades confidence | Local TTL; independent cloud heartbeat, pending-outbox and queue checks | Does not establish completeness; coverage calibration pending | test_health_staleness; collector/provider outage scenarios |
| Forensics | Hash validity, timestamp order, explicit gaps | Re-export from retained version; corrupted copies rejected | Hash is not truth/completeness; simultaneous hash alteration out of scope | tampering scenario, verify CLI |
| Deployment | Read-only identity/budget/logging preflight | Change-set review; known-good code rollback; retained evidence | No paid deploy until owner approval; cleanup leaves retained charges | cfn-lint; live deployment/rollback/teardown pending |
