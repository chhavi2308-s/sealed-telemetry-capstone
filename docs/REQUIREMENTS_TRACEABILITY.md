# Requirements traceability

The complete source extracts in docs/specifications are the specification register. The table maps all architecture planes and delivery work packages; pending tickets remain requirements, never implied completion. Owner for implementation: Codex; AWS account/budget and independent review: project owner. Acceptance maps to final blueprint §§24, 41, 44 and Review-2 tickets §§7, 18.

| Ticket | Requirement and source | Target | Acceptance/dependency |
|---|---|---|---|
| ENG-01 | Foundation, CI, dependency scanning (§28) | pyproject.toml, .github/workflows | lint/type/test/audit; none |
| LAB-01 | Mock OAuth expiry/scope/audience/revocation (R2-03) | src/sealed_telemetry/provider.py | rejected invalid tokens; ENG-01 |
| LAB-02 | SaaS synthetic actions, independent durable outbox (R2-04) | provider.py | audit survives app suppression; LAB-01 |
| LAB-03 | Legitimate Lambda, Secrets Manager, ingress (R2-05) | aws_handlers.py, infra | successful cloud request; LAB-02 |
| OBS-01 | App/platform/access logs and supported CloudTrail (R2-06) | infra, docs/runbook.md | separate source proof; cloud approval |
| EVD-01 | Authenticated intake, strict schema, receipts (R2-07) | schema.py, aws_handlers.py | spoof/oversize/invalid rejected |
| EVD-02 | Queue/DLQ/retry/idempotency/index (F2) | storage.py, infra | duplicate/outage/redrive tests; EVD-01 |
| EVD-03 | Raw/canonical archive, KMS, Object Lock (F5) | storage.py, infra | tamper detection and AWS deny tests |
| SEC-01 | Separate accounts/roles, protected evidence (F1) | infra, docs/adr | workload cannot modify evidence; approval |
| DET-01 | Invocation/action/provider IDs, pseudonyms, bounded fallback (F3) | reconciliation.py | replay without invocation, ambiguity/concurrency |
| DET-02 | Deadlines, health, late revisions, decision history (F4) | reconciliation.py | T01–T16; EVD-02 |
| DEM-01 | Replay/suppression/benign failure (R2-09–12) | cli.py, tests | repeatable local and deployed demo |
| RSP-01 | EventBridge/Step Functions, policy approval, verified revoke (F6) | response.py, infra | fail/unknown never successful |
| REC-01 | Rotation, clean deployment, synthetic recovery (F7) | response.py, docs/runbook.md | old fails/new succeeds |
| FOR-01 | Timeline, gaps, hashes, report (F7) | reporting.py | explicit provenance/uncertainty |
| EXP-01 | Four baselines and four ablations, independent labels (F9) | experiments, evaluation.py | held-out seeded trials |
| EXP-02 | Precision/recall/F1/FPR/inconclusive, latency, overhead/cost | evaluation.py | real denominators, no fabricated cloud metrics |
| OPS-01 | Fault contracts, rollback, budget, cleanup (F10) | docs/runbook.md, scripts | deployed rehearsal; cloud approval |
| RES-01 | Literature matrix, poster/report/video (final defense) | docs/research | verified sources and review artifacts; EXP-01 |
| OPT-01 | Optional real authorized provider (F8) | future adapter | explicit separate authorization |


## Verified implementation checkpoint

| Ticket | Actual implementation and proof | Status |
|---|---|---|
| ENG-01 | pyproject, exact locks, pinned/read-only CI; 59 passing tests, Ruff, strict mypy, SAM validate/build | Local foundation verified; remote CI pending |
| LAB-01/02 | provider.py and cloud_lab.py; test_provider_security_and_verified_response, test_issuer_and_provider_outbox, stream acknowledgement regression | Local/Moto verified; live provider pending |
| LAB-03 | cloud_lab.gateway/app, WorkloadApi, issuer and SaaS APIs | Packaged candidate; no deployed 200 response claimed |
| OBS-01 | JSON app logs, default platform logs and API access-log groups in template | Supplementary archive adapters and configured CloudTrail coverage pending KI-04 |
| EVD-01 | aws_handlers.collector, schema.py, schemas/evidence-v1.schema.json | Source spoof/unknown/oversize/content conflict tests pass; live IAM test pending |
| EVD-02/03 | partial SQS batches, S3-first conditional index, active TTL, newest health, exact-version export | Recovery/idempotency/tampering tests pass; live DLQ/retention/deny rehearsal pending |
| SEC-01 | own-function log policies, source-role-bound intake, workload archive denial, separate response key/role | Static/Moto checks; final cross-account authorization pending |
| DET-01/02 | reconciliation.py, transactional cloud history, health monitor and configurable policy | All five states tested; duplicates/retries, clock skew, late state revision, cross-run replay and invalid policy handled |
| DEM-01 | cli.py and scripts/cloud_demo.py; docs/results/demo | Three local demos verified; live AWS Review-2 not complete |
| RSP-01 | cloud_response.py, EventBridge/Step Functions, explicit approval output, response-key lookup | Mock-provider rejection, failed verification and idempotent evidence tested; live execution pending |
| REC-01 | local containment-recovery, integration disable/restore and clean-code runbook | Local verified; cloud recovery and modified-resource restore pending |
| FOR-01 | reporting.py and scripts/export_incident.py | Exact S3 version/hash checks tested; investigator export not yet exercised on AWS |
| EXP-01/02 | fifteen scenarios, eight detectors/ablations, seed manifest, separate labels, metrics and calibration functions | 30 local smoke runs measured; held-out AWS latency/overhead/cost are null/pending |
| OPS-01 | preflight.py, cleanup.py, failure-contracts and runbook | Read-only gates and explicit deletion flags implemented; deployment/rollback/cleanup unverified |
| RES-01/OPT-01 | Original references preserved; research protocol and explicit limitations | Novelty/literature comparison, final artifacts and optional real authorized provider remain unfinished |
