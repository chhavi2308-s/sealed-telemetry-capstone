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
