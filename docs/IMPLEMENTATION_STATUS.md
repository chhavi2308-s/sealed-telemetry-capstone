# Implementation status

26 October 2026. Working branch: `implementation/engineering-foundation`. Baseline: dd3d212. The original repository had three DOCX plans, a PDF, Mermaid architecture and a decision-tree PNG; no source, tests, CI or infrastructure. Original source assets are unchanged and their SHA-256 hashes are recorded in docs/specifications/manifest.json. Full DOCX text was extracted before code changes. No separate Codex instructions or original Review-1 slide deck was present.

**This is a working local system and a validated/buildable AWS deployment candidate. The full capstone and AWS Review-2 acceptance are not complete. No AWS stack has been deployed, paid resources created, account-wide IAM changed, or GitHub branch pushed.**

| Milestone | Implemented and verified | Remaining gate |
|---|---|---|
| M0 foundation | Python package, exact dependency snapshots, lint/format, strict typing, pinned/read-only CI, fault/security tests, SAM validation and local package build | Remote CI execution and approved account preflight/deployment |
| M1 Review-2 | Disposable scoped tokens; synthetic provider with durable audit outbox; trusted expected-action gateway; app-log suppression; replay without invocation IDs; benign fault and delay demo; cloud HTTPS/SigV4 adapters | Live AWS proof, role-denial tests, timestamps, screenshots/video and teammate rehearsal |
| M2 evidence | Source-bound intake, strict schema/size validation, stable intake receipt, raw/normalized/hash metadata, SQS/DLQ, S3-first/index-second idempotency, retained versions, KMS, transient active/health indexes, independent operational health | Live retention/IAM/KMS failure/stream-expiry and redrive rehearsal; multi-account profile |
| M3 IBER | All five states, bounded matching across research run IDs, configurable per-source deadlines, health freshness, late revision history, concurrency transaction, integrity failure uncertainty | Calibrate with measured benign deliveries; characterize scale bounds and provider coverage |
| M4 response/forensics | Gated EventBridge/Step Functions template; encrypted-token responder; real mock-provider rejection check; optional integration disable; idempotent receipts; local revocation/rotation/recovery; version-pinned cloud report exporter | Live workflow/recovery/rollback and operator approval rehearsal |
| M5 research | Fifteen reproducible local scenarios; four detector baselines plus four ablations; independent labels; counts, rates, Wilson intervals, reconstruction and measured local harness duration; calibration utility | Held-out AWS experiments, detection/response latency, overhead, billed cost, literature comparison and final defense artifacts |

Verification artifacts are in docs/results and experiments/results/local-smoke. The final test suite passes with no skipped tests. Lint, formatting, strict typing and SAM validation pass. SAM packaging uses a hash-verified short staging path on Windows because long-path cached builds fail; see runbook. Dependencies were audited against OSV with no known vulnerabilities reported. GitHub Actions has not run remotely.

Critical path now: owner supplies approved sandbox parameters → read-only preflight and reviewed change set → deploy and IAM negative tests → live Review-2 traces → calibration/held-out evaluation → final hardening and handover. No planning target is reported as an experimental result.
