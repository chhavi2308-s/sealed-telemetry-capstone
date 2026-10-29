# Architecture decisions

- ADR 001: final-blueprint schema names, untrusted application claims, mock opaque tokens, per-record receipts, one-account Review-2 versus final separate-account authorization.
- ADR 002: preserve uncertainty for retries, require independent corroboration, restrict logs, protect token material in response, separate transient operational state and retain forensic history.

These are implementation decisions and documented deviations/backlog, not approval of cloud spending or a claim of final capstone completion. The original target Mermaid is retained in docs/architecture/final.mmd; infra/template.yaml describes the actual deployment candidate. ADR 003 implements supplementary ingestion, two-account templates and action-bound callbacks offline; live operation remains pending.

- ADR 003: source-isolated queues, version-pinned supplementary metadata, final two-account profile and expiring operator approval; see docs/adr/003-isolation-telemetry-approval.md.
