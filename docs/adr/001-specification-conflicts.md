# ADR 001 Specification conflicts and safe implementation baseline

Accepted for local implementation, 26 October 2026.

Final blueprint is a superset of master and Review-2 plans. Earlier schema uses source_type/trust_tier variants, event_payload_hash and classification; final uses source_id, canonical_hash and state. Use versioned final names, retain raw original input and collector receipt separately; source trust is assigned by authenticated ingress, never self-reported.

State aliases CORROBORATED and CORROBORATED_SUSPECTED_ABUSE map to the latter. SUSPICIOUS_TELEMETRY_GAP is a reason under INCONCLUSIVE, not confirmed abuse. Diagram's missing-evidence suspicious branch is conservative: absence alone remains inconclusive. REVISED is a new decision version, not a sixth state.

Intent is an untrusted claim, not authorization. Add independent gateway-issued expected-action records in the controlled lab. A matched intent alone cannot establish consistent authorization. Without an independently issued expectation, unmatched provider activity is suspicious at most. Missing invocation IDs do not prove replay. Never use scenario labels as detector evidence.

Use opaque disposable tokens and a transactional provider outbox. Locally SQLite emulates durability only; it does not provide AWS IAM isolation or WORM storage. AWS adapters and tests must not inherit claims of local trust separation.

Review-2 profile permits separate roles in one sandbox; final separate accounts remain pending authorization. No account, region, budget, retention or paid deployment has been approved. No deployment executed.

Use per-record hash receipts first; do not claim a global chain across concurrent consumers. Governed S3 version retention preserves versions; manifests must identify versions. Deadlines are configurable provisional lab values until independently calibrated.
