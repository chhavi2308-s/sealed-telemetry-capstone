# Four-stage evidence integration contract, version 1

Phase B is an **offline normalization boundary** for records already produced by
`four_stage.py`. It does not connect the deployed demonstration to the cloud detector.
It preserves partial observations and refuses to manufacture complete IBER `Evidence`.
The existing strict schema and reconciliation rules remain unchanged.

Baseline reviewed: `3c2f38998c13c2087913ee03a500b6f45773dcf3`, branch
`feature/aws-iber-integration`. The owner reports a four-stage deployment in account
`011237053677`, region `ap-south-1`; this work does not independently verify it.

## What the existing records establish

| Producer / independently read source | Observed fields used | Trust and limits |
| --- | --- | --- |
| Authorization / ExpectedActions table | action ID, operation, filename, authorization and expiry seconds | Trusted authorization only within the lab's independently enforced writer permissions. Does not record caller identity, a credential fingerprint, or the app invocation ID. |
| App / exact CloudWatch log stream | APP_INTENT event ID, action ID, operation, filename, recorded seconds, optional invocation ID | Application claim. Reading an authentic log stream does not make its message true or prove the action was performed. |
| SaaS / SaasAudit table | request ID, claimed action ID, operation, filename, outcome, recorded seconds, synthetic marker | Independent synthetic provider receipt. The action ID comes from the request. The receipt does not identify which credential was presented, even on success. |
| Issuer / OAuthTokens table | SHA-256 token lookup hash, action ID, scope, filename, audience, expiry | Establishes an issuer-side lookup relation, but no provider receipt links back to that token row. Multiple credentials can be issued for one action. This table is intentionally excluded from normalization and reports. |

The normalizer does not join by action ID to supply missing credential, actor or
invocation identities. Successful validation by the provider is evidence of the
provider's acceptance, not evidence identifying a particular token in a later export.

## Offline API and provenance boundary

`sealed_telemetry.four_stage_evidence.normalize(records, source_resources)` accepts
`CollectedRecord` objects with producer payload and separate collector-owned metadata:

- `resource_arn`: an exact DynamoDB table ARN or exact CloudWatch log-stream ARN.
- `native_id`: the table primary-key value or CloudWatch log-event ID, not the app's
  self-reported event ID. A real log export must retain this ID and stream identity.
- `collected_at_utc`: UTC collection time, kept separate from producer event time.
- `payload`: a decoded DynamoDB resource row or decoded APP_INTENT JSON object.

`source_resources` is a trusted exact ARN-to-source allowlist established outside the
payload. Wildcards, source/type mismatches, stream ARNs in place of table ARNs, and
unknown producer fields are rejected. New producer formats need a reviewed contract
version; an arbitrary `credential_fingerprint` field is not accepted as an upgrade.
Raw Lambda log text and low-level DynamoDB AttributeValue JSON must be decoded by a
future collector before using this API.

**This function cannot authenticate an offline file.** Its caller must establish
authenticated collection and independently controlled source permissions. Fixture
ARNs in tests are synthetic. An ARN supplied by an app is not provenance. A canonical
payload hash detects content differences; it is not a signature, an immutable archive,
or proof that a collector/source is uncompromised. No source-health or completeness
assertions are inferred from the presence or absence of records.

The output is `NormalizationResult`: partial `FourStageObservation` values and
metadata-only rejection diagnostics. Each observation carries:

- A deterministic UUIDv5 derived from `[resource_arn, native_id]`, explicitly a
  **normalizer identity**, not a newly observed producer ID. The original app event ID
  is preserved separately as `producer_event_id` and cannot block provider records.
- Source, event type (`APP_INTENT` maps to `INTENT_CREATED`), event time converted
  losslessly from integral Unix seconds to UTC, optional observed invocation/request
  IDs, and a separate authorization expiry when present.
- `resource_name`, retaining the existing synthetic filename. It is not represented
  as a pseudonym. Future support for real resources requires reviewed pseudonymization.
- Source resource/native ID, collection time, canonical payload hash, normalization
  version, and trust tier. App invocation IDs remain app claims.

`unknown`, which the provider currently writes for missing action/operation/filename,
maps to `None` only in provider records. Missing credential and actor identity remain
`None`. Gateway expectations and app intent do not gain a synthetic success outcome;
provider success and denial remain separate observed outcomes. No bearer token, token
lookup hash, payload dump or arbitrary exception text is exported in diagnostics.

The adapter accepts integral DynamoDB `Decimal` values without float conversion,
rejects malformed timestamps rather than substituting collection time, and limits
batches to 1,000 records and canonical payloads to 16 KiB. Exact duplicate deliveries
collapse within a batch. Conflicting versions of the same native identity, including
invalid variants, are withheld for the remainder of that batch. This is not persistent
cross-batch replay detection; future intake must retain native IDs and hashes.

## Credential-to-action binding rule

The existing records do **not** support this binding end to end. Consequently every
current observation reports `missing_iber_fields`, including actor identity and
credential fingerprint. `to_evidence()` fails with
`FOUR_STAGE_IBER_CONTRACT_INCOMPLETE`. It is not passed to `reconcile()` or the cloud
collector. Empty output is not a clean bill of health, and a normalization diagnostic
is not an IBER abuse finding. Existing `four_stage_analysis.analyze()` remains a
separate, limited action-level analyzer with different categories.

Before a future producer contract can emit complete IBER evidence, it must establish:

1. **Independent issuance attestation:** the issuer validates a durable gateway
   authorization, then records a binding between the exact credential and that action,
   scoped operation/resource, issuance ID, issue/expiry times and pseudonymized identity.
   Use a versioned, independently managed HMAC key and one defined fingerprint input
   representation. Never relabel a plain token SHA-256 lookup hash or action-ID hash as
   an HMAC fingerprint. Old exports cannot recover an HMAC of a missing bearer value.
2. **Observed credential identity at use:** the provider computes/records the same
   fingerprint from the credential it actually validated. An action ID or fingerprint
   supplied by the application cannot be promoted to provider attestation. Denied
   unknown credentials must remain explicitly unbound.
3. **Trusted expectation enrichment:** a separately controlled join verifies the
   issuance attestation against the original authorization, preserves both references
   and original event times, and rejects conflicting or multiple ambiguous bindings.
   It cannot simply copy provider/app fields back into the authorization. An issuer
   attestation does not itself authorize an extra operation or a retry.
4. **Explicit invocation semantics:** the gateway's request ID, the app's Lambda
   request ID, and a request-supplied action ID are different things. Current gateway
   and provider records cannot be populated with the app's ID after the fact. Any
   future exact-execution binding needs an independently evidenced protocol. Otherwise
   preserve a missing provider invocation ID and the engine's bounded-fallback or
   ambiguous result; do not manufacture a high-confidence exact match.
5. **Independent collection and health:** source-bound transport, receipt integrity,
   durable deduplication, authenticated health observations and bounded delivery
   watermarks must be verified independently. Experiment run/scenario labels can be
   supplied by a trusted harness, but cannot authorize activity or hide replays.

These are producer requirements for the next phase, not attestations accepted by this
legacy adapter. The existing `Evidence` parser checks shape, not cryptographic origin;
passing schema validation alone would not satisfy this contract.

## Offline acceptance and remaining work

`tests/test_four_stage_evidence.py` exercises actual in-memory four-stage handler output,
real APP_INTENT log formatting, suppression, successful replay versus denied attempts,
duplicate/conflicting deliveries, malformed records, Decimal timestamps, source
spoofing, redaction, native-ID isolation, late collection and fail-closed IBER conversion.
Existing reconciliation tests retain the distinction between missing telemetry,
unmatched activity and observationally indistinguishable replay/benign retry.

Five pre-existing strict typing errors in `four_stage.py` and `four_stage_analysis.py`
are corrected with annotations and a typed local variable; handler behavior is unchanged.

No live AWS reads, handler logic changes, IAM/template changes, deployment, token extraction,
GitHub push or merge are part of Phase B. Next work is a separately reviewable producer
binding design and offline producer tests, followed by a reviewed collection/infrastructure
diff. Cloud execution still requires the owner's approval.
