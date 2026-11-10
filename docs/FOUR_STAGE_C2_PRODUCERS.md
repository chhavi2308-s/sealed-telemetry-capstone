# C2: four-stage issuer and provider evidence producers

Status: implementation and offline testing only. No AWS deployment, IAM change or
infrastructure edit accompanies this code. IBER algorithms, shared Evidence schema,
Phase B parser and C1 fingerprint contract remain unchanged.

## Explicit compatibility and rollout boundary

The existing handlers delegate to `four_stage_binding.py` only when
`FOUR_STAGE_EVIDENCE_MODE=c2`. The default `legacy` path remains compatible with the
current four-stage deployment and local showcase. An unsupported mode fails rather
than silently falling back. C2 mode is not wired into the existing SAM template.
Code must not be deployed or enabled until configuration, keys, source ownership and
permissions have been separately reviewed and approved. No automatic migration occurs.
All four handlers must use a consistent mode. The C2 app requires C2 response-contract
markers from issuer and provider and fails unavailable on a missing/different marker;
markers detect configuration mismatch, not source authenticity. Invalid app mode is
rejected before intent emission or service invocation.

Future C2 configuration references, not secret values:

- `FOUR_STAGE_IDENTITY_SECRET`: Secrets Manager JSON with `key_version`, base64
  `key_b64` (at least 32 bytes) and an independently configured OAuth `subject`.
  Gateway and issuer use domain-separated HMAC inputs for OAuth subject, synthetic
  resource and authorizing IAM principal. These are distinct identity meanings.
- `FOUR_STAGE_CREDENTIAL_SECRET`: issuer-only Secrets Manager JSON with `active_version`
  and `keys`, mapping explicit versions to base64 keys of at least 32 bytes. Only
  the active version is selected; missing/invalid configuration fails closed.
- `EXPECTED_TABLE`, `TOKEN_TABLE`, `AUDIT_TABLE`: existing table interfaces.
- `ISSUANCE_TABLE`: separately controlled issuer evidence table interface with string
  hash key `issuance_id`. It is logically distinct from the other three tables.

These interfaces exist in code/Moto only; no new table or secret was provisioned.
No key material is stored in environment variables, records, reports or source code.
Test vectors and fixture keys remain public synthetic data, never production secrets.

## Durable gateway authorization

Before invoking the app, the gateway stores its independently generated action ID,
original authorization and expiry seconds, synthetic operation/resource, C2 source and
contract labels, revision UUID, OAuth subject/resource pseudonyms, authorizing-principal
pseudonym and identity-key version. Optional `gateway_request_id` comes from actual
gateway Lambda context; it is not an application execution ID. A canonical snapshot
hash covers the stored authorization fields. The hash is an integrity reference,
not a source signature. These additional internal fields are not returned to the app
or public API response. Old authorizations are not backfilled using app claims.

The issuer reads the expected row consistently, validates its C2 source/contract,
revision, content hash, operation, resource, time window and configured identity binding.
Application-supplied actor, fingerprint, key version and timing fields cannot replace
the independent row. The configured OAuth subject is separate from the authenticated
IAM principal that authorized it. Identity-key rotation that makes an old snapshot
unverifiable fails closed; identity-key lifecycle migration is not implemented here.

## Atomic issuance and duplicate policy

The issuer generates a private token UUID and issuance UUID and computes the C1
HMAC-SHA256 fingerprint using the selected credential key. It verifies the private
attestation before persistence. The bearer stays transient except for its private
SHA-256 lookup hash; raw bearers are never persisted.
Issuance time is sampled after key loading, while request receipt and original gateway
authorization times remain separate. The provider likewise resamples its clock after
the lookup before accepting an operation, preserving its original request receipt time.

One DynamoDB transaction:

1. Condition-checks every observed authorization snapshot field and its hash, guarding
   against a change between the independent read and the write. It resamples the issuer
   clock immediately before the transaction, checks the window again and rejects a
   backwards sample. DynamoDB has no server-clock condition here: network delay is
   not a real-time guarantee. The provider independently checks expiry at use time.
2. Conditionally writes the private registry row, including the private C1 attestation,
   lookup hash, authorized scope/audience, expiry and authorization reference.
3. Conditionally writes an issuer-owned redacted evidence envelope, containing
   `to_evidence_dict()`, exact gateway table ARN/native ID, revision, snapshot hash and
   original authorization times. Private token ID and lookup hash are absent.
4. Conditionally writes a per-authorization claim in the same issuer table. Claim
   rows use `authorization:<action_id>` and `record_kind=issuance_claim`; they are not
   evidence events. Evidence rows use UUID keys and `record_kind=issuance_evidence`.

**Explicit policy:** one persisted credential issuance per synthetic authorization.
This prevents retries from minting multiple independently usable credentials for the
one authorized upload. An identical duplicate yields `issuance_already_recorded` with
no bearer; a conflicting claim yields `issuance_conflict`. A new issuance needs a new
gateway authorization. The application never chooses the claim or issuance identity.
This is a C2 issuer policy, not a change to IBER's one-use reconciliation semantics.
Repeated gateway API requests still create distinct authorizations; distinct provider
calls still create distinct receipts. End-to-end HTTP/provider request idempotency
has not been introduced or claimed by the issuance guard.

Transaction requests disable automatic SDK retries and use the issuance UUID as the
DynamoDB client request token. Cancellation rolls back all writes. Transport errors
yield `issuance_outcome_unknown`: a timeout may occur after commit. No bearer is
returned and no compensating delete or replacement issuance is attempted. The durable
claim makes a subsequent request discover an already recorded issuance. This does
not restore a lost bearer or claim that a timed-out transaction failed.

Issuer envelopes deliberately have no TTL in this implementation; claim/registry
retention must be reviewed together before rollout. Expiring a registry entry must
not erase issuance evidence or permit unsafe duplicate replay. No cleanup, redrive
or collection mechanism is configured by this change.

## Provider lookup and evidence

The SaaS handler resolves the presented bearer through its own consistent private
registry lookup. It validates the stored C1 record, registry metadata and bounded
authorization reference before recording its fingerprint, algorithm, key version,
issuance ID, credential issue/expiry times and authorization reference. It does not
read HMAC secrets. It trusts issuer-owned registry integrity, not app-provided headers
or fields. Fingerprint agreement alone does not authenticate the issuer record.

Unknown/malformed or unverifiable legacy/corrupt credentials produce denied records
with null binding fields, never a zero or shared placeholder fingerprint. A known
expired/revoked/mismatched credential retains its observed binding with a denied
outcome and a bounded reason. Requested action IDs and authorized action IDs remain
separate. Unrecognized operations/resources are represented as missing with mismatch
reasons, not copied as hostile free text or rewritten to authorized values.
Missing or non-Boolean revocation metadata is an unverifiable registry record, not
evidence that a revocation occurred. A backwards provider clock returns unavailable.

Each real provider call creates an independent request ID and audit receipt. Replaying
one valid bearer can therefore produce several distinct successful receipts; these
are observations, not claims of theft. Audit failure returns unavailable, never
success. App and gateway handlers preserve operation failure rather than claiming
an unavailable evidence operation succeeded. No private payload or SDK error is logged
or returned. Only fixed diagnostic codes cross handler boundaries.

## Provenance, uncertainty and remaining collector work

Producer `source_id` fields and hashes are claims until collection authenticates the
exact source/table or signing principal and verifies its permissions. Current deployed
permissions have not been verified or changed. Issuer-private registry serialization
must never be used as an evidence export. Only issuer evidence-kind rows and provider
audit rows are candidates for authenticated collection, under a new versioned route.

C2 receipts contain no invented application invocation ID, app intent or source-health
assertion. A stable credential binding cannot prove an app execution or attacker
identity. Phase B v1 rejects these new rows rather than silently upgrading them to
complete IBER Evidence. C2 does not call or modify the IBER reconciliation engine.

Remaining work: authenticate issuer/provider collection, define a strict C2 envelope
normalizer and persistent duplicate/conflict handling, verify gateway/issuer references,
and gate conversion on real actor/context/invocation and source-health evidence. Do
not drop incomplete expectations while feeding a provider-only subset to IBER and
claiming complete coverage. Preserve late revisions and replay/benign-retry ambiguity.

Future permission review must cover gateway/issuer identity-secret reads, issuer-only
credential-secret reads, expected-row consistent read and transaction condition check,
expected-table ARN discovery, private registry and issuer-table conditional transaction
writes/claim reads, and provider registry reads/audit writes. No wildcard grants,
role edits or template changes are made here; the actual least-privilege diff and
retention/rollback plan must be reviewed before any deployment approval.
