# Phase C1: offline issuer attestation contract

**Status:** Offline design and tests only. No AWS producer, IAM, collection or deployed
resource has been changed. This contract is not evidence that issuance was observed.

## Scope and trust

`four_stage_issuance.py` specifies a strict, versioned, private issuer record.
Only a separately authenticated issuer collector may accept it. A producer-supplied
`source_id`, an application claim, or a syntactically valid attestation is not proof
of issuer provenance. Phase C2 must define atomic persistence with the private
credential registry and independent writer permissions.

Fields: `issuance_id` (UUID), `token_id` (private issuer-generated UUID), `action_id`
(UUID), `authorization_native_id`, `actor_pseudonym`, `operation`,
`resource_pseudonym`, UTC `issued_at_utc` and `expires_at_utc`,
`credential_fingerprint`, `fingerprint_key_version`, and explicit contract and
algorithm versions. The attestation must not be logged or placed in public reports
with `token_id`. No bearer value, SHA-256 lookup hash, or HMAC key is part of the
contract. The existing legacy four-stage rows do not satisfy this contract.

## Strict parsing and privacy boundary

Construction validates immediately. `IssuanceAttestation.parse()` accepts at most
16 KiB of canonical private-record JSON and requires every field, including explicit
contract and algorithm versions. Unknown or missing fields are rejected. It never
substitutes defaults for missing persisted facts. Rejections suppress input values
and chained parser exceptions that could disclose private values.

Issuance, token and action IDs must be distinct canonical lowercase UUIDv4 values.
The gateway's existing table is keyed by action ID, so `authorization_native_id`
must equal that action ID. This checks reference consistency, not row existence.
Actor and resource pseudonyms must have lowercase 64-hex HMAC shape; shared zero
placeholders and raw principal/resource names are rejected. Shape alone does not
prove pseudonym derivation. This version supports only `files:upload`. Times must
be explicit UTC, with expiry strictly later than issuance.

`repr(record)` and `str(record)` hide every field. `to_evidence_dict()` is the
explicit redacted projection for independently authenticated collection and omits
`token_id`. That projection cannot reconstruct the private record and is not complete
IBER `Evidence`. Generic `dataclasses.asdict()`, pickling and direct attributes still
contain private material: use them only inside the private issuer/verification
boundary, never as a logging or reporting interface. Even pseudonymous evidence
needs controlled access and retention; it is not an unrestricted public report.

## Fingerprint construction

`HMAC-SHA256(key_for_version, UTF8(token_id))`, represented as 64 lowercase hex
characters. The key version is a trusted selector of an independently managed
256-bit-or-greater key, not part of the HMAC message. The issuer's `token_id` is
private and not the bearer, `action_id`, SHA-256 token lookup hash, or app-provided
identifier. The provider must independently obtain the token ID from its own
successful bearer lookup before computing the same fingerprint. It must never
trust an app-provided fingerprint. C2 can instead copy the immutable issuer-stored
fingerprint/version from the provider's own trusted bearer lookup, as the broader
cloud lab already does, without granting the provider access to the HMAC secret.
Unknown credentials remain unbound.

Test vectors use **public, synthetic test keys only**. Never deploy them as real
HMAC secrets. The vectors are stable fixtures for deterministic cross-component
implementation; they do not prove that two components independently observed a
credential.

| Version | Test key (hex) | Token ID | Expected HMAC-SHA256 |
| --- | --- | --- | --- |
| v1 | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` | `11111111-1111-4111-8111-111111111111` | `37bb64cdc05bfac138ca1f21dd669b0403e2b83fccd5ae38be3a4a7922ef1964` |
| v2 | `202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f` | `11111111-1111-4111-8111-111111111111` | `f6bb11b62d0a672e6b437bbfb729f48bea8c257c5a0ea37456e0aa6ef80a818b` |

Key rotation: each version maps to exactly one key. Verification fails for unknown
versions; it must not silently try a different version. Existing attestations retain
their original version. Retention and revocation of old verification keys need a
separately approved lifecycle policy. The module checks attestation structure and
fingerprint agreement, **not** authorization existence, uniqueness, source
attestation, clock trust, atomicity, or complete evidence provenance.

The implementation reuses `schema.pseudonym()` so its vectors agree with the existing
IBER laboratory. A version label does not cryptographically alter the HMAC message.
Reusing identical key bytes under a different label yields the same fingerprint;
independent key management and authenticated version metadata are prerequisites.

Verification recomputes the fingerprint from the private token ID under exactly the
selected key, with constant-time comparison and no fallback. An ordinary SHA-256
lookup hash or a fingerprint derived from the action ID does not pass that check.
However, UUID syntax cannot prove that an ID was generated by an issuer rather than
supplied by an app. Only C2's independently read registry/provenance can establish
that fact. In particular, the HMAC does **not** cover the action, authorization,
resource or timing fields: changing those fields can leave fingerprint verification
true. Fingerprint agreement is not a signature on the attestation or authorization
to act. This limitation has an explicit regression test.

## C2/C3 acceptance gates

1. Independently verify the gateway authorization before issuing; preserve its
   native reference and original timestamp.
2. Atomically commit issuance attestation with the private credential registry,
   or fail issuance; define idempotency and conflict handling.
3. Provider independently looks up the bearer, retrieves the private token ID,
   and writes its own fingerprint and key version with the audit receipt.
4. Keep unknown credentials explicitly unbound. A known credential denied for expiry
   or scope may retain its lookup-observed identity with an explicit denied outcome.
   Denial never establishes a successful action. Never backfill missing identity using
   `action_id`, app headers, or token hashes.
5. Protect token IDs and HMAC keys from logs, reports and application-controlled
   surfaces. Authenticate source ownership and persist deduplication across batches.
6. Do not infer application execution from issuance or provider credential binding;
   IBER invocation correlation and source-health uncertainty remain separate.
