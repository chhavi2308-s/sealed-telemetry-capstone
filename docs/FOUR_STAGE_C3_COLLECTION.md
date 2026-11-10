# C3: authenticated collection, persistent quarantine and safe IBER admission

Implementation and offline tests only. No deployment, IAM or infrastructure change
is included. Existing C2 producers, shared Evidence schema and IBER reconciliation
algorithm remain unchanged. This is not a claim of live end-to-end AWS detection.

## Read-through collection and configuration

`four_stage_collection.Collector` accepts trusted `Configuration` and optional SDK
session dependencies, not producer-uploaded evidence or receipts. The new, unwired
`handler` accepts only `{"operation":"collect"}` or `{"operation":"reconcile"}`.
It reads `C3_COLLECTION_CONFIG` from trusted runtime configuration, never from the
invocation body. No existing Lambda/API handler or infrastructure template is rewired.

Configuration consists of an exact `collector_role_arn`, exact `state_table_arn`, a
list of source specifications and bounded `max_records`/`max_pages` limits. Each source
has `source_id`, `contract`, `table_arn` and primary `key`. Defaults are 1,000 records
and 20 pages. All resources must be in the same configured account, partition and
region. Cross-account collection is not implemented by this path.

| Contract/source | Required native key | Accepted records |
| --- | --- | --- |
| c2 / gateway | action_id | C2 gateway snapshots |
| c2 / issuer | issuance_id | Redacted issuance envelopes; validated claim rows are ignored |
| c2 / provider | provider_request_id | C2 provider audit receipts |
| iber-1 / gateway, app, provider, health | event_id | Explicit complete canonical records from separately configured flat event tables |

A configured contract must declare its entire source set: all three C2 tables and/or
all four canonical tables. Duplicate resource identities, duplicate source/contract
authorities, wildcard/non-table ARNs and a state/source table overlap are rejected.
The collector verifies STS caller account/session identity, the full configured IAM
role ARN and role ID through read-only IAM metadata, then each actual table ARN,
region, active status and exact single-string-hash-key schema through DescribeTable.
The private credential registry cannot be selected as issuer evidence: its schema
does not match `issuance_id`. Authentication failures happen before state is initialized.

The collector uses AWS-authorized, consistent source scans with bounded pagination.
The actual source resource is selected by configuration, not by a row's `source_id`.
A disagreeing producer label fails validation; it cannot change the authenticated
resource identity. Configuration is bound to the state table by a policy hash, so
changing the configured authorities or bounds cannot silently reuse previous state.

This authenticates the collector's access and the native resource it read. It does
not recover the principal that originally wrote an individual DynamoDB item or prove
that configured writer ownership is secure. Source-writer isolation and collector/state
permissions remain explicit deployment prerequisites. SDK dependency injection and
Python private methods are trusted-code interfaces, not a process security boundary.

## Strict, private-data-bounded normalization

`four_stage_c3_schema` accepts exact versioned C2 field sets, native identifiers,
integral DynamoDB Decimal timestamps, explicit UTC times, supported operations,
HMAC-shaped pseudonyms, fingerprint versions and consistent outcomes. Unknown fields,
private attestations/token IDs, bearer fields and lookup-hash fields are rejected.
Malformed records produce fixed diagnostics with no payload dumps or exception chains.
Accepted records are bounded to 16 KiB of canonical JSON.

Gateway snapshot hashes, native action keys and revisions are validated. Optional
gateway request IDs must be canonical UUIDv4 values under this strict format; unsupported
formats are quarantined rather than silently repurposed as application invocation IDs.
Issuer normalization accepts the redacted C1 field set only and validates authorization
references, issue/expiry times and request receipt time. It does not invent a private
token ID to invoke the private C1 parser or recompute an HMAC.

Known provider bindings require internally consistent version, algorithm, issuance,
actor/resource, lifetime and authorization-reference fields. Accepted and denied
outcomes remain distinct. Unknown or unverifiable credentials retain null binding
fields. Denial reasons must be internally consistent with their available metadata;
revocation remains a provider assertion, not an independently verified response action.

Source-provided original times remain unchanged. Collector receipt time is separate.
Normalizer UUIDs are deterministically derived from native resource/key identity and
are labeled as normalization identities, not newly observed producer events.

## Persistent deduplication, quarantine and history

The collector-private state table requires a string hash key `record_id`; code does
not create it. Conditional DynamoDB transactions coordinate a global revision,
source-namespaced current records and immutable safe-version histories. Exact redelivery
does not create another current event. A different or invalid version of an existing
native identity permanently quarantines that identity across later batches and
collector instances. Restoring the old source payload does not resurrect it.

Only already validated safe versions enter history. Invalid variants store metadata-only
diagnostics, not the rejected body or a hash of its private contents. Claims are not
treated as issuer events. Current acceptance means successful source collection and
schema validation; it is separate from cross-source binding consistency or IBER readiness.
Quarantine resolution requires a future explicit reviewed procedure; no automatic
clear, delete, TTL or source disappearance removes historical expectations.

Each assessment uses a revision-stable ledger view. Body hashes, policy binding and
receipt/source identity are rechecked and normalization is reproduced before use.
Changing the ledger during assessment prevents successful publication. Every stored
assessment carries its snapshot revision and content hash. `latest_assessment()`
must be used to consume it: it rejects stale revisions, altered bodies and observations
older than 130 seconds or from the future. A late conflict invalidates earlier ready
results without deleting assessment history. Directly reading an old raw ASSESSMENT
row is not a valid freshness check.

Source read failures retain previous observations but record an incomplete collection
attempt. Limits, concurrent changes or state integrity failures fail closed; no
partial scan prefix is reconciled as a complete view. The bounded state scan includes
history/control rows in its read cost even though it selects current records. History
growth can therefore require future indexed-storage/retention work and capacity review.

## Cross-source reference and binding verification

The readiness adapter checks issuer references against an independently collected
gateway resource/key, revision, snapshot hash, original authorization times and
operation/actor/resource fields. Known provider records must agree with an independently
collected issuer's fingerprint, version, algorithm, issuance identity, authorized
action/resource, credential times and complete authorization reference. Multiple
issuances claiming one gateway authorization remain ambiguous rather than creating
extra expectations. Requested and authorized action IDs are not conflated.

Late gateway/issuer/provider records can resolve a missing-reference status in a new
assessment. Old event times and previous assessments are retained. Cross-source
disagreement blocks admission; the adapter does not overwrite one independent source
with another. HMACs identify credentials, not attestation signatures: this comparison
does not cryptographically authenticate every authorization field or prove execution.

## What can enter the existing IBER engine

**Current C2 records cannot yet enter IBER.** Gateway snapshots still lack actual
application invocation identity and run/scenario context; provider records lack that
context and may have missing identity/resource fields. Supporting issuer envelopes
are not IBER detection events. These facts remain unknown, even when source references
and credential bindings are consistent. Successful scans never manufacture source
health. The adapter keeps the entire known incomplete set and submits zero events.

An explicit `iber-1` compatibility route supports complete independently collected
canonical Evidence, not enrichment of C2 fields. It requires the exact explicit
Evidence fields, UUID run context, `lab-v1` scenario, synthetic upload operation,
HMAC-shaped actor/resource/credential identity and no arbitrary trace payload.
Canonical source health uses the existing monitor's explicit metadata and preserves
actual healthy/unhealthy/unknown observations; incidental monitor sentinel fields
are not used as credential identities or synthesized by this adapter.

Health must come from the separately configured health event source and be fresh,
non-conflicting and not future-dated for gateway/provider/app/collector. A provider's
optional invocation ID may remain None: existing IBER fallback uncertainty is preserved.
Complete unmatched expectations remain in the input, including before late provider
arrival. A provider-only credential scope is blocked, even when unrelated expectations
exist. Any incomplete C2 evidence or quarantined record blocks a mixed ledger; the
adapter never silently drops it to admit a complete canonical subset.

The adapter calls the existing `reconciliation.reconcile()` unchanged only after all
gates pass. It neither alters detection rules nor claims a physical app execution.
The flat canonical route is not an automatic decoder for the existing SQS/S3 archive
envelopes or indexed Events-table wrapper; connecting those interfaces needs its own
explicit mapping and source-ownership review.

All results say `coverage_complete=false` and describe only the observed ledger view.
A completed DynamoDB scan is not an atomic cross-source snapshot, a watermark proving
all events were delivered, or proof of global coverage. Source availability is not
completeness. No automatic response/containment behavior is introduced.

## Remaining deployment requirements

Future approval must cover the collector Lambda/entrypoint and trusted configuration,
exact native sources and ownership, read-only STS/IAM role metadata checks, source
DescribeTable/consistent Scan access, private conditional/transactional state access,
state capacity/indexing, encryption, retention, alarms and rollback/quiescence plans.
No source table, state table, role, queue, API route or secret is provisioned here.
Existing templates and permissions are unmodified.

Live tests must independently verify writer isolation, denied collector identities,
source access denial, delivery gaps, latency and historical conflict handling before
claiming AWS integration. Missing C2 app execution/context and independent health
telemetry must be produced and authenticated before safe C2-to-IBER conversion can be
enabled. No value should be generated merely to satisfy `Evidence.parse()`.
