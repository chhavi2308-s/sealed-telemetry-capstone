# C4 source-owned context and AWS compatibility

Code/offline tests only. No deployment, infrastructure changes, IAM changes or live
verification is included. The existing IBER algorithm and Evidence schema are unchanged.

## Opt-in producer contract

Set `FOUR_STAGE_CONTEXT_MODE=c4` alongside `FOUR_STAGE_EVIDENCE_MODE=c2` only after
the Phase D resource/permission/configuration review. Disabled mode preserves the
existing producer path. New handlers are not wired into any template.

`four_stage_context.py` records immutable `four-stage-context-4` observations:

| Resource | Key | Writer / records |
| --- | --- | --- |
| C4_GATEWAY_TABLE | record_id (S) | Gateway: authorization context and synchronous dispatch observation |
| C4_APP_TABLE | record_id (S) | Application: intent and credential observation, separate immutable phases |
| C4_PROVIDER_TABLE | provider_request_id (S) | Provider: one-use context request claims and post-audit context observations |
| C4_HEALTH_TABLE | event_id (S) | Separate monitor: independently observed operational health |

The gateway assigns a real run ID to each authorized synthetic upload and records
the fixed `lab-v1` scenario. These are run context, never substitutes for invocation
identity. Its context separates API Gateway's requestContext.requestId (nullable)
from the authorization Lambda's context.aws_request_id. C4 no longer populates the
legacy C2 field named gateway_request_id with a Lambda invocation ID.

The app obtains its actual invocation ID exclusively from Lambda runtime context.
It validates the durable authorization and gateway-owned run context, writes intent
before issuing or acting, reads independently persisted issuer evidence and writes
a separate credential observation before calling the provider. Missing context,
failed intent persistence or missing runtime IDs never produce replacement IDs.
No intent is inferred from issuance. A retry has a distinct runtime invocation ID;
the issuer's existing per-authorization single-issuance rule is preserved.

Application intent remains source-owned and untrusted in the IBER sense. It is not
an independent claim that the application physically executed a provider action.

## Request provenance and replay

A supplied app ID is only a lookup locator. The application signs a domain-separated
HMAC-SHA256 context over its source-owned invocation/action/issuance/fingerprint,
logical context request UUID, key version and observation timestamp. The dedicated
`C4_CONTEXT_SECRET` is separate from identity and credential fingerprint secrets:

    {"active_version":"vN","keys":{"vN":"<base64 of at least 32 private bytes>"}}

Use independently generated keys. Retain previous verification versions for the
approved overlap; do not print values. The provider loads the configured keyring,
checks the signature and request scope against the durable binding, enforces a
60-second context age, then conditionally reserves a one-use request claim before
calling the C2 provider path. A replay cannot create a second action with that claim.
Indeterminate persistence is not retried automatically. An orphan claim stays
incomplete; it does not prove an action happened.

After its own C2 bearer lookup/audit, the provider checks the credential fingerprint,
version, issuance and authorized action against the app records. Only matching signed
context gets a verified app reference. The provider's own Lambda invocation ID and
its independent provider request ID remain separate fields. Unknown credentials,
bad/missing signatures and mismatches remain unbound; their genuine provider audit
records are retained. A bearer token or ordinary lookup hash never supplies an app ID.

Context signatures and bearer payloads are private invocation material; they are not
stored in exported evidence or logs. Runtime/source isolation and key distribution
must be independently verified at deployment. A stolen signed envelope can still be
raced within its one-use window; shared verifier-key compromise is outside this
evidence guarantee. No physical execution or attacker identity is asserted.

## Independently observed health

`four_stage_health.handler` accepts only an empty request and uses trusted
`C4_HEALTH_FUNCTIONS` configuration (gateway/app/provider/collector to exact unqualified
function ARNs), not caller-supplied statuses. It uses a separate monitor execution role.

For each source it records exact function identity, Lambda State/LastUpdateStatus and
the original AWS/Lambda Invocations, Errors and Throttles Sum datapoints. It starts
unknown. Healthy requires Active/Successful and explicit aligned fresh metrics with
positive invocations and zero errors/throttles. Missing datapoints are not filled
with zero. AWS read failures emit sanitized unknown observations. Missing metadata,
stale/future/misaligned datapoints and idle windows stay unknown. Positive errors or
throttles and observed non-ready function state produce unhealthy observations.

This is operational runtime-window availability, not a delivery-completeness or
end-to-end pipeline-health proof. CloudWatch metrics can be delayed or sparse; the
conservative policy may block low-traffic lab admission. Do not relax it by assuming
success. No probes are generated to manufacture healthy activity.

The collector independently configures the expected four function ARNs in
`Configuration.health_functions`; a producer's function_arn is not authentication.
At admission, both observation time and original metric time must still be fresh.
Missing, unhealthy, stale or contradictory health blocks submission. Old health
observations remain in history and are not refreshed by repeated collection.

## C3 extension and admission

Use the three existing C2 sources plus four `c4` source entries:

    Source("gateway", "c4", "<gateway context table ARN>", "record_id")
    Source("app", "c4", "<application table ARN>", "record_id")
    Source("provider", "c4", "<provider context table ARN>", "provider_request_id")
    Source("health", "c4", "<health table ARN>", "event_id")

Source ownership, IAM role identity checks, bounded reads, policy-bound state,
cross-batch deduplication, sticky quarantine and revision-bound assessments remain
the C3 mechanisms. Configure a new ledger for the changed source policy; old C3 state
must not be silently reused under a different policy hash.

The C4 adapter checks original gateway snapshots, issuer/provider bindings, gateway
dispatch versus actual app observation, run context, hashes, one-use provider claims,
key versions and temporal order. It emits only complete synthetic upload events,
retaining original event times. The canonical gateway invocation field is a documented
cross-source join to the app runtime observation, not a claim that gateway generated
or independently observed the app runtime ID. Every emitted event has an admission
manifest listing its source records. Evidence itself does not receive fabricated
trace fields or receipt fields just to satisfy Evidence.parse().

All non-health supporting records must participate. Missing intents, retries with
ambiguous intents, unknown credentials, orphan claims, absent dispatch observations,
late/unmatched evidence or tampering block the entire ledger rather than allowing
a convenient subset. Complete unmatched gateway/app evidence can remain PENDING
until provider records arrive. Delayed records are retained for the next assessment.
These deliberately conservative gates can prevent detection of an unsupported
scenario; they do not alter IBER rules to hide it.

Offline complete C4 fixtures can enter the existing engine. Deployment is not ready
until Phase D approval, resource isolation, configuration and independent live checks.
All results keep coverage_complete=false and application_execution_proven=false.

## Explicit legacy AWS mappings

`four_stage_archive.py` implements separate mappings:

- `aws-events-table-1`: exact indexed Events row and embedded collector envelope;
- `aws-sqs-envelope-1`: configured SQS route plus original collector envelope;
- `aws-s3-envelope-1`: exact-version S3 read using ExpectedBucketOwner, with no fallback
  to latest or unversioned objects.

They validate raw-body/canonical/normalized hash agreement, explicit version strings,
receipt ID, configured principal-to-source mapping, source/event IDs and archive
path/index consistency. Hash agreement is integrity checking, not authentication.
The collector-owned resource and isolated writer are the trust boundary. Calling a
pure decoder with arbitrary JSON does not authenticate an SQS trigger or source.

For persistent collection, use a separate ledger configured with one
`Source("archive", "aws-events-1", "<Events table ARN>", "event_id")` and four explicit
`archive_roles` mappings (gateway/app/provider/health to exact IAM role ARNs). The
collector verifies role metadata and exact table identity before scanning; native
source:event keys persist conflicts across collection batches. Different archive
resources/policies must not share a ledger. Source-role receipt claims are trusted
only within the independently secured legacy collector/archive writer boundary.

SQS and S3 mappers are explicit compatibility APIs, not newly deployed triggers or
an alternate public ingestion route. They do not bypass persistent collection gates.
The Events mapping is the wired durable collector path; standalone S3/SQS decoding
does not directly submit to IBER or claim complete cross-batch ingestion.

Existing legacy events with arbitrary traces, non-HMAC identities or unsupported
operations are rejected/quarantined, not silently rewritten. Legacy SOURCE_HEALTH
events do not carry independent observation details: they remain retained but cannot
establish C4 health or make archive admission ready. Bridging those health observations
requires a separately reviewed versioned producer/collector migration, not invented
measurements. Unversioned archive pointers have no exact-version S3 verification.

No existing IBER detection rule, schema, infrastructure template or IAM boundary changed.
