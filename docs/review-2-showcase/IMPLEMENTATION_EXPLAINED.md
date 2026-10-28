# Implementation explained

Status: local implementation and static infrastructure candidate. No deployed architecture or live AWS result exists yet.

Sealed-Telemetry compares evidence from an application with independently controlled observations of OAuth-protected actions. A bearer token authorizes its holder; copying it can permit replay until expiry or revocation. This lab uses only disposable synthetic credentials and a mock provider. It does not steal real credentials.

Serverless means the cloud service manages invocation capacity and execution hosts. API Gateway accepts HTTPS requests and invokes Lambda. Lambda provides isolated execution roles and bounded runtime without a permanently managed application server. It does not make compromised application code trustworthy.

The gateway records invocation intent, obtains a scoped disposable credential and invokes the application. The app makes a legitimate mock SaaS request. The SaaS validates credential status, audience, expiry and scope against the registry and creates its own provider audit record. The disposable exposure mode allows the separate harness to reuse a test token. The suppression scenario omits application security events; it does not disable AWS platform logs, gateway intent or provider audit generation.

## Component map

Paths below are relative to the repository; functions/resources are implementation names, not evidence of deployment.

| Component | Source / entry | AWS resource | Input → output |
|---|---|---|---|
| Trusted gateway | src/sealed_telemetry/cloud_lab.py gateway | GatewayFunction | request → intent, app invocation |
| Disposable issuer | cloud_lab.py issuer | issuer function in infra/template.yaml | requested scope → short-lived token |
| Workload | cloud_lab.py app | AppFunction | invocation context → SaaS result, optional app evidence |
| Provider | cloud_lab.py saas | mock SaaS function | bearer-auth request → resource/denial and audit outbox |
| Audit delivery | cloud_lab.py audit_forwarder | provider stream forwarder | outbox change → dedicated provider queue |
| Intake/archive | src/sealed_telemetry/cloud.py | intake/normalizer functions, Events, Archive | authenticated event → receipt, versioned S3 object and index |
| Supplementary observations | src/sealed_telemetry/telemetry.py | platform/native parser and queues | bounded native metadata → source-qualified observations |
| Reconciliation | src/sealed_telemetry/reconcile.py and cloud_detector.py | detector schedule/function, Decisions | evidence plus health/deadlines → versioned findings |
| Approval | src/sealed_telemetry/approvals.py broker/api | approval API, encrypted broker, state machine | current decision + operator proof → approved action |
| Containment/recovery | src/sealed_telemetry/cloud_response.py | responder functions | approved action → verified attempts/evidence |
| Forensics | scripts/export_incident.py, export_response.py | private report API and archive | case/credential → exact-version verified reconstruction |

Use the expanded inventory and source for exact logical IDs; security/workload profiles partition ownership. Event example below is an explanatory projection, not a complete schema-valid intake payload:

```json
{"source":"provider","event_type":"PROVIDER_ACTION","invocation_id":"synthetic-invocation","action_id":"synthetic-action","provider_request_id":"synthetic-request","credential_fingerprint":"pseudonym","outcome":"success"}
```

Evidence is authenticated by caller identity and queue origin, validated, buffered through SQS and archived conditionally before indexing in DynamoDB. Queue redelivery is expected: source-qualified identifiers prevent cross-source collisions, conditional writes enforce idempotency and retries repair partial progress. Poison records become DLQ/quarantine metadata; they are not silently discarded.

IBER uses invocation/action/provider-request identifiers, credential pseudonyms and bounded windows. It waits for source-specific deadlines, considers source availability and preserves decision history. Missing app logs alone do not prove theft. Unmatched successful provider activity can become suspicious; stale health, delay or ambiguous retry matches can remain inconclusive. Cloud sweeps happen after invocation and ingestion, not synchronously at token use. No guaranteed real-time detection is claimed.

Containment is a separate approved workflow. It verifies token-specific rejection before optional integration disabling. Recovery tests old rejection and fresh-token success and closes the integration on failure. Integrity checks compare archived versions with receipts; hashes do not establish source honesty.

The research contribution being evaluated is invocation-bound reconciliation with independent observations, deadlines, uncertainty and decision history. This is a proposed mechanism, not an established novelty claim. Local scenario-disjoint tests show both useful suppressed-log detection and copied-identifier replay false negatives. Live AWS isolation/performance and broader external validity remain incomplete. See RESULTS_EXPLAINED.md and ../KNOWN_ISSUES.md.
