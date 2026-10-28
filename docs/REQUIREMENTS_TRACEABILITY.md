# Requirements traceability

27 October 2026. The full 45-section specification register and hashes are in BLUEPRINT_AUDIT.md and release/blueprint-audit.json. Module filenames below resolve under src/sealed_telemetry/. TESTED means offline/local/Moto/static proof, never live AWS. No requirement is marked DEPLOYED.

| Requirement | Source / path / proof | Offline status | Cloud/owner acceptance |
|---|---|---|---|
| ENG-01 foundation | pyproject, three exact locks, CI, source lint/type tests, wheel/clean install; results/verification-20261027.json | TESTED | BLOCKED: remote CI/review |
| LAB-01 OAuth lifecycle | provider.py/cloud_lab.py; expiry/audience/scope/revoke and response tests | TESTED | BLOCKED: actual serverless calls |
| LAB-02 provider-owned observations | provider outbox, stream forwarder, dedicated source queue; test_cloud_lab/test_redrive | TESTED | BLOCKED: real delivery/outage/stream exhaustion |
| LAB-03 legitimate serverless flow | gateway, issuer, workload and SaaS APIs/functions in infra | IMPLEMENTED | BLOCKED: deploy/readiness/smoke |
| OBS-01 supplementary AWS evidence | telemetry.py; source-whitelist/gzip/version tests; account-native trails, central native storage, platform/failure queues | TESTED | BLOCKED: native coverage/digest validation |
| EVD-01 source/schema/receipt authority | schema.py/aws_handlers.py/JSON schema; source forgery, byte-limit, no raw rejection body tests | TESTED | BLOCKED: live IAM/API denial |
| EVD-02 queue/retry/idempotency/recovery | source ARN binding, source namespaces, partial batches, reviewed redrive/outbox replay; archive/index recovery tests | TESTED | BLOCKED: real fault rehearsal |
| EVD-03 archival/integrity/retention | KMS, versioned Object Lock archive, receipts and exact-version exports; test_aws/test_export | TESTED | BLOCKED: enforcement/recovery/cost; per-record receipt decision in ADR 001 |
| SEC-01 account isolation/IAM | generated security/workload profiles, permission boundary, scoped policies, retained bucket policies; test_release_security | TESTED | BLOCKED: actual role/account-admin denials and propagation |
| DET-01 IBER correlation | reconciliation.py; native/logical identifier caveats, bounded joins, no fabricated external invocation; test_core/test_identifiability | TESTED | BLOCKED: live traces |
| DET-02 deadlines/health/revisions/capacity | cloud_detector.py, configurable policy, immutable decision history, explicit overflow, cursor/page bounds | TESTED | BLOCKED: measured benign calibration/high-load/coverage |
| DEM-01 Review-2 normal/replay/suppression/benign fault | cli.py/lab.py; scripts/cloud_demo.py/cloud_acceptance.py | TESTED locally | BLOCKED: actual AWS finding/evidence/timestamps/video |
| RSP-01 approved verified response | approvals.py/cloud_response.py; encrypted callback, stale-revision atomic denial, leases/attempt records and split verification tests | TESTED | BLOCKED: live operator/response faults |
| REC-01 restoration | approved credential/integration recovery and fail-closed tests; known-good deployment runbook | TESTED for scoped model | BLOCKED: live clean-code recovery and ADR 003 read-only-data scope approval |
| FOR-01 reconstruction/reporting | cloud_reporting.py/reporting.py; reports API, version/hash manifest, decision history and export_response.py | TESTED | BLOCKED: live export and completeness assessment |
| EXP-01 baselines/ablations/held-out trials | evaluation.py/holdout.py/study.py; disjoint calibration/test scenarios, independent seeds/labels/frozen policy | TESTED synthetic | BLOCKED: cloud and independent external validation |
| EXP-02 metrics | real confusion counts, Wilson summaries, virtual latency/reconstruction, actual local runtime; explicit null cloud fields | TESTED synthetic | BLOCKED: actual AWS latency, overhead, response latency and bills |
| OPS-01 operational safeguards | preflight/cleanup/redrive/operator tools, exact transformed inventory, budget/dashboard/alarms, rollback/drain procedures; test_operator_safety | TESTED offline gates | BLOCKED: actual target/change set, notifications, rollback/teardown |
| RES-01 handover/review | technical report, onboarding, architecture, failure contracts, research limitations, current milestone report | IMPLEMENTED | BLOCKED: owner/reviewer signoff and actual cloud artifacts |
| OPT-01 real third-party provider | Blueprint optional provider integration; no credentials or attacks against real SaaS | OUT OF SCOPE | New explicit authorization required |

Evidence is scoped: service emulation cannot establish real account isolation; hashes cannot establish truth/completeness; health is not coverage attestation; virtual time cannot establish cloud latency. The empirical recall target is not silently substituted for an engineering goal. Copied-ID attacks remain positive ground truth even when IBER returns INCONCLUSIVE.

Historical checkpoint: c359d8b reported and independently passed 63 tests. Later commits implement the gaps above; current test counts/results come from the dated JUnit/verification files, not that historical statement. Requirements whose final acceptance needs AWS remain BLOCKED until the approved live checks succeed.
