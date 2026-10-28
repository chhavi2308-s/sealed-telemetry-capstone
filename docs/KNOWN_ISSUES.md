# Known issues and residual risks

27 October 2026. Offline controls and their limits are separated below. No known failing test is waived or skipped.

| ID | Status | Issue / required evidence |
|---|---|---|
| KI-01 | BLOCKED | Target account(s), region, SSO/profile, CloudFormation role, artifact bucket, budget/notifications, Owner/ExpiresOn and retention approval are unconfirmed. No AWS preflight has run |
| KI-02 | BLOCKED | Actual IAM denial, Object Lock/KMS enforcement, cloud delivery/retry/stream expiry, deployment/rollback/cleanup and alert delivery require approved live acceptance |
| KI-03 | IMPLEMENTED | Separate security/workload templates and permission boundary exist. Cross-account policy propagation, account-admin boundaries and native trail delivery remain unverified live |
| KI-04 | IMPLEMENTED | Supplementary adapters/trails/queues exist; CloudTrail covers selected AWS APIs, not SaaS HTTPS. Platform messages can be spoofed in a compromised environment. Native digest-signature validation and delivery coverage require live evidence |
| KI-05 | TESTED | Health records report observed availability/configuration and lag, not a completeness attestation or a complete historical coverage model. Retention loss and correlated security/provider failures can remain unobservable |
| KI-06 | TESTED | Reconciliation is bounded: 1,000 records per credential, ten active credentials and at most twenty scan pages per sweep. Overflow is INCONCLUSIVE and does not halt other groups. Active windows are finite; high load/long outages require measured capacity/partitioning and may delay or miss automatic evaluation. No production-scale/SLA claim |
| KI-07 | TESTED | Queue-pair/digest-bound redrive and original outbox replay are implemented. Stream failure metadata must not be treated as raw evidence; real exhausted-stream and poison-message recovery need rehearsal. Invalid raw bodies are intentionally not retained in quarantine |
| KI-08 | TESTED | Mock IAM JSON client-credentials and idempotent /oauth/revoke work with read/export scopes. This is not a standards-complete OAuth authorization server or RFC 7009 form endpoint |
| KI-09 | IMPLEMENTED | Cases/report APIs and operational dashboard exist. API results are bounded/truncation-labelled; paginated SDK exports provide full scoped data up to the documented report bound. No bespoke investigator UI is claimed |
| KI-10 | TESTED | Approval is action/current-revision bound; attempts are leased and recorded. Generic denial or an already disabled integration cannot prove per-token revocation. Ambiguous callback/partial outcomes remain unverified; operator recovery/new approval may be needed |
| KI-11 | BLOCKED | Credential/integration restoration is implemented; real clean-code redeployment and recovery are not rehearsed. Synthetic records are read-only; arbitrary modified-data restoration is an explicit ADR 003 scope decision awaiting owner review |
| KI-12 | TESTED | Copied identifiers and legitimate retries can be observationally identical. Those attacks remain false negatives/inconclusive. Synthetic scenario-disjoint results are not blind independent validation, a population error bound, novelty proof or cloud performance evidence |
| KI-13 | IMPLEMENTED | Windows long-path/cross-sandbox directory permissions can block cached builds. Use a writable short source path, verified hashes, a local wheelhouse/non-cached SAM build or Linux CI. No validation failure is hidden by this workaround |
| KI-14 | BLOCKED | Remote CI, teammate/reviewer signoff, approved release tag and actual cloud screenshots/video are absent. Final AWS metrics and real bill reconciliation remain null |

Security-account/provider administrators and coordinated compromise of protected storage/receipt trust remain outside the initial workload-compromise assumption. Governance retention does not withstand an authorized bypass administrator or destruction of the decryption key. Preserve uncertainty; never turn a telemetry gap into confirmed token theft.
