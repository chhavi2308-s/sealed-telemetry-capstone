# Known issues and acceptance gaps

| ID | Issue | Impact and next action |
|---|---|---|
| KI-01 | Account, region, temporary deployment role/profile, owner/expiry, budget cap and retention approval not supplied | Blocks live deployment. Run scripts/preflight.py only with confirmed values; inspect change set before execution |
| KI-02 | Live AWS security/reliability not exercised | Moto and static policy tests do not prove real role denial, Object Lock enforcement, propagation, retries, costs or teardown. Execute live acceptance in runbook |
| KI-03 | Single-account Review-2 candidate only | Separate roles are implemented; separate security/workload accounts, cross-account policy and organization guardrails remain a final-profile task requiring ownership approval |
| KI-04 | Supplementary platform and selected CloudTrail ingestion implemented offline; live subscriptions not exercised | Adapters whitelist metadata, preserve native IDs and bind versioned S3 input. Separate queues prevent forged provider source identity. EnableSupplementary defaults false; cloud coverage/cost still requires approval |
| KI-05 | Operational health is not a completeness attestation | Monitor checks deployment state, queue conditions and pending outbox lag. Coverage gaps and correlated provider/control-plane failures remain uncertain |
| KI-06 | Provisional deadlines and scale bounds | Benign delivery calibration has not run on AWS. More than 1000 records for one credential fails visibly; active batches need load tests and partitioned scheduling. Long outages may exhaust SQS/stream retention |
| KI-07 | No rehearsed automated DLQ/expired-stream redrive | Raw outbox/archives remain retained and manual recovery is documented; automate authorized replay and prove it in a fault experiment |
| KI-08 | Mock OAuth interface is deliberately limited | IAM-authorized JSON client credentials and read/export scopes work. No standards-complete OAuth authorization-code flow or public RFC 7009 revoke endpoint; responder uses scoped internal registry operations |
| KI-09 | Operator IAM cases HTTP API implemented; dashboard still backlog | GET /v1/cases/{case_id} and callback approval endpoints exist in SAM; not deployed |
| KI-10 | Cloud callback approval implemented offline; live verification pending | Encrypted callback tokens, operator IAM role matching, action-bound expiring proof, leased response attempts and immutable attempt history replace boolean authorization. Revocation requires provider denial reason/request ID; arbitrary 403 is insufficient. Live callback/expiry/concurrency acceptance remains required |
| KI-11 | Recovery scope | Local token revocation/rotation and integration disable/restore are tested; synthetic data is read-only. Cloud clean-code redeployment and restoration of modified resources have not been rehearsed |
| KI-12 | Research evidence is a local smoke dataset | Fifteen curated scenarios and virtual event time do not establish held-out effectiveness, a detection SLA, invocation overhead, AWS cost or novelty. Correlated-ID retries remain inconclusive; do not relabel them malicious to inflate recall |
| KI-13 | Windows long paths | SAM cached dependency paths fail under the original long checkout. Native validation and non-cached build succeed from a hash-verified short source path. Clone/build in a short path or use Linux CI |
| KI-14 | Remote review not performed | Local commits only; no branch pushed, PR created, teammate signoff, release tag, screenshots/video or final report/poster |

No known failing tests are hidden or skipped. These gaps prevent a final-system completion claim.
