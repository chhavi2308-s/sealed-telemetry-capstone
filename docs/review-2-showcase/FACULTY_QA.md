# Faculty viva preparation

## 1. Why Lambda?

It provides managed invocation execution, per-function roles and bounded runtime; workload code remains compromisable.

## 2. Why serverless?

It reduces server management and makes invocation context explicit, while adding asynchronous delivery and cloud dependency failure modes.

## 3. What is OAuth2?

An authorization framework for delegated access using tokens; it is not by itself an authentication protocol.

## 4. What is a bearer token?

A credential usable by its holder without an additional proof-of-possession key.

## 5. How does replay work?

An attacker reuses a copied valid token against an accepting resource server before expiry or revocation.

## 6. Why not CloudWatch alone?

Application-authored messages may be omitted or forged by compromised application code.

## 7. What does CloudTrail record?

Supported AWS API management and selected data events; arbitrary outbound SaaS HTTPS calls are not recorded as SaaS audit actions.

## 8. Why is provider audit independent?

The provider owns validation and audit generation outside the workload execution role. This assumes provider control is not compromised.

## 9. How are logs suppressed?

A disposable lab switch omits application security evidence emission. It does not erase existing protected evidence or disable platform logging.

## 10. Detection versus recovery?

Detection assesses evidence; containment restricts credentials; recovery restores verified synthetic integration operation.

## 11. Is detection real time?

No guarantee: delivery, source deadlines, skew allowance and scheduled sweeps add latency.

## 12. What distinguishes IBER?

The proposed combination binds expected actions to provider observations and models uncertainty, health and deadlines. Novelty needs comparative research evidence.

## 13. What if SQS fails?

Producers receive errors/retry; provider outbox preserves eligible audit data, DLQs and alarms expose exhausted processing. Long outages can exceed retention.

## 14. What if audit is delayed?

Pending or inconclusive states avoid immediate theft claims; late data appends revised decisions.

## 15. How is forgery reduced?

Intake authenticates caller source and queue origin; schema validation and source-specific permissions prevent workload impersonation of provider evidence.

## 16. What does Object Lock guarantee?

Configured retention protects versions from ordinary deletion according to governance rules; authorized bypass and key loss remain relevant.

## 17. What are the false negatives?

Copied-identifier replay can be observationally identical to legitimate retries:15 misses among60 replay trials in the primary synthetic test.

## 18. How is accuracy measured?

Ground truth is separate; TP/FP/FN/TN produce precision, recall, F1 and false-positive rate. Inconclusive cases are separately reported.

## 19. What is the cost?

The documented us-east-1 planning model is not a live bill or selected-region quote; retained keys/secret keep charging and budgets only alert.

## 20. How does recovery work?

Separately approved recovery creates a fresh scoped credential, verifies old rejection and fresh success, and closes integration if verification fails.

## 21. What are trust boundaries?

Workload, security evidence owner, provider and operator privileges are separated; two accounts strengthen administrative separation.

## 22. What is compromised?

The assumed attacker controls workload code and its credentials, but not the security account/provider administration.

## 23. Why pseudonymize credentials?

Detectors correlate stable fingerprints without storing bearer tokens as evidence. Pseudonym key access remains sensitive.

## 24. Why S3 and DynamoDB?

S3 holds exact evidence versions; DynamoDB indexes queries and current decisions. They serve different access patterns.

## 25. Are duplicate deliveries normal?

Yes. Source-qualified IDs and conditional writes make retries idempotent.

## 26. What if archive succeeds but index fails?

A retry reuses the archive identity and repairs indexing rather than treating partial progress as completion.

## 27. What is a DLQ?

A queue for messages exceeding processing attempts; recovery reviews source/configuration and redrives at bounded rates.

## 28. What is pending?

Evidence deadlines are still open, so the engine waits before treating unmatched activity as suspicious.

## 29. What is consistent?

Available independently expected evidence matches under configured identifiers/windows; it is not a proof that every action is benign.

## 30. What is inconclusive?

Missing/unhealthy/ambiguous evidence does not support a reliable conclusion.

## 31. What is suspicious?

Evidence such as unmatched successful provider activity exceeds bounded expectations; it does not establish attacker identity.

## 32. What is corroborated abuse?

A stronger state requires independent contradictory successful activity following verified revocation beyond allowed skew.

## 33. Why retain decision history?

Late evidence can change conclusions; append-only revisions preserve what was known at each evaluation.

## 34. Does source health prove completeness?

No. Availability/configuration/lag checks do not attest that every historical action was delivered.

## 35. What happens with clock skew?

Bounded skew widens conservative evaluation; excessive or unknown skew increases uncertainty.

## 36. What if identifiers are copied?

Identifiers alone are not cryptographic sender binding, so some retries and attacks remain indistinguishable.

## 37. Can thresholds solve copied-ID attacks?

Not without extra observations; aggressive thresholds can accuse legitimate retries.

## 38. What stronger observation could help?

Trustworthy provider attempt identities or sender-constrained tokens could add distinguishing information; this lab does not claim they are implemented.

## 39. Why scope tokens?

Scope limits permitted operations and audience limits accepting services, reducing exposure consequences.

## 40. Is the mock OAuth service standards complete?

No. It is a controlled synthetic issuer/validator, not a production authorization server or conformance-certified implementation.

## 41. How is revocation verified?

Probe the actual mock resource server and require token-specific revoked denial and a provider request ID; generic403 is insufficient.

## 42. Why revoke before global disabling?

Global disabling could mask whether the individual token was actually revoked.

## 43. Who approves response?

An authorized operator approves a current decision-bound, expiring action through an encrypted callback workflow.

## 44. What if the finding changes?

Current-decision guards reject stale approvals and atomically guard registry effects.

## 45. What if response times out?

Durable attempt starts/history expose uncertainty; no success is claimed without verification.

## 46. Are hashes proof of truth?

No. They show consistency with trusted receipts, not honesty of the original source.

## 47. What is cross-account isolation?

Security resources reside under a separately administered account with narrow cross-account delivery/invocation grants.

## 48. What are algorithm bounds?

Bounded candidate reconciliation uses O(n²) memory and worst-case O(n² log n) time including sorting; cloud batch limits are explicit.

## 49. Why synthetic data?

It enables reproducible ground truth and safe disposable-token replay without attacking third-party systems.

## 50. What is held out?

Calibration uses benign scenarios disjoint from the primary test scenarios; seeds/protocol/policy hashes document reproducibility.

## 51. Are the timings AWS timings?

No. Current reported40/45second medians are virtual simulator detection times. Live metrics remain unmeasured.

## 52. What is an ablation?

A variant removes a mechanism to examine its contribution; variants are not independently optimized production detectors.

## 53. Why no guaranteed zero false positives?

Finite correlated synthetic scenarios cannot establish population-wide behavior; uncertainty intervals and external validation are needed.

## 54. What survives stack deletion?

Resources marked Retain, including evidence stores, keys, secret and archive policies. Cleanup does not authorize evidence destruction.

## 55. What if KMS keys are deleted?

Retained ciphertext can become permanently unreadable even when Object Lock still protects object versions.

## 56. What can faculty see today?

Working local demonstrations, test evidence, synthetic evaluation and static infrastructure; actual AWS deployment remains blocked on access and approval.
