# Sealed-Telemetry technical report

The implementation reconciles expected invocation actions with independent synthetic provider observations. Authenticated intake, separate source queues, conditional archive receipts, source-qualified IDs and append-only decision revisions preserve provenance across application-log suppression. Platform and CloudTrail evidence are supplementary: CloudTrail does not observe arbitrary SaaS HTTP requests, and workload telemetry is not tamperproof.

## Verification and scope

The recorded source verification has 107 passing tests, strict typing, lint, infrastructure lint and dependency audits with no known vulnerabilities. See results/test-results-20261027.xml and the dependency audit JSON files. AWS deployment, regional quotas, real IAM enforcement, cross-account acceptance and actual cloud timings remain BLOCKED pending an approved target and temporary credentials. Offline SAM expansion is not deployment evidence.

## Research method and measured results

The primary dataset is experiments/results/scenario-study-20261027. Forty benign calibration runs and 180 unique test runs use disjoint scenario sets and documented seeds. A protocol and policy hashes precede evaluation. Frozen calibrated and fixed policies evaluate the same test inputs; these are not 360 independent trials. Ground truth is stored separately from detector inputs. Baselines and ablations are included in the machine-readable summary.

Full IBER observed TP45, FP0, FN15 and TN120: precision 1.0, recall 0.75, F1 0.8571 and false-positive rate 0.0. Zero observed false positives does not establish zero population risk (descriptive Wilson upper bound about 3.1%). Calibrated virtual detection p50/p95 is 40/40 seconds; fixed-policy is 45/45. These are simulator times, not AWS measurements. Macro forensic completeness is 0.8333. The 0.6667 inconclusive rate counts runs containing an inconclusive case and can overlap alerts; it is not a whole-run abstention rate. Synthetic scenario templates and related seeds limit statistical independence and generalization.

Copied identifiers explain the original two unflagged attack trials: a replay and a legitimate retry can have identical detector-visible observations. This observational limit persists as 15 false negatives in the primary study. No threshold was weakened or ground truth relabelled. See research/copied-identifiers.md. Stronger provider-side sender binding or trustworthy attempt identity would add observations outside this experiment.

Cloud detection/containment latency, invocation overhead and billed cost remain null. scripts/analyze_measurements.py requires labelled live observations, paired scope and explicit billing scope; missing and censored results remain missing. Response failures are tested independently; the research response-failure scenario does not itself execute containment.

## Security and recovery

Approval binds the current decision, actor, action, expiry and callback proof. Registry changes atomically check the current decision. Durable attempt starts precede effects. Revocation must be independently probed before integration disabling; generic rejection is insufficient. Recovery issues fresh scoped credentials and verifies both old rejection and fresh success. Arbitrary modified-data restoration and clean-code live recovery require the scope decision in ADR003. Evidence hashes establish integrity relative to trusted receipts, not source truth. Security-administrator compromise remains outside the boundary.

## Handover and limitations

Use ONBOARDING.md, runbook.md, release/DEPLOYMENT.md, REQUIREMENTS_TRACEABILITY.md and KNOWN_ISSUES.md. Retained evidence, keys and secrets survive stack deletion and can continue charging. Health is availability rather than completeness attestation; active-window and bounded batch limits constrain outage recovery. No novelty, production-readiness or live acceptance claim is made.
