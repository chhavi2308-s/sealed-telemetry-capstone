# Implementation checkpoint report

26 October 2026. Executable local software and an AWS SAM deployment candidate are implemented. The live Review-2 gate and final capstone are **not complete**.

## Audit and architecture

Baseline dd3d212 contained six specification/architecture assets and no source, tests, CI or infrastructure. The repository was clean. Original assets were preserved, complete Word text extracted, and the PDF, Mermaid and decision tree inspected before code changes. Work is on implementation/engineering-foundation; main was preserved. ADRs resolve schema differences, untrusted application intent and retry ambiguity.

The implemented candidate connects an independently controlled gateway, workload Lambda, scoped mock OAuth issuer and synthetic SaaS. Provider-owned durable audit flows through authenticated intake, SQS and an S3-first evidence normalizer. Permanent forensic records are separated from transient credential activation and latest source-health state. A deadline sweeper appends versioned decisions, publishes findings and invokes a response policy gate. An approved responder verifies actual mock-provider rejection. Investigators can export exact archived versions.

## Milestone checkpoint

| Milestone | Files and implemented components | Actual verification | Remaining gate |
|---|---|---|---|
| M0 | pyproject.toml, requirements*.lock, pinned/read-only CI, package/tests and SAM | 63 passing tests; zero failures, errors or skips. Ruff lint/format and strict mypy pass. cfn-lint, native SAM validation and package build pass. OSV reports zero known vulnerabilities in 63 dependency entries | Remote CI execution, account permissions and approved deployment |
| M1 | provider.py, cloud_lab.py, lab.py, cli.py and cloud_demo.py | Normal is CONSISTENT. Suppressed replay is SUSPICIOUS with an INCONCLUSIVE application-telemetry gap. Benign logging failure is INCONCLUSIVE. Saved report hashes verify | Live AWS requests, independent role ownership, measured timestamps, screenshots/video and teammate rehearsal |
| M2 | schema.py, storage.py, aws_handlers.py, cloud_health.py, archive/queue/index resources | Spoof/size/schema rejection, duplicates, ID conflicts, poisoned batches, S3/index crash recovery, provider outbox acknowledgement, lag and tampering tests pass | Real IAM/Object Lock enforcement, prolonged outages, expired-stream redrive and retained-resource teardown |
| M3 | reconciliation.py, cloud_detector.py, measurements.py and calibrate.py | Five states, bounded cross-run matching, missing/delayed/out-of-order evidence, clock skew, retries, source health, late revisions, transactional history and invalid policy tests pass | Empirical benign-delay calibration, provider coverage and load/partitioning evaluation |
| M4 | response.py, cloud_response.py, reporting.py, export_incident.py and gated workflow | Actual local provider rejection, fresh-token recovery and integration disable/restore pass. Cloud adapter tests cover verified/unverified responses, idempotent evidence and exact-version export | Live approval, revocation enforcement, clean-code recovery, rollback and response failure rehearsal |
| M5 | evaluation.py, fifteen scenarios, four baselines plus four ablations, separate labels and manifests | 30 local smoke runs measured; rates, Wilson intervals, reconstruction and actual local harness wall time preserved | Held-out AWS trials, detection/response latency, invocation overhead, billed cost, literature matrix and final defense artifacts |

See docs/results/test-results.xml and verification-summary.json for the test checkpoint. build-source-manifest.json identifies hash-verified source used for native packaging. Local commits preserve logical increments. No GitHub push, AWS deployment, account-wide IAM change or destructive teardown was performed.

## Security and reliability

Source identity comes from authenticated IAM roles, not producer claims. The workload has access only to its own log streams and the application evidence route; it cannot authorize expectations or edit security storage. Raw bearer values are excluded from audit, findings, workflow input and reports. A separate KMS key protects responder token material. S3 versions, raw/normalized hashes, conditional indexing, partial queue batches and source-health freshness support recovery and uncertainty handling.

Copied action/invocation metadata can also represent legitimate retries. These cases remain inconclusive. Corroboration requires independent verified-revocation evidence followed by contradictory provider success beyond the clock-skew allowance. This does not establish theft mechanism or attacker identity, and does not imply universal immediate OAuth revocation.

## Measured research limits

The curated local smoke run flagged 6 of 8 attack trials, with 0 flagged benign trials among 22 benign/fault trials. Fourteen of 30 runs had some pending/inconclusive evidence. These are observed local counts, not generalized accuracy or a held-out result. The ambiguous copied-ID replay trials remain false negatives instead of being relabeled to raise recall. Full metrics, uncertainty and raw sanitized reports are preserved in experiments/results/local-smoke.

Event times are virtual. Recorded local harness wall duration is not Lambda overhead or cloud detection latency. AWS cost, cloud latency and invocation overhead remain null. No research novelty claim is made.

## Exact next action

Provide/approve the sandbox account ID, region, SSO/temporary deployment role or profile, owner tag, expiry date, existing subscribed USD budget/cap, and regional API Gateway logging role. Approve the one-day governance retention and retained archive/keys/tables. The template declares 92 resources before SAM expansion; inspect the resource inventory and generated change set before execution. Budget alerts do not cap charges. This gate comes from the user's AWS safety requirements.

Then run read-only preflight, review the change set, deploy, execute actual workload-role denial tests, run the three Review-2 scenarios, export version-pinned evidence and measure real times. Rehearse response, rollback and cleanup before claiming deployment acceptance. Complete the calibrated held-out study and final handover afterward.

## Outstanding issues

KNOWN_ISSUES.md records the full backlog: cross-account final profile; supplementary CloudTrail/platform archive feeds; automated redrive and scale tests; limited mock OAuth/CLI investigator interfaces; operator-driven approval; cloud recovery; measured research and final artifacts. Windows cached builds under the original long checkout hit path limits; an identical short staging path validates and builds successfully. No system path setting was changed.

The source ZIP preserves tested working-tree bytes. A Git bundle also preserves commit history; text line endings may be normalized by a future Git checkout. The original binary documents are unchanged.
