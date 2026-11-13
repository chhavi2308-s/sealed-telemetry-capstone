# ESA demonstration runbook

## Scope and environment

Run in a **fresh clone or fresh ESA worktree** from ESA baseline
`3f3afad8683b72094b30e2017be626fa23bbeccb`,
with Python 3.12 and the locked development dependencies installed. These
commands are local-only: they do not use AWS credentials, call an endpoint,
read a secret, or modify infrastructure.

The supplied scripts require their output directory not to exist. Use a fresh
worktree, or alter only the output path for a new local capture; do not delete
evidence as part of a demo.

```powershell
$env:PYTHONPATH='src;.'
..\test-env\Scripts\python.exe scripts\benchmark_temporal_index.py --output benchmarks\esa-phase-remaining\benchmark
..\test-env\Scripts\python.exe scripts\esa_day2_demo.py --output benchmarks\esa-phase-remaining\five-scenarios
..\test-env\Scripts\python.exe scripts\esa_corroborated_demo.py --output benchmarks\esa-phase-remaining\corroborated
..\test-env\Scripts\python.exe -m sealed_telemetry.study --output benchmarks\esa-phase-remaining\evaluation --trials 5
..\test-env\Scripts\python.exe scripts\esa_expanded_unrelated_leases.py --output benchmarks\esa-phase-remaining\unrelated-leases
..\test-env\Scripts\python.exe scripts\esa_forensic_demo.py --output benchmarks\esa-phase-remaining\forensic
..\test-env\Scripts\python.exe scripts\benchmark_phase45.py --output benchmarks\esa-phase-remaining\phase45 --repeats 5
```

## 1. Indexed temporal benchmark

Run `scripts/benchmark_temporal_index.py`. It creates five timing samples for
each of eight rows: sparse partitions (250/1,000), dense ambiguity (100/250),
high concurrency (250/1,000), and unrelated expectations (250/1,000). It
compares the indexed candidate prefilter and the preserved exhaustive fallback
on identical seeded evidence. Before saving a row, it requires ordered
candidate-set equality and full finding equality.

Inspect `benchmarks/esa-day2-final/measurements.json` and
`docs/optimization/BENCHMARK.md`. Show the dense-250 result as the important
counterexample: all candidates remain plausible, so indexing was 0.99x rather
than being presented as a universal improvement.

## 2. Five-scenario IBER demonstration

Run `scripts/esa_day2_demo.py`. It invokes the real local
`lab.run_scenario` and then `reconcile` in indexed and exhaustive modes:

| Scenario | Expected final result |
|---|---|
| Authorized activity | `CONSISTENT / MATCHED_EXPECTATION` |
| Direct OAuth replay | `SUSPICIOUS / UNMATCHED_PROVIDER_ACTION`, alongside an `INCONCLUSIVE` application-telemetry gap |
| Benign application-log failure | `INCONCLUSIVE / APPLICATION_TELEMETRY_GAP` |
| Delayed provider evidence | `CONSISTENT / MATCHED_EXPECTATION` after a pending revision |
| Legitimate retry ambiguity | `INCONCLUSIVE / AMBIGUOUS_OR_REUSED_AUTHORIZATION` |

Review `benchmarks/esa-day2-demo/demo.json`. It contains source-qualified
event IDs and stored revisions, and asserts indexed/exhaustive equality for
every scenario. It does not manufacture a corroborated-abuse demonstration;
that state remains regression-tested separately.

## 3. Evaluation reproduction

Run the `study` command with `--trials 5`. It generates 40 benign calibration
runs and 180 test runs: 12 registered test cases × three fixed seeds × five
trials. Inspect `benchmarks/esa-evaluation/summary.json`.

The captured IBER result is TP 45, FP 0, FN 15, TN 120; precision 1.0, recall
0.75, F1 0.8571428571, and FPR 0.0. `alert_coverage` is the share of evaluated
runs with an observed `SUSPICIOUS` or `CORROBORATED_SUSPECTED_ABUSE` finding:
45/180 = 0.25 for IBER. `PENDING` and `INCONCLUSIVE` are separate non-alert
states; this final-horizon run has 0 pending and 120 inconclusive results.
`uncertainty_rate` remains the union of those states for continuity. The 0-FP
observation has a Wilson FPR upper bound of about 3.1%; it is not a population
guarantee.

Run `scripts/esa_expanded_unrelated_leases.py` for the separately versioned
supplement, `esa-expanded-unrelated-leases-v1`. It runs three fixed seeds and
ten trials per seed for each of two cases (60 runs total):

- 30 cases place an external provider action beside two valid but unrelated
  gateway/application leases. Its conflicting populated invocation and action
  IDs keep it `SUSPICIOUS`; it cannot borrow either lease.
- 30 benign controls submit provider actions with exact bindings for two
  independent leases. Both remain `CONSISTENT`, with no false alert.

The captured supplement reports TP30/FP0/FN0/TN30, 0.5 inconclusive-rate from
the unmatched leases' provider-evidence gaps, no failures, and complete
indexed/exhaustive equivalence. It does not modify the frozen 40/180 baseline
or tune IBER.

## 3a. Corroborated-abuse rule demonstration

Run `scripts/esa_corroborated_demo.py` into a fresh output directory. It feeds
the real engine a synthetic, source-attributed responder revocation success and
a later successful provider action for the same credential. It does not hardcode
the decision: both indexed and exhaustive modes must derive
`CORROBORATED_SUSPECTED_ABUSE / SUCCESS_AFTER_VERIFIED_REVOCATION` from the
existing rule. The output explicitly says that these fixtures are neither live
nor independent evidence.

## 4. Forensic reconstruction

Run `scripts/esa_forensic_demo.py`. It produces a local
replay-suppression report, then changes one event only in memory and verifies
that its receipt hash no longer matches. Inspect
`benchmarks/esa-forensic-redacted/forensic-summary.json`:

- original report and timeline integrity: `true`;
- modified timeline integrity: `false`;
- exported summary: no `credential_fingerprint` field.

The local forensic report is not WORM storage, and its hashes establish byte
integrity only—not truth, causal ordering, complete collection, token theft, or
attacker identity.

## 5. Regression and static validation

```powershell
$env:PYTHONPATH='src'
..\test-env\Scripts\python.exe -m pytest -q
..\test-env\Scripts\python.exe -m ruff check src tests scripts
..\test-env\Scripts\python.exe -m ruff format --check src tests scripts
..\test-env\Scripts\python.exe -m mypy --strict src
git diff --check
```

Current certified release validation (`20261113-212031`): 397 collected and
attempted tests passed, with zero failures, errors, skips, xfails,
interruptions, or nonzero-exit batches. The recorded source fingerprint is
`90F867EEAC45C5707B52DE55DF99500CC46024DC16C55567FDCA06F093FFE62D`.
Strict mypy, Ruff, format, and whitespace passed. The cfn-lint Python API found zero findings in the five unchanged
infrastructure templates for `ap-south-1`. CloudFormation Guard remains
deferred by owner decision and did not run. The SAM CLI was unavailable, so
SAM-specific validation did not run.

## 5a. Phase 4/5 paired diagnostics benchmark

Run `scripts/benchmark_phase45.py` with a new output directory. It compares
graph diagnostics enabled/disabled on identical ambiguous candidate graphs,
then compares the local append-only revision bridge with direct full
recomputation over the same late-evidence and health sequence. Five samples are
required for each workload and any finding mismatch exits nonzero. The captured
run found graph diagnostics slower at both measured sizes while authoritative
findings remained equal. The bridge median was 8.6900 ms versus 0.5834 ms for
direct full recomputation, so it is not described as a true incremental speedup.

## Existing AWS evidence (do not rerun here)

Prior project records report a successful C2 deployment and one live synthetic
smoke test. C4 was deployed with `UPDATE_COMPLETE` and 84 recorded deployment
checks. A separately authorized C4 evidence-path smoke recorded one HTTP 200,
C2/C4 linkage, and source-owned HMAC/context version `v1` records. It did not
invoke the collector or monitor, establish healthy sources, recompute HMACs,
or independently verify the evidence path.

## Explicit limitations

- All benchmark, evaluation and demo results are synthetic/local, not AWS
  detection latency, cost, availability or SLA measurements.
- The current caller can write some evidence in the broader project; no demo
  claims independent live verification or universal replay protection.
- The unrelated-lease supplement is synthetic and not an independent external
  corpus; its perfect observed score does not supersede the frozen baseline.
- Dense ambiguity is intentionally retained as uncertainty; candidate indexing
  never changes the authoritative `matches()` predicate or IBER decision rules.
- The benchmark and demonstration results remain synthetic. Independently
  verified collection, full source-health coverage, live latency, and
  version-pinned AWS archive verification are partial or deferred.
