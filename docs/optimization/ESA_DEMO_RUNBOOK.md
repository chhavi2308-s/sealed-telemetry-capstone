# ESA demonstration runbook

## Scope and environment

Run in a **fresh clone or fresh ESA worktree** of branch
`feature/esa-temporal-index`, baseline `8b219102ebe2c29c04972a1a6a4fc44d444a244c`,
with Python 3.12 and the locked development dependencies installed. These
commands are local-only: they do not use AWS credentials, call an endpoint,
read a secret, or modify infrastructure.

The supplied scripts require their output directory not to exist. Use a fresh
worktree, or alter only the output path for a new local capture; do not delete
evidence as part of a demo.

```powershell
$env:PYTHONPATH='src'
..\test-env\Scripts\python.exe scripts\benchmark_temporal_index.py
..\test-env\Scripts\python.exe scripts\esa_day2_demo.py
..\test-env\Scripts\python.exe -m sealed_telemetry.study --output benchmarks\esa-evaluation --trials 5
..\test-env\Scripts\python.exe scripts\esa_expanded_unrelated_leases.py
..\test-env\Scripts\python.exe scripts\esa_forensic_demo.py
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
0.75, F1 0.8571428571, FPR 0.0, and inconclusive-run rate 0.6667. Pending and
inconclusive findings are not alerts: the metric’s prediction is an observed
`SUSPICIOUS` or `CORROBORATED_SUSPECTED_ABUSE` finding, while uncertainty is
counted separately. The 0-FP observation has a Wilson FPR upper bound of about
3.1%; it is not a population guarantee.

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

Recorded validation: 384 full-suite tests passed in 283.75 seconds; a focused
ESA/security/admission subset had 89 passing tests; strict mypy passed over 36
source files; Ruff, format and whitespace passed. The existing cfn-lint Python
API found no issues in the five unchanged infrastructure templates for
`ap-south-1`. CloudFormation Guard was deliberately deferred and did not run.
The SAM CLI was unavailable, so SAM-specific validation did not run.

## Existing AWS evidence (do not rerun here)

Prior project records report a successful C2 deployment and one live synthetic
smoke test. C4 was deployed with `UPDATE_COMPLETE` and 84 recorded deployment
checks. This runbook neither queries AWS nor invokes a live endpoint; the C4
live smoke remains **not tested** until separately authorized.

## Explicit limitations

- All benchmark, evaluation and demo results are synthetic/local, not AWS
  detection latency, cost, availability or SLA measurements.
- The current caller can write some evidence in the broader project; no demo
  claims independent live verification or universal replay protection.
- The unrelated-lease supplement is synthetic and not an independent external
  corpus; its perfect observed score does not supersede the frozen baseline.
- Dense ambiguity is intentionally retained as uncertainty; candidate indexing
  never changes the authoritative `matches()` predicate or IBER decision rules.
