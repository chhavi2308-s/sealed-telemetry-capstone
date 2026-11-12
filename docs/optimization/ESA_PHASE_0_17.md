# ESA Phase 0–17 implementation evidence

Scope: local ESA worktree `feature/esa-temporal-index` at baseline
`8b219102ebe2c29c04972a1a6a4fc44d444a244c`. No AWS API mutation, deployment,
IAM change, endpoint invocation, secret read, commit or push was performed.
The separate AWS worktree and its four pre-existing uncommitted C2/C4 files
were not modified.

## Focused audit and design

`src/sealed_telemetry/reconciliation.py` owns authoritative pairing. `matches`
requires the protected composite identity fields, the inclusive
matching-window-plus-clock-skew bound, and rejects only populated conflicting
provider/action/invocation identifiers. Reconciliation preserves the five
finding states, capacity handling and source-health uncertainty. `lab.py` is
the local real-engine scenario entry point; `four_stage_iber.py` and
`four_stage_c4_iber.py` are AWS evidence-admission adapters; `reporting.py`
is the forensic exporter. The Day 1 index is only a candidate prefilter;
exhaustive mode remains selectable with `candidate_mode="exhaustive"`.

No bipartite replacement is warranted: current ambiguity is intentionally
reported rather than optimistically assigned. No incremental/event-driven
architecture was added: the existing ledger sweep and append-only revisions
already reconsider late evidence and health changes.

## Phase accounting

| Phase | Implemented / tested evidence | Status | Remaining work |
|---:|---|---|---|
| 0 | Isolated ESA worktree, baseline preservation, Python test environment; original AWS worktree untouched. | PASS | None for local work. |
| 1 | Focused code/trust-boundary audit above. | PASS | Live AWS evidence remains outside this audit. |
| 2 | `ExpectedActionIndex` design and complexity in `BENCHMARK.md`. | PASS | None. |
| 3 | Indexed + exhaustive modes; randomized, boundary, conflict, retry, delayed-evidence and decision-equivalence tests. | PASS | None. |
| 4 | Existing conservative ambiguity behavior inspected; no Hopcroft–Karp change. | DEFERRED | Only revisit for a demonstrated correctness need. |
| 5 | Existing ledger sweeps/revisions inspected; no new incremental pipeline. | DEFERRED | AWS-triggered incremental design needs separate approval. |
| 6 | Five actual local `lab.run_scenario` runs and indexed/exhaustive comparison in `benchmarks/esa-day2-demo/demo.json`. | PASS | Not independent/live verification. |
| 7 | Actual scenario-disjoint study: 40 calibration, 180 test runs in `benchmarks/esa-evaluation/`. IBER TP45/FP0/FN15/TN120. | PASS | Synthetic only. |
| 8 | The frozen 180-run holdout and calibration cover the original seeded cases; separate `esa-expanded-unrelated-leases-v1` adds 30 unmatched-provider cases with two unrelated valid leases and 30 benign multi-lease controls. | PASS | Synthetic evidence only; not an external corpus. |
| 9 | `summary.json` contains precision/recall/F1/FPR, uncertainty counts and Wilson intervals; no population-FP claim. | PASS | No real-world confidence claim. |
| 10 | Five-repeat benchmark + raw samples in `benchmarks/esa-day2-final/`; summary in `BENCHMARK.md`. | PASS | Repeat on a controlled host for comparative capacity planning. |
| 11 | Existing offline C2/C4 admission tests included in full suite; adapter source files inspected. | PASS (offline) | Live collector/source-ownership verification requires authorized AWS session. |
| 12 | Evaluation records cloud latency, containment latency, overhead and AWS cost as null. | DEFERRED | Approved live timing measurement. |
| 13 | Prior project evidence recorded: C2 live smoke passed; C4 UPDATE_COMPLETE/84 deployment checks; C4 live smoke remains **not tested**. | PARTIAL | Separately authorized bounded C4 test only. |
| 14 | Actual local replay-suppression forensic export plus in-memory tamper detection in `benchmarks/esa-forensic-redacted/`. | PASS (local) | Version-pinned S3 archive export requires approved read-only AWS access. |
| 15 | Full offline suite, lint, format, strict mypy, whitespace and local cfn-lint validation of all five unchanged templates. | PASS | CloudFormation Guard remains explicitly deferred; no template was changed. |
| 16 | Acceptance criteria supported by local artifacts and full tests; AWS/live criteria qualified above. | PARTIAL | C4 live acceptance and cloud latency are blocked by authorization. |
| 17 | This document, `BENCHMARK.md`, `ESA_DEMO_RUNBOOK.md`, raw benchmark/demo/evaluation/forensic outputs and scripts are the ESA package. | PASS | Commit/push only with approval. |

## Actual local demonstrations

`scripts/esa_day2_demo.py` runs `lab.run_scenario`, then executes
`reconcile` in both candidate modes over the canonical ledger evidence. Both
modes were equal for every scenario:

| Requested scenario | Local engine scenario | Final indexed finding(s) | Revision evidence |
|---|---|---|---|
| Authorized activity | `normal` | `CONSISTENT / MATCHED_EXPECTATION` | `PENDING → CONSISTENT` |
| Direct OAuth token replay | `replay-suppression` | `INCONCLUSIVE / APPLICATION_TELEMETRY_GAP`; `SUSPICIOUS / UNMATCHED_PROVIDER_ACTION` | pending and final revisions retained |
| Benign application-log failure | `benign-log-failure` | `INCONCLUSIVE / APPLICATION_TELEMETRY_GAP` | `PENDING → INCONCLUSIVE` |
| Delayed evidence arrival | `delayed-audit` | `CONSISTENT / MATCHED_EXPECTATION` | `PENDING → CONSISTENT` |
| Ambiguous legitimate retry | `legitimate-retry` | two `INCONCLUSIVE / AMBIGUOUS_OR_REUSED_AUTHORIZATION` | ambiguity retained, not forced suspicious |

The five state names exist in the tested engine. This five-scenario set
observes `CONSISTENT`, `SUSPICIOUS`, `PENDING` revisions and `INCONCLUSIVE`;
`CORROBORATED_SUSPECTED_ABUSE` remains covered by the regression suite rather
than fabricated in a demo.

## Evaluation and forensic results

The actual `study --trials 5` run produced 40 calibration and 180 test runs.
IBER result: TP 45, FP 0, FN 15, TN 120; precision 1.0, recall 0.75, F1
0.8571428571, FPR 0.0, recall Wilson 95% [0.6277, 0.8422], FPR Wilson 95%
[0, 0.0310]. The zero observed FP result is descriptive, not proof of zero
population risk. Virtual detection p50/p95 were 40/40 seconds (calibrated)
and 45/45 seconds (fixed); these are not AWS measurements.

The separately versioned expanded evaluation adds 60 deterministic runs without
changing that baseline: 30 unmatched provider actions alongside two unrelated
valid leases each, and 30 benign controls with two independently bound leases.
It recorded TP30/FP0/FN0/TN30, 0.5 inconclusive-rate (the unmatched cases also
retain uncertainty for their absent provider evidence), no recorded failures,
and exact indexed/exhaustive equality. These supplemental results are not used
to tune or replace the historical recall result.

The forensic run used actual local ledger evidence from `replay-suppression`.
The original timeline integrity check passed; modifying one event in memory
caused verification to fail. Its exported summary deliberately omits the
credential fingerprint. Hashes establish byte integrity, not truth,
completeness, causal ordering or theft mechanism.

## Reproduction and validation

```powershell
$env:PYTHONPATH='src'
..\test-env\Scripts\python.exe scripts\benchmark_temporal_index.py
..\test-env\Scripts\python.exe scripts\esa_day2_demo.py
..\test-env\Scripts\python.exe -m sealed_telemetry.study --output benchmarks\esa-evaluation --trials 5
..\test-env\Scripts\python.exe scripts\esa_expanded_unrelated_leases.py
..\test-env\Scripts\python.exe scripts\esa_forensic_demo.py
..\test-env\Scripts\python.exe -m pytest -q
..\test-env\Scripts\python.exe -m ruff check src tests scripts
..\test-env\Scripts\python.exe -m ruff format --check src tests scripts
..\test-env\Scripts\python.exe -m mypy --strict src
git diff --check
```

Validation run: full pytest `384 passed in 283.75s`; focused ESA/security/
admission tests `89 passed in 93.09s`; post-final-edit temporal-index tests
`5 passed in 0.24s`; full strict mypy over 36 source files passed. Ruff,
format and `git diff --check` passed. The already-installed cfn-lint Python API
reported 0 findings over `infra/budget.yaml`, `infra/four-stage.yaml`,
`infra/security.yaml`, `infra/template.yaml` and `infra/workload.yaml` for
`ap-south-1`. The SAM CLI was unavailable, so no SAM-specific validation ran.
CloudFormation Guard was not installed or run because the owner previously
requested it be deferred.
