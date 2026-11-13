# Phase 4/5 offline release evidence index

## Scope and reproducibility

This index records a local-only release check for
`feature/esa-phase4-graph-matching`, based on ESA commit
`bad378f4d72cda2a0e1b437a9fe0f337a2d17150`. It neither accesses AWS nor
changes deployed resources. Captured raw outputs are intentionally retained
outside version control under
`verification/phase4-release-artifacts-20261113`; they are reproducible with
the commands below.

The complete node-ID regression was run as `20261113-212031`: 397 collected,
397 attempted, and 397 passed; failures, errors, skips, xfails, interruptions,
and nonzero-exit batches were all zero. Its source snapshot fingerprint is
`90F867EEAC45C5707B52DE55DF99500CC46024DC16C55567FDCA06F093FFE62D`.

```powershell
$env:PYTHONPATH='src;.'
..\test-env\Scripts\python.exe -m pytest -q
..\test-env\Scripts\python.exe -m ruff check src tests scripts
..\test-env\Scripts\python.exe -m ruff format --check src tests scripts
..\test-env\Scripts\python.exe -m mypy --strict src scripts\benchmark_phase45.py
git diff --check
```

The certified full regression used a manifest-driven PowerShell runner because
the foreground tool has a short command limit. It records each node once and
distinguishes attempted from completed test cases.

## Evaluations and demonstrations

The historical study remains a fixed, synthetic baseline: 40 calibration runs
and 180 held-out test runs produced TP=45, TN=120, FP=0, FN=15, precision=1.0,
recall=0.75, and F1=0.8571428571. Its 15 false negatives remain documented;
they were not tuned away. Final pending was 0 and final inconclusive was 120.

The separately versioned expanded 60-run supplement produced TP=30, TN=30,
FP=0, FN=0, with 30 inconclusive outcomes. It exercises unrelated valid leases
beside unmatched provider activity and a benign multi-lease control. Ground
truth is generated independently of detector output; it does not alter the
historical baseline.

```powershell
..\test-env\Scripts\python.exe -m sealed_telemetry.study --output <new-output> --trials 5
..\test-env\Scripts\python.exe scripts\esa_expanded_unrelated_leases.py --output <new-output>
..\test-env\Scripts\python.exe scripts\esa_day2_demo.py --output <new-output>
..\test-env\Scripts\python.exe scripts\esa_corroborated_demo.py --output <new-output>
..\test-env\Scripts\python.exe scripts\esa_forensic_demo.py --output <new-output>
```

The five-scenario real-engine synthetic demonstration has indexed/exhaustive
finding equivalence and covers authorized activity, direct replay, a benign
application-log gap, delayed evidence, and ambiguous retry. The corroborated-
abuse demonstration derives its finding from source-attributed synthetic
revocation and provider evidence; neither demonstration is live or independent
verification.

Fresh forensic output verifies an original timeline, fails after an in-memory
tamper, and preserves append-only revisions. Exported summaries redact the
credential fingerprint. Integrity hashes demonstrate byte integrity, not source
truth, completeness, causal order, or attacker identity.

## Benchmark evidence

`scripts/benchmark_temporal_index.py` measured five samples for eight seeded
workloads. Indexed and exhaustive candidate sets and final findings were equal
in every row. Indexing was faster on six workloads and slower on both dense
ambiguous workloads, where safe pruning is unavailable. Exact raw samples are
in `indexed-exhaustive-benchmark/measurements.json`; the workload methodology
and prior figures are in `BENCHMARK.md`.

`scripts/benchmark_phase45.py` is a standalone typed harness for paired,
identical-input measurements. It runs five samples per workload, uses
`tracemalloc` peak allocation measurements, exits nonzero on any correctness
mismatch, and retains graph diagnostics as non-authoritative.

| comparison | workload | enabled/bridge median ms | disabled/full median ms | result |
|---|---|---:|---:|---|
| graph diagnostic | 100 expected, 25 provider | 29.7464 | 22.6334 | equal authoritative findings; enabled slower |
| graph diagnostic | 250 expected, 62 provider | 174.6231 | 138.4812 | equal authoritative findings; enabled slower |
| local revision bridge | late evidence / health revision sequence | 8.6900 | 0.5834 | equivalent promised final state; bridge slower |

The graph figures include diagnostic/index/reconciliation work and are not a
claim about AWS latency. The local bridge performs a full reconciliation and
append-only SQLite revision work; it is not event-driven incremental
reconciliation and does not show an incremental speedup.

```powershell
..\test-env\Scripts\python.exe scripts\benchmark_temporal_index.py --output <new-output>
..\test-env\Scripts\python.exe scripts\benchmark_phase45.py --output <new-empty-output> --repeats 5
```

## Offline infrastructure validation

The Python cfn-lint API reported zero findings for `infra/budget.yaml`,
`infra/four-stage.yaml`, `infra/security.yaml`, `infra/template.yaml`, and
`infra/workload.yaml` in `ap-south-1`. CloudFormation Guard remains deferred
by owner decision; SAM CLI was unavailable. This is not an AWS deployment or
live CloudFormation validation.

## Original 14-phase directive status

| Original phase | Status | Evidence / remaining condition |
|---:|---|---|
| 1–3: temporal candidate matching | PASS (local) | Shared index preserves exhaustive fallback and authoritative `matches()`. |
| 4: graph matching diagnostics | PASS (local) | Bounded deterministic Hopcroft–Karp is diagnostic-only; it never assigns evidence. |
| 5: incremental reconciliation | PARTIAL | Append-only local revision bridge is correct for its promised scope but recomputes full reconciliation. |
| 6–10: security demonstrations, evaluation, metrics, benchmarks | PASS (synthetic/local) | Results above; dense regressions and historical false negatives are retained. |
| 11: AWS-facing admission integration | PASS (offline) | Adapter and four-stage tests; no new live verification here. |
| 12: live latency/cost/containment | DEFERRED | Requires a separately authorized AWS session. |
| 13: AWS deployment/live acceptance | PARTIAL | Prior bounded C2/C4 smoke evidence exists; this release does not independently repeat it. |
| 14: forensic verification/handoff | PARTIAL | Local integrity and redaction pass; version-pinned AWS archive verification needs approved read-only AWS access. |

## Explicit limitations

- All measurements in this index are synthetic/local, not live AWS latency,
  availability, cost, or throughput claims.
- Independently verified AWS collection, complete independent source health,
  live latency, and version-pinned archive verification remain partial or
  deferred.
- Candidate-index or graph speed changes do not change the authoritative
  predicate, evidence assignment policy, or the five IBER finding states.
- No benchmark implies universal replay protection, proof of application
  execution, or independent cryptographic recomputation.
