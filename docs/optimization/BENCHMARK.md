# ESA indexed temporal matching benchmark

This is a local, reproducible benchmark of the actual reconciliation engine. It
uses seeded synthetic `Evidence`, the unchanged authoritative `matches()`
predicate, normal capacity-safe policies, five measurements per mode and
`tracemalloc` peak allocations. It does not use AWS resources or claim AWS
latency.

Run from the repository root with the development environment:

```powershell
$env:PYTHONPATH='src'
..\test-env\Scripts\python.exe scripts\benchmark_temporal_index.py
```

The harness writes raw timing samples and median/standard-deviation summaries
to `benchmarks/esa-day2-final/measurements.json`. Each row verifies ordered
candidate-set equality and full finding equality before it is saved.

## Captured results (five runs each)

Times are milliseconds; `predicate` is the median count of authoritative
`matches()` evaluations for the entire reconciliation. Peak memory is Python
`tracemalloc` bytes, not process RSS.

| workload | size | build median ± sd | lookup median ± sd | exhaustive / indexed total median | speedup | predicate (exh → idx) | candidates | peak bytes (exh → idx) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| sparse partitions | 250 | 1.42 ± 0.14 | 4.46 ± 0.15 | 124.43 / 75.91 | 1.64× | 125,000 → 62,834 | 250 | 415,230 → 430,258 |
| sparse partitions | 1,000 | 6.57 ± 1.08 | 20.40 ± 1.18 | 5,511.02 / 2,599.60 | 2.12× | 2,000,000 → 1,001,369 | 1,000 | 1,661,622 → 1,737,886 |
| dense ambiguous | 100 | 1.86 ± 0.67 | 76.42 ± 6.84 | 103.44 / 101.00 | 1.02× | 2,500 → 2,500 | 2,500 | 319,718 → 323,824 |
| dense ambiguous | 250 | 5.33 ± 0.24 | 462.46 ± 17.38 | 598.72 / 606.63 | 0.99× | 15,500 → 15,500 | 15,500 | 1,789,948 → 1,800,330 |
| high concurrency | 250 | 6.19 ± 0.84 | 17.14 ± 1.19 | 882.85 / 318.93 | 2.77× | 125,000 → 62,834 | 250 | 416,494 → 429,824 |
| high concurrency | 1,000 | 110.26 ± 28.92 | 274.90 ± 112.44 | 1,389.37 / 884.52 | 1.57× | 2,000,000 → 1,001,376 | 1,000 | 1,661,298 → 1,742,512 |
| unrelated expectations | 250 | 3.61 ± 0.35 | 0.10 ± 0.03 | 53.15 / 26.36 | 2.02× | 62,500 → 0 | 0 | 545,576 → 589,762 |
| unrelated expectations | 1,000 | 14.05 ± 0.93 | 0.54 ± 0.05 | 697.47 / 107.81 | 6.47× | 1,000,000 → 0 | 0 | 2,161,770 → 2,350,624 |

All eight rows have equal candidate sets and equal final findings in indexed
and exhaustive modes. Dense ambiguity is deliberately the counterexample:
every expected action is plausible, so the index cannot safely prune and is
slightly slower at size 250.

## Complexity and interpretation

Index construction groups expected actions by the protected composite key
`(credential fingerprint, operation, resource pseudonym, actor pseudonym)`,
sorts each temporal bucket, and retains original input position: aggregate
build cost is `O(E log E)`. For each provider observation, bucket selection is
expected `O(1)`, temporal bracketing is `O(log B)`, and the original predicate
is applied to `K` time-window entries. Restoring original evidence order costs
`O(K log K)` in the current implementation. Thus retrieval is not universally
`O(M log N + K)`: filtering and ordering are observable costs.

The index never replaces `matches()`: it only admits a superset selected by
fields and the same inclusive temporal bound used by `matches()`. Exact
identity conflicts, source-qualified fields, retries, ambiguity and capacity
rules are still decided by the authoritative matcher and reconciliation logic.

Whole-pipeline speedup is smaller or variable because intent matching,
decision construction, health/deadline work and allocation remain outside the
provider-candidate lookup. The remaining application-intent loop is a
meaningful possible future bottleneck at large `K`, but measurements do not
justify a second index before a separate correctness/security review.

## Phase 4/5 paired diagnostic and revision measurements

The standalone `scripts/benchmark_phase45.py` harness uses identical seeded
inputs, five samples per workload, `tracemalloc` peaks, and a nonzero exit on
authoritative-finding mismatch. Its fresh captured output is intentionally
outside version control under
`verification/phase4-release-artifacts-20261113/phase45-paired-benchmark`.

| comparison | workload | median A ms | median B ms | finding equality |
|---|---|---:|---:|---|
| graph diagnostics enabled/disabled | 100 expected / 25 provider | 29.7464 / 22.6334 | enabled slower | equal |
| graph diagnostics enabled/disabled | 250 expected / 62 provider | 174.6231 / 138.4812 | enabled slower | equal |
| revision bridge/direct full recomputation | late evidence + health sequence | 8.6900 / 0.5834 | bridge slower | equal where promised |

The graph calculation is bounded and diagnostic-only; its cost does not buy an
authoritative assignment. The revision bridge deliberately recomputes a full
run and persists append-only history, so it is not a true event-driven
incremental optimization. These are local Python timings, not AWS claims.
