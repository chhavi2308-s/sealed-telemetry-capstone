# Local smoke results

These are 30 curated local runs with virtual event time. They are not held-out AWS results or evidence of general research superiority. Inconclusive attack runs count as false negatives.

| Detector | TP | FP | FN | TN | Precision | Recall | F1 | Inconclusive rate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| app_only | 0 | 0 | 8 | 22 | undefined | 0.000 | 0.000 | 0.133 |
| audit_only | 6 | 0 | 2 | 22 | 1.000 | 0.750 | 0.857 | 0.133 |
| fixed_missing | 8 | 6 | 0 | 16 | 0.571 | 1.000 | 0.727 | 0.000 |
| iber | 6 | 0 | 2 | 22 | 1.000 | 0.750 | 0.857 | 0.467 |
| without_binding | 0 | 0 | 8 | 22 | undefined | 0.000 | 0.000 | 0.600 |
| without_deadlines | 6 | 0 | 2 | 22 | 1.000 | 0.750 | 0.857 | 0.400 |
| without_integrity | 6 | 0 | 2 | 22 | 1.000 | 0.750 | 0.857 | 0.400 |
| without_provider | 0 | 0 | 8 | 22 | undefined | 0.000 | 0.000 | 1.000 |

Actual local harness wall time: p50=0.031719s; p95=0.178052s. This includes the entire local scenario and is not invocation overhead or cloud detection latency.

The copied-ID replay scenario is intentionally inconclusive because the evidence also fits legitimate retries. AWS cost, cloud latency and invocation overhead remain null. Confidence intervals and per-run provider reconstruction counts are preserved in summary.json.
