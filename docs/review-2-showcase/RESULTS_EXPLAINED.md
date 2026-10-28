# Results explained

The primary synthetic study uses 40 benign calibration runs and 180 unique scenario-disjoint test runs. Calibrated and fixed policies reuse identical inputs. Full IBER: TP45, FP0, FN15, TN120; precision1.0, recall0.75, F1≈0.8571. All 15 misses are copied-identifier replay ambiguity. Legitimate retries can have the same visible evidence: this is an observational limit, not evidence that the attack was benign. Threshold shortcuts would introduce unsupported accusations.

Zero observed false positives is not a guarantee; descriptive 95% Wilson upper bound is approximately3.1%. Correlated scenario templates limit confidence interpretation. Virtual p50/p95 detection40/40seconds calibrated,45/45fixed are simulation clocks. Inconclusive rate0.6667 counts any inconclusive case within a run and can overlap an alert. Forensic macro completeness0.8333 is a synthetic reconstruction measure. Actual AWS latency, overhead, containment time and billed cost are unmeasured/null.

The summary JSON contains application-only, independent-audit-only, fixed-deadline, IBER and ablation outputs. Do not pool older development datasets with revised any-alert-over-horizon scoring. Provider health is not complete historical coverage; response-failure scenario inputs do not mean live containment failed or succeeded. See ../TECHNICAL_REPORT.md.
