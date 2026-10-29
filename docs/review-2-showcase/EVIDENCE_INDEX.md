# Evidence index

| Category | Actual artifact | What it supports |
|---|---|---|
| Local tests | ../results/test-results-20261027.xml | Recorded107-pass source checkpoint; rerun separately logged |
| Local scenarios | ../results/clean-install-demo/ | Normal/replay/benign local reports and ground truth |
| Synthetic study | ../../experiments/results/scenario-study-20261027/ | Protocol, frozen-policy hashes, calibration/test outputs |
| Analysis | ../results/scenario-study-summary.json | Baselines, ablations, accuracy and virtual timing |
| Static AWS expansion | ../release/template-inventory.json, security-inventory.json, workload-inventory.json | Exact offline generated inventories; not deployed resources |
| Dependency review | ../results/dependency-audit-20261027.json, sam-dependency-audit-20261027.json | Audit snapshot, not future vulnerability guarantee |
| Source staging | ../results/sam-source-manifest-20261027.json | Source hashes, not deployment attestation |
| AWS integration | None | BLOCKED |
| Cloud timing/cost | None | Unmeasured |
| AWS screenshots/deployment IDs | None | Not fabricated |

An illustrative event in the explanation is not a captured audit record. For live evidence, add immutable versions, sanitized command outputs, account/region scope, timestamps and actual test outcomes after approval.
