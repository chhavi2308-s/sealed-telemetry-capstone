# New engineer onboarding

Start with README, IMPLEMENTATION_STATUS.md, BLUEPRINT_AUDIT.md, threat-model.md and ADR 001–003. Original plans and extracted text/hashes are in docs/specifications. The implementation profile is infra/template.yaml; scripts/generate_profiles.py produces the separate-account templates and tests detect drift.

Use Python 3.12 in a fresh virtual environment. Install requirements-dev.lock, then install the project with --no-deps -e . . Run Ruff check/format check, mypy src and pytest. Runtime dependencies are separately pinned in requirements.lock/src/requirements.txt; isolated SAM tooling is pinned in requirements-sam.lock. Never install SAM into the application environment to work around conflicting tooling dependencies.

Run the three local demos from README into new directories. Reports/ground truth are separate; provider.sqlite/security.sqlite are local research state and must not be committed. The local model is not an OS/account boundary. Use a fresh output directory rather than overwriting evidence.

Run python -m sealed_telemetry.study --output NEW_DIRECTORY for disjoint calibration/test experiments. Inspect study-protocol.json, frozen-policy.json, raw inputs, labels and observations. Clock-skew and transport offsets are synthetic. No attack labels are used to fit deadlines, and no policy is retuned on test results. All AWS timing/cost fields remain null until live measurements exist.

For AWS work follow release/DEPLOYMENT.md and runbook.md exactly. Account/region/roles are owner inputs. Preflight is read-only; sam deploy --no-execute-changeset still stages paid resources and needs approval. Do not use --resolve-s3, disable rollback, broaden role trust for tests, or delete retained keys/evidence without explicit review.

Code map: schema.py validates source contracts; cloud_lab.py is the mock issuer/provider/gateway/workload; aws_handlers.py handles authenticated intake/archive/index/quarantine; telemetry.py handles supplementary metadata; reconciliation.py is pure IBER; cloud_detector.py performs bounded sweeps/history; approvals.py and cloud_response.py implement current-revision approval and verified effects; cloud_reporting.py exports exact versions; redrive.py provides reviewed recovery; lab/evaluation/holdout/study modules provide reproducible local evaluation.

When changing schemas update the JSON schema and negative tests. When changing infrastructure regenerate profiles/inventories and inspect IAM/retention diffs. Keep original evidence and append late/revised decisions. A verified hash proves byte integrity, not event truth, completeness or attacker identity. Record actual commands/results in the verification manifest; do not carry forward an old green checkpoint.

## Regenerating the SAM tool lock

Use an isolated Python3.12 SAM environment. Export `python -m pip freeze --all > sam-freeze.txt`, then run `python scripts/lock_sam.py sam-freeze.txt --output requirements-sam.lock`. Do not replace the lock directly with raw Windows freeze output: freeze omits dependency-edge platform markers. Docker SDK requires pywin32 only on Windows. The normalizer restores known Windows-only markers; review new platform-specific dependencies and test clean Linux/Windows installs before committing. Current local host has neither Docker nor installed WSL, so clean Linux installation remains a CI verification gate.
