# AWS teammate handover

Use https://github.com/chhavi2308-s/sealed-telemetry-capstone branch implementation/engineering-foundation. Remote publication remains unverified until authentication succeeds. AWS is NOT DEPLOYED.

```powershell
git clone --branch implementation/engineering-foundation https://github.com/chhavi2308-s/sealed-telemetry-capstone.git
cd sealed-telemetry-capstone
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements-dev.lock
.venv/Scripts/python -m pip install -e .
.venv/Scripts/python -m pytest
```

Templates: infra/template.yaml (sandbox), security.yaml and workload.yaml (two accounts). Deployment/rollback/cleanup: docs/release/DEPLOYMENT.md. Demonstration: docs/review-2-showcase/LIVE_DEMO_RUNBOOK.md. Configure authorized account(s), region, temporary role, CloudFormation role, encrypted artifact bucket, budget notifications, owner/expiry tags and approved retention.

Use AWS CLI v2: aws configure sso --profile sealed-sandbox; aws sso login --profile sealed-sandbox. Set AWS_PROFILE and run aws sts get-caller-identity. Never commit credentials. Run python scripts/preflight.py --help and the read-only preflight command in the deployment runbook with a reviewed permission plan. Review exact change set, account, region, costs and retained resources with the owner before deployment.

Never execute deployment, change-set execution, fault injection, response actions, stack/key/evidence deletion without applicable explicit approval. Budget alerts are not spending caps. Retained evidence/keys/secret survive teardown and may charge indefinitely.

107 tests passed; live IAM isolation, outages, recovery, performance, cost and cleanup remain unverified. Copied-identifier replay retains15 false negatives among60 synthetic replay trials. See KNOWN_ISSUES.md and TECHNICAL_REPORT.md.

## Publish fallback from an authenticated machine

Clone the supplied bundle, inspect the branch, add the GitHub origin and fetch before pushing. If the remote branch has conflicting history, stop rather than force push. Authenticate through browser-based GitHub CLI or Credential Manager; never paste tokens into chat.

```powershell
git clone sealed-telemetry.bundle sealed-telemetry-capstone
cd sealed-telemetry-capstone
git remote rename origin bundle
git remote add origin https://github.com/chhavi2308-s/sealed-telemetry-capstone.git
gh auth login
git fetch origin
git push -u origin implementation/engineering-foundation
git fetch origin
git rev-parse HEAD
git rev-parse origin/implementation/engineering-foundation
```

Verify matching hashes and inspect the remote tree before claiming publication. Create a PR to main only; do not merge automatically.
