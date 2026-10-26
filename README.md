# Sealed-Telemetry

Executable synthetic OAuth evidence-reconciliation lab, plus an AWS SAM deployment candidate. **No AWS deployment has been performed.** Local execution and AWS service emulation are separate verification levels. See docs/IMPLEMENTATION_STATUS.md for measured status and remaining acceptance gates.

## Quick start

Requires Python 3.12 and Git. Use a virtual environment; no AWS credentials are needed for the local demo or test suite.

```powershell
python -m venv .venv
.venv/Scripts/python -m pip install --upgrade "pip>=26.2"
.venv/Scripts/python -m pip install -r requirements-dev.lock
.venv/Scripts/python -m pip install --no-deps -e .
.venv/Scripts/python -m pytest -q
.venv/Scripts/python -m sealed_telemetry.cli demo --scenario normal --output local-runs/normal
.venv/Scripts/python -m sealed_telemetry.cli demo --scenario replay-suppression --output local-runs/replay
.venv/Scripts/python -m sealed_telemetry.cli demo --scenario benign-log-failure --output local-runs/benign
.venv/Scripts/python -m sealed_telemetry.cli verify --output local-runs/replay
.venv/Scripts/python -m sealed_telemetry.cli experiment --seed 2026 --trials 2 --output local-runs/experiment
```

On Linux/macOS substitute `.venv/bin/python`. Demo directories must be new; existing evidence is never overwritten. Reports and independent ground-truth labels are separate files. The local replay uses the same disposable token against the independent mock provider with no invocation ID. The local boundary is a software model in one process, **not an OS/account security boundary**. Only the AWS deployment can substantiate role isolation.

## Structure

- `src/sealed_telemetry/`: schema, provider/outbox, ledger, IBER, response, reporting, evaluation and AWS Lambda adapters.
- `infra/template.yaml`: SAM infrastructure, ten Lambda service roles, encrypted evidence, queue/DLQ, provider outbox stream, scheduled reconciliation, findings and gated response.
- `tests/`: local fault scenarios and AWS adapter tests using Moto.
- `docs/specifications/`: full text extracted from the three original plans; originals are preserved at the repository root.
- `docs/adr/`: specification conflicts, trust assumptions and accepted local design choices.
- `docs/runbook.md`: cloud deployment, rollback, redrive, incident response and teardown.
- `docs/REQUIREMENTS_TRACEABILITY.md`: requirement/ticket mapping, including unfinished requirements.

## Trust and limits

The compromised app cannot authorize its own expected actions. A separately permissioned gateway registers expectations, the SaaS provider writes its own outbox, and authenticated intake assigns source identity. Application intent remains an untrusted claim. Independent evidence supports observed actions, not proof of credential theft or attacker identity. CloudTrail is supplementary AWS API evidence and does not record arbitrary outbound SaaS HTTP. A Lambda extension shares the environment's compromise risk. No real-time guarantee is made.

The mock issuer supports IAM-authorized internal issuance and a JSON client-credentials `/oauth/token` route, not a standards-complete OAuth authorization server. Local tokens validate scope, audience, expiration and revocation. Cloud issuer supports read/export scopes; the workload uses only read. See known issues before assessing final acceptance.

## Verification

```text
ruff check src tests scripts
ruff format --check src tests scripts
mypy src
pytest -q
cfn-lint infra/template.yaml
pip-audit --vulnerability-service osv --no-deps --disable-pip -r requirements.lock
```

CI performs these checks without deployment permissions. Lock snapshots include exact transitive versions. AWS deployment requires account, region, role, budget, retention and change-set review; no long-lived keys belong in this repository. See scripts/preflight.py and docs/runbook.md. No automatic deployment runs on push.
