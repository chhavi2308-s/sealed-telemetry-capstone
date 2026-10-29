"""Regenerate a 45-section blueprint audit with full source text and explicit verification gates."""

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs/specifications/Sealed_Telemetry_Final_End_to_End_Blueprint.txt"
MAPPING = {
    1: (
        "docs/threat-model.md, docs/IMPLEMENTATION_STATUS.md",
        "TESTED",
        "Live Review-2 and final acceptance require approved AWS account",
    ),
    2: (
        "docs/threat-model.md, tests/test_release_security.py",
        "TESTED",
        "Live workload role denial and account administrator exclusions",
    ),
    3: (
        "docs/architecture/final.mmd, infra/template.yaml",
        "IMPLEMENTED",
        "Confirm deployed resource flows",
    ),
    4: (
        "docs/release/template-inventory.json, infra/",
        "IMPLEMENTED",
        "CloudFormation change-set reconciliation",
    ),
    5: (
        "pyproject.toml, requirements-dev.lock, .github/workflows/ci.yml",
        "TESTED",
        "Remote CI and independent review",
    ),
    6: (
        "schema.py, schemas/evidence-v1.schema.json, tests/test_core.py",
        "TESTED",
        "Live authenticated source acceptance",
    ),
    7: (
        "cloud_lab.py, scripts/cloud_demo.py, scripts/cloud_acceptance.py",
        "TESTED",
        "Review-2 live demonstration",
    ),
    8: (
        "infra/security.yaml, cloud_response.py, holdout.py",
        "IMPLEMENTED",
        "Final live acceptance",
    ),
    9: (
        "reconciliation.py, tests/test_core.py, tests/test_identifiability.py",
        "TESTED",
        "Measured AWS deadlines/coverage",
    ),
    10: (
        "evaluation.py, holdout.py, experiments/results/",
        "TESTED",
        "Independent scenario holdout and cloud cost/overhead",
    ),
    11: ("docs/NEXT_STEPS.md", "BLOCKED", "Owner assigns people, dates and review availability"),
    12: ("docs/KNOWN_ISSUES.md, docs/adr/", "IMPLEMENTED", "Risk acceptance by owner"),
    13: (
        "docs/runbook.md, docs/release/DEPLOYMENT.md, scripts/preflight.py",
        "IMPLEMENTED",
        "Deployment/rollback/cleanup rehearsal",
    ),
    14: (
        "docs/research/copied-identifiers.md, docs/TECHNICAL_REPORT.md",
        "IMPLEMENTED",
        "Human defense rehearsal",
    ),
    15: (
        "docs/IMPLEMENTATION_STATUS.md, docs/release/DEPLOYMENT.md",
        "IMPLEMENTED",
        "AWS and reviewer signoff",
    ),
    16: (
        "docs/threat-model.md, docs/adr/",
        "IMPLEMENTED",
        "Deployment authorization is not inferred",
    ),
    17: (
        "infra/template.yaml, infra/security.yaml, infra/workload.yaml",
        "TESTED",
        "Distinct account identities and cross-account propagation",
    ),
    18: (
        "cloud_lab.py, tests/test_cloud_lab.py, scripts/cloud_acceptance.py",
        "TESTED",
        "Actual source separation and IAM acceptance",
    ),
    19: (
        "scripts/cloud_demo.py, docs/runbook.md",
        "IMPLEMENTED",
        "Capture actual timestamps/screenshots/video",
    ),
    20: (
        "docs/failure-contracts.md, redrive.py, tests/test_redrive.py",
        "TESTED",
        "Rehearse cloud fallback paths",
    ),
    21: (
        "src/sealed_telemetry/, infra/, tests/",
        "IMPLEMENTED",
        "Live F1-F10 acceptance; optional real provider excluded",
    ),
    22: (
        "schema.py, reconciliation.py, cloud_reporting.py",
        "TESTED",
        "Live versioned evidence export",
    ),
    23: ("reconciliation.py, docs/algorithm.md", "TESTED", "Provisional timing calibration"),
    24: (
        "tests/, holdout.py, experiments/results/",
        "TESTED",
        "Actual cloud faults and workload-role denials",
    ),
    25: (
        "holdout.py, docs/research/copied-identifiers.md",
        "TESTED",
        "Blind external holdout and billed measurements",
    ),
    26: (
        "docs/NEXT_STEPS.md",
        "BLOCKED",
        "Owner selects actual schedule; eight-week plan is not an execution result",
    ),
    27: (
        "src/sealed_telemetry/, scripts/, docs/adr/003-isolation-telemetry-approval.md",
        "IMPLEMENTED",
        "API adaptations recorded; no standards-complete OAuth claim",
    ),
    28: (
        ".github/workflows/ci.yml, scripts/preflight.py, infra/budget.yaml",
        "TESTED",
        "Remote CI and actual account budget/notifications",
    ),
    29: (
        "docs/ONBOARDING.md, docs/ARCHITECTURE_DECISIONS.md",
        "IMPLEMENTED",
        "Team signoff and credentials handover through SSO",
    ),
    30: (
        "docs/TECHNICAL_REPORT.md, docs/research/, docs/release/",
        "IMPLEMENTED",
        "Live artifacts, poster review and video require real acceptance",
    ),
    31: (
        "docs/IMPLEMENTATION_STATUS.md, docs/NEXT_STEPS.md",
        "IMPLEMENTED",
        "Historical sprint target superseded by actual commit/test evidence",
    ),
    32: (
        "tests/test_aws.py, tests/test_identifiability.py, docs/threat-model.md",
        "TESTED",
        "Live boundaries; no extension attestation or SaaS egress CloudTrail claim",
    ),
    33: (
        "infra/, cloud_reporting.py, docs/adr/003-isolation-telemetry-approval.md",
        "IMPLEMENTED",
        "REST API, opaque-token and read-only recovery deviations require review",
    ),
    34: (
        "docs/release/template-permissions.json, tests/test_release_security.py",
        "TESTED",
        "Live IAM denials/SCP/resource policies",
    ),
    35: (
        "schema.py, telemetry.py, tests/test_telemetry.py",
        "TESTED",
        "Actual supported event coverage",
    ),
    36: (
        "cloud_lab.py, aws_handlers.py, cloud_detector.py, cloud_response.py",
        "TESTED",
        "Cloud end-to-end causal observations",
    ),
    37: (
        "cloud_lab.py, approvals.py, cloud_reporting.py, docs/adr/003",
        "TESTED",
        "IAM JSON mock contracts, source-bound /evidence path and owner-run scenarios",
    ),
    38: (
        "docs/release/DEPLOYMENT.md, scripts/preflight.py",
        "IMPLEMENTED",
        "Account/region/artifact bucket/service role and change-set approval",
    ),
    39: (
        "infra/, docs/release/*-inventory.json, docs/failure-contracts.md",
        "TESTED",
        "Real service propagation, throttling, retention and cost",
    ),
    40: (
        "reconciliation.py, measurements.py, tests/test_cloud_detector.py",
        "TESTED",
        "Benign AWS percentile calibration; bounds remain explicit",
    ),
    41: (
        "tests/, scripts/cloud_acceptance.py, cloud_lab.permission_probe",
        "TESTED",
        "Real cloud fault/security/clean-deploy checks",
    ),
    42: (
        "docs/threat-model.md, docs/KNOWN_ISSUES.md, docs/research/copied-identifiers.md",
        "TESTED",
        "Independent review; privileged security-account compromise excluded",
    ),
    43: (
        "docs/architecture/, docs/release/, docs/TECHNICAL_REPORT.md, docs/ONBOARDING.md",
        "IMPLEMENTED",
        "Actual cloud evidence and human review artifacts",
    ),
    44: (
        "docs/IMPLEMENTATION_STATUS.md, docs/release/DEPLOYMENT.md",
        "BLOCKED",
        "Final go/no-go cannot pass before deployment, recovery and measured cloud evaluation",
    ),
    45: (
        "docs/architecture/final.mmd, original root Mermaid source",
        "IMPLEMENTED",
        "Diagram is an implementation candidate, not deployed topology",
    ),
}


def main() -> None:
    text = SOURCE.read_text(encoding="utf-8")
    # Section headings start 1..45 followed by title text, unlike numbered runtime instructions.
    headings = []
    expected = 1
    for match in re.finditer(r"(?m)^(\d+)\. ([^\n]+)", text):
        if int(match.group(1)) == expected:
            headings.append(match)
            expected += 1
    assert len(headings) == 45
    records = []
    for index, heading in enumerate(headings):
        number = index + 1
        section = text[
            heading.start() : headings[index + 1].start()
            if index + 1 < len(headings)
            else len(text)
        ]
        paths, status, gate = MAPPING[number]
        records.append(
            {
                "section": number,
                "title": heading.group(2).strip(),
                "specification_text": section,
                "source_sha256": hashlib.sha256(section.encode()).hexdigest(),
                "paths": paths,
                "offline_status": status,
                "cloud_or_owner_status": "BLOCKED",
                "blocker": gate,
                "verification": "docs/results/verification-20261027.json; mapped tests",
                "deployed": False,
            }
        )
    (ROOT / "docs/release/blueprint-audit.json").write_text(
        json.dumps(records, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    lines = [
        "# Final blueprint: 45-section audit",
        "",
        "Full source text/hashes: `release/blueprint-audit.json`, audited 27 October 2026. "
        "TESTED means offline/local or AWS service emulation; it never means DEPLOYED. "
        "IMPLEMENTED means source/artifact exists. BLOCKED identifies an external live/owner gate. "
        "Nothing is DEPLOYED. The optional real-provider adapter is OUT OF SCOPE.",
        "",
        "| Section | Offline status and evidence | External gate (BLOCKED) |",
        "|---|---|---|",
    ]
    for r in records:
        lines.append(
            f"| {r['section']}. {r['title']} | {r['offline_status']}: "
            f"{r['paths']} | {r['blocker']} |"
        )
    lines += [
        "",
        "ADR 001–003 record deviations. Proposed targets and schedules are not measured results.",
        "Audit searches cover TODO/FIXME, empty functions and skipped tests. "
        "IAM review: release/DEPLOYMENT.md and release/*-permissions.json. "
        "Local results: TECHNICAL_REPORT.md. Cloud cost and latency remain unobserved.",
    ]
    (ROOT / "docs/BLUEPRINT_AUDIT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
