# Next steps

1. Owner reviews the offline release, ADR 001–003 and read-only synthetic recovery scope, and supplies non-secret target configuration listed in release/DEPLOYMENT.md. Do not provide access keys or session tokens.
2. Under securely configured SSO/temporary roles run read-only preflight for each chosen profile; inspect account identity, region, roles/trust/permissions, quotas, budgets, artifact storage and retention consequences.
3. Obtain explicit permission to stage artifacts/create change sets. Show actual target resources, regional estimate and proposed changes. Wait for separate execution approval.
4. Deploy the approved sandbox; run service readiness, three live Review-2 scenarios, actual workload-role canary denials, source forgery, collector/provider outages, buffering/redrive, archive/digest integrity and notification tests.
5. Review and approve containment/recovery cases, verify both requested effects, export attempt histories and sanitized incidents. Rehearse rollback, quiescence, draining and owner-approved teardown while preserving retained evidence/keys.
6. Collect real benign delivery calibration before freezing cloud test policy. Execute held-out scenarios/seeds with independent ground truth, measure real detection/response/overhead and billing, and preserve uncertainty/false negatives. Synthetic timing is not a substitute.
7. Complete independent review and capture the actual final demonstration artifacts. Only then assess the final go/no-go checklist. No completion claim is made while these external gates remain open.
