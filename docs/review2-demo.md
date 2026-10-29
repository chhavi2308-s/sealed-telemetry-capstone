# Review-2 demonstration

Local rehearsal is executable now; live AWS Review-2 acceptance remains pending.

1. Explain app, provider and security boundaries. Show current deployment status honestly.
2. Run normal scenario and inspect gateway expectation, app intent, provider action, receipt/hash and consistent finding.
3. Run replay-suppression. Show the same disposable token used by the separate logical harness without invocation metadata. Provider audit remains while app intent is absent. Show suspicious external activity and uncertainty for the missing app log separately.
4. Run benign-log-failure and delayed-audit: demonstrate uncertainty/pending and late revision, not confirmed theft.
5. Verify the saved report; alter only a disposable copy and show verification failure.
6. Show response approval and failure tests. Never equate a revoke acknowledgement with enforcement.
7. Present actual local smoke measurements with their virtual-time limitation. Cloud latency/cost fields remain null.

For AWS repeat using scripts/cloud_demo.py and the runbook only after approval. Capture evidence versions, findings, timestamps, region and commit. Record actual latency; the local 50-second virtual deadline is not a measured cloud result. No screenshots or live video are claimed to exist.
