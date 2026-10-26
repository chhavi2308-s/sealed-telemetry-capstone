# Next steps

1. **Owner input required for cloud gate:** approved sandbox account ID, region, SSO/temporary deployment role/profile, Owner tag, expiry date, existing USD budget name/cap with subscribed notifications, and explicit approval for one-day governance retention and retained resources. Confirm existing regional API Gateway logging role; changing it requires separate account-wide approval under the user's safety rules.
2. Run read-only preflight. Review the SAM change set and resource inventory, then obtain execution approval. Do not treat a budget alert as a spending cap.
3. Deploy the Review-2 profile and run real app-role access-denial tests against intake source forgery, archive/index writes and responder permissions. Rehearse rollback, transient failures and retained-resource teardown.
4. Run scripts/cloud_demo.py for normal, replay-suppression and benign-log-failure; export exact archived versions using scripts/export_incident.py. Capture real action/receipt/decision times, stack identity, commit and demo proof.
5. Use independent benign calibration delays with scripts/calibrate.py; supply its policy through ReconciliationPolicy. Freeze baselines and held-out run/scenario splits before collecting research results.
6. Complete KI-03–KI-12: final trust profile, supplementary telemetry, redrive/load tests, cloud response/recovery, actual latency/overhead/cost measurement, literature matrix and final defense artifacts. The CLI case/report interface is current; any future HTTP API must retain investigator-only access.
7. Push the reviewed implementation branch and open a PR when GitHub write access/review is arranged. Do not directly overwrite main or create a Review-2 release tag before live acceptance.
