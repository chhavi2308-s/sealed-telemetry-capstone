# ADR 002 Retry ambiguity and deployment boundaries

Accepted safe implementation choices, 26 October 2026.

Repeated successful requests with the same action/invocation metadata may be legitimate retries. They remain INCONCLUSIVE; a one-use cardinality assumption alone must not label them corroborated abuse. CORROBORATED_SUSPECTED_ABUSE requires an independently authenticated responder receipt proving observed rejection after revocation, followed by contradictory provider success outside the configured clock-skew allowance. This is evidence of inconsistent enforcement/suspected misuse under the controlled mock's semantics, not proof of theft or a guarantee of universal OAuth revocation propagation. Missing invocation metadata alone remains insufficient. The local smoke dataset therefore includes an intentional missed/inconclusive replay case.

The workload's CloudWatch permissions are restricted to its own function log group; it cannot write security operational log streams. Source authentication uses role-bound SigV4 intake. Security archive/index/decisions remain outside workload permissions. A final separate-account profile is deferred until owner authorization, not silently declared equivalent to a security account.

The mock issuer exposes an IAM-authorized JSON client-credentials route. Containment uses an internal encrypted-token registry service rather than putting a bearer value in Step Functions history or exposing a new unauthenticated revoke route. A full provider OAuth adapter and investigator HTTP cases API remain explicit backlog items; the current incident interface is a read-only SDK export.

Transient active credentials and latest health are separate from the permanent forensic index. Only transient activation has TTL; archived originals and numbered decision revisions are retained. Cloud snapshots are checked for canonical integrity before inference; exports independently read exact retained S3 versions. Hashes never establish truth or completeness.
