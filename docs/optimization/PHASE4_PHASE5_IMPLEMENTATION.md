# Phase 4–5 continuation status

This continuation starts from the verified ESA baseline commit
`bad378f4d72cda2a0e1b437a9fe0f337a2d17150` in the isolated branch
`feature/esa-phase4-graph-matching`. It makes no AWS call, deployment, IAM
change, or modification to either pre-existing worktree.

## Phase 4 — deterministic graph diagnostics

`src/sealed_telemetry/graph_matching.py` implements a bounded deterministic
Hopcroft–Karp maximum-cardinality calculation. It accepts only an already-built
observation-to-expectation edge map; it cannot create an edge or bypass
`reconciliation.matches()`.

`reconcile()` calls it only where candidate alternatives compete (one observation
has alternatives or an expectation is reusable). The call is diagnostic-only:
its output is not surfaced as a decision, does not assign an expectation, and
cannot convert a credential/action relationship into proof of application
execution. Existing ambiguity/reuse decisions remain `INCONCLUSIVE`.

The graph component bound is 10,000 vertices and 100,000 edges. A bound breach
stops diagnostics without producing an assignment; reconciliation retains its
existing conservative result. Candidate edges come from the selected indexed or
exhaustive generator, both of which finish with the authoritative `matches()`
predicate.

`tests/test_graph_matching.py` covers deterministic ordering, small seeded
brute-force maximum-matching equivalence, capacity handling, conditional graph
execution, ambiguity preservation, and indexed/exhaustive decision equivalence.

## Phase 5 — local late-evidence revision bridge

`Ledger.reconcile_run()` recomputes one stored run with the unchanged
authoritative reconciliation engine, then uses the existing append-only decision
history. It is deliberately not an AWS event-driven pipeline and does not
incrementally assign graph edges. Therefore late evidence or a health-state
change creates a material revision rather than silently replacing history.

`tests/test_incremental_reconciliation.py` covers a late expected action plus
intent, a health revision, conflict rejection before state change, idempotent
re-runs, and indexed/exhaustive equivalence.

## Release validation recorded for this batch

- Certified local regression run `20261113-212031`: 397 collected, attempted,
  and passed; 0 failed, errors, skipped, xfailed, interrupted, or nonzero-exit
  batches. The node manifest was accounted for exactly once. The recorded
  source fingerprint is
  `90F867EEAC45C5707B52DE55DF99500CC46024DC16C55567FDCA06F093FFE62D`.
- Focused graph, local-revision, and deterministic four-stage node-ID tests
  passed before that certification.
- Ruff, Ruff format, strict mypy, whitespace, five-template cfn-lint, forensic
  integrity/tamper/revision checks, evaluations, and benchmark correctness
  checks are recorded in `PHASE4_PHASE5_RELEASE_EVIDENCE.md`.

## Remaining work

The source baseline contains reproducible ESA artifacts, offline C2/C4
admission tests, evaluation and forensic scripts. The local release is now
certified as described above. No live AWS conclusion, independent verifier
claim, event-driven incremental performance claim, or execution-identity proof
follows from these local diagnostics.
