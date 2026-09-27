# BLAKE3 full-STARK composition qualification

Task and semantics: record the complete OODS composition equality for the real
combined BLAKE3 proof, including every typed AIR and both native lookup tables.
Canonical match: symbolic evaluation of authenticated arithmetic DAGs, followed
by existing typed arithmetic lowering. Reuse composition_graph_recorder's exact
direct/LogUp interpreter, tableEntryGeneric and pairConstraintGeneric rather than
transcribing equations. Inputs: verified capture samples, universal draws, claims,
composition challenge and seed; structural geometry comes from admitted components.
Graph construction linear in recorded operations apart from hash interning;
no performance prediction. Existing production recorder is the reusable authority.
Qualify native equality, reject mutated composition sample and claim, then commit
and verify the resulting graph using existing multiplication/inverse/linear AIRs.
Extract the existing arithmetic proof fixture to avoid duplicate lowering code.
No production suite/key changes. This is separate arithmetic qualification, not a
single joined parent proof; private input wiring and CPU/Metal migration remain.
