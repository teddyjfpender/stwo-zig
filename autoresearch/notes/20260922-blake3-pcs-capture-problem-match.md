# Verified PCS capture to typed BLAKE3 paths

Task: qualify typed Merkle witnesses against actual successful CPU PCS/FRI
verification, rather than independently constructed Merkle fixtures.
Inputs: a small mixed-size two-column PCS proof, 17 raw queries over a 16-row
extended domain (duplicates guaranteed), all captured trace and FRI openings.
Invariant: preserve verifier-owned column ordering, raw duplicates, lifted row
projection, packed QM31 coordinate order, path indices and all 32 root bytes.
Canonical match: exact representation conversion followed by Merkle membership;
reuse native VerifiedProofCapture and existing typed path preparation. This is
integration validation, not a new hash or algorithm. Complexity is proportional
to captured path bytes and typed hash rows; tiny fixture only.
Sources: src/core/pcs/verifier.zig and src/core/fri/merkle_queries.zig;
existing BLAKE3 migration report contains upstream research and protocol pins.
Selected transfer: native capture -> lifted leaf/packed FRI leaf -> typed path.
Rejected alternative: inventing a second PCS transcript or multiproof decoder.
Prediction: every captured opening reconstructs its native root, and one actual
FRI opening verifies in a complete typed outer proof; altered public leaf fails.
Plan: one focused guarded test; no production benchmark or speed claim.
Limits: caller-supplied outer composition/OODS metadata are placeholders because
this fixture is PCS only, not an outer STARK proof. This does not qualify private
DEEP/FRI arithmetic connections, production identities, Metal or recursion trees.

Integration finding: FriLayerQueryCapture stores raw evaluation positions and
paths ABOVE the folding subtree, not paths from a single packed leaf. Therefore
recover the first original leaf plus its intra-subtree siblings using the native
packing rule (one QM31 for fold1, four for larger folds), then append the captured
upper path. This exact perfect-binary-tree reduction costs O(fold_width) hashes
and scratch words. It validates captured group membership, but a proof of the
resulting first-leaf path does not constrain arithmetic values in sibling leaves.
Test fold1 and fold2 schedules; retain this explicit limitation.
