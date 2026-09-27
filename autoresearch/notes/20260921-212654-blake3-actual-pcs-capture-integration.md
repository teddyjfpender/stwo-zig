---
title: BLAKE3 actual PCS capture integration
author: Teddy Pender
created_utc: 2026-09-21T21:26:54Z
---

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
