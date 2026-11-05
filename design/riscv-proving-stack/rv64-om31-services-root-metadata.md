# OM31 services root metadata closure

`om31_native/services_root.zig` implements the native metadata portion of a recursive services root. It does not authenticate circuit proofs, leaf frames or topology admissions by itself, and its `Metadata` return is deliberately not an execution-verification result.

The outer recursive receiver must first verify its root circuit proof, admit each leaf's exact topology and security profile, authenticate every leaf frame digest, and establish exactly-once ordered coverage. Only those authenticated frame words and sidecars may enter this adapter. Running it on arbitrary JSON or words is not verification.

The adapter then:

1. Rebuilds `execution.Inventory` from receiver-owned setup, request and expected execution authority, including program/input/output, register/PC adjacency, coverage, geometry, spans and mass bounds. Candidate fixed authorities remain independently reconstructed and retained.
2. Decodes the bounded original stage-one file against that complete expected inventory.
3. Recomputes each CPU canonical receipt from the encoded child proof, trusted scope/instances and terminal-marginal sidecar. The digest must equal the receipt authenticated by the CPU leaf frame. This is a hash/encoding check, not another numerical GKR verification: the leaf circuit already checked that proof, its artifact, local closure, eta and physical terminal binding.
4. Reconstructs the canonical manifest and shared challenges through `Manifest.commitViews`, then compares every CPU public word with `cpu_leaf.expectedWords` and every truth frame with its original leaf helper.
5. Recomputes initial/terminal RAM claims from complete authorized public cell lists through `expected_boundary.claim`. These large lists stay native rather than being hashed inside the circuit.
6. Aggregates all physical CPU claims and truth claims, excludes absent-relation claims, and invokes the original separate RAM/KIO/Wire closure authority.

Worker, public-word and terminal-sidecar limits are explicit. Receipt encodings and fields retain their original canonical bounds. Current production row-secp truths are covered; obsolete product/linear `.secp` truths fail closed until they have a matching admitted recursive leaf.

Qualification uses a real complete modern fixture with two CPU shards, Keccak and row-secp ADD/DOUBLE. It is produced and freshly verified under the exact registered `conjectured128_b2_q108_p20_fold4` configuration with independently acquired `Fixed.Binding` authorities. Metadata closure reproduces the native manifest. Altered CPU frame, terminal marginal, truth manifest and exceeded sidecar budget are rejected.

The same test builds the complete CPU graph at that target profile, matching its native final transcript and every public word: 11,261,794 variables and 2,054,720 Blake G gates. These are graph counts, not recursive STARK timings. The focused root passed 41 tests including transitively imported native admission tests. Actual production-layout circuit proofs, outer-root authentication/folding and the real seven-segment block remain separate qualification gates.
