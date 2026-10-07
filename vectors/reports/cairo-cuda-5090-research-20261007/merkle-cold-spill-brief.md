# Problem match: offload a cold Merkle tree instead of hot AIR columns

**Task and semantics.** Preserve the exact canonical Cairo proof while
freeing HBM for constraint evaluation. CUDA managed-memory placement changes
only the location of authenticated, unchanged words; it must not change the
Merkle root, decommit path, transcript, or proof bytes.

**Scale and structure.** The resident plan for both the 4M and 8M PIEs has a
4,294,967,264-byte `trace_merkle_hashes` slot for the preprocessed tree,
live from trace commitment through decommit. The 4M no-placement proof ran
through relation and failed from CUDA allocation pressure in constraint
evaluation. Offloading its interaction evaluations fully made the proof
19.025 s, of which 14.870 s was constraint evaluation. A cold, large tree is
a better spill candidate than a repeatedly accessed evaluation range if its
construction and queried openings remain inexpensive enough from host pages.

**Chosen exact variant.** Before the preprocessed commitment's first write,
host-prefer only the authenticated preprocessed Merkle-hash slot. Leave
writer scratch and main/interaction evaluation columns under their normal
managed placement. The preprocessed commitment, root capture, OODS, FRI, and
decommit code remain unchanged. The optional policy can combine with the
existing selective interaction-evaluation spill for geometries that need
more than this tree's 4.29 GB.

**Prediction and falsifier.** On the 4M PIE, the tree alone may keep total
resident HBM below the 5090 budget and substantially reduce the 14.870 s
constraint cost. A complete proof must equal SHA-256
`0d74ce722cfdadc65b046057fcef2a5a2da52d9fccc74fd85b69154b8cc90a39`
and pass the pinned Rust verifier. Record preprocessed-commit, constraint,
decommit, full proof, publication, GPU peak, and host RSS. If commitment or
decommit becomes more expensive than the saved constraint work, reject this
placement. For the 8M PIE, expect to need a second spill; a single tree is
smaller than the apparent capacity gap.

**First results and next spill.** The preprocessed-tree-only policy produced
the exact 4M proof and passed Rust verification. It reduced proof execution
to 5.554 s and adapted-input-to-publication to 9.282 s, with 28.49 GiB
sampled device use. Constraint evaluation fell below one second; the
preprocessed commitment grew by roughly one second. On the 8M PIE, combining
the preprocessed tree with a 75% interaction-evaluation spill still failed in
constraint evaluation at the CUDA memory ceiling. Its resident plan also has
roughly 1.07 GB each of main and interaction Merkle hashes. The next exact
variant host-prefers those two trees before their first writes. It may fit
without moving more hot evaluation columns, and each added tree's commitment
cost will be measured separately.
