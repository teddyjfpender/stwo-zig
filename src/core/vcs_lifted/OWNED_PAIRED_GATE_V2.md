# Candidate owned paired Gate transcript

`owned_paired_gate_v2.zig` is a candidate custody boundary for the reserved
`S31NAT9F` protocol. It is not selected by a production verifier.

`OwnedPairedGateVerifierV2.init` validates and hashes the line manifest once,
checks its digest and key digest against the statement, copies the fold roster
and opening shapes, and allocates the event plan and admitted cache together.
The cache points at the channel inside that stable allocation. Its opaque API
returns no mutable plan, channel, root cache, or query position slice. It
destroys the cache and sampled queries before freeing the allocation.

The public methods follow the proposed four-source-root, two-FRI-track order.
The two line-root methods check the current track and fold height, absorb a
root at its named event, and retain that same root for Merkle opening checks.
The event plan advances only after successful capture. The terminal sampler
keeps raw query words and sampled positions inside the object, and exposes
individual positions by value. Opening checks use the captured root and
copied row width and tree height; the manifest is not rehashed per opening.

For this candidate, the first fold height `k` is the raw query-domain log
size. Fold heights must be `k, k-1, ...`, and each nonterminal original and
own-quotient line tree must have `tree_log_size = fold_height - 1`. A sampled
raw position is always less than `2^k`. At line tree `i`, the selected row is
`raw >> (i+1)` in bit-reversed FRI query order; equivalently it is
`raw >> (k - tree_log_size)`. The public opening API takes a sampled query
ordinal and derives this leaf index privately. It rejects an ordinal beyond
the stored query count and a mismatched fold/tree height. A valid opening
for the other leaf cannot be replayed at the selected ordinal. The adjacent
line row also needed by a full fold relation is not yet authenticated here.
The projection matches the selected row of the pair opened in the experimental
`paired_sparse_cascade_heights_experimental.zig` verifier, whose pair base is
`((raw >> (i+2)) << 1)` for line tree `i`.

`verifyAndReadLinePair` authenticates **both** rows at `pair_base` and
`pair_base+1` under one captured root. Each row has four canonical M31 words,
forming one QM31 line value. `verifyAndReadBothTrackPairs` does this for the
original and own-quotient tracks together and returns no values unless all
four paths verify. Neither method accepts a leaf index. A wrong neighbor or a
replayed path at the other position fails its Merkle check.

`initWithSourceRoster` additionally admits an H1 source profile. All source
columns must have log size `k`, and the composition tree must have eight
columns. The source descriptor encodes `S31SRC2V`, the fixed source hash
profile, its two eight-byte BLAKE2s contexts, the key digest, root ordinal,
named root event, query log, column count, and each column's little-endian
log plus full 32-byte identity in order. The four named root events are
`1, 4, 10, 12`. The descriptor is framed under `tree_context` event zero and
must match the corresponding statement digest before the object is created.
The source profile uses `S31S2LEF` for canonical M31 row leaves and
`S31S2PAR` for 64-byte `left || right` parents. It is distinct from the
production plain profile and the candidate line profile. The fixed profile
and complete column roster are checked once; the selected verifier still
must derive the key, identities, and statement from one sealed source.

At an H1 query ordinal, `verifyAndKeepSourcePair` derives the source pair
indices `raw & ~1` and `(raw & ~1)+1` from the privately stored raw query.
It checks both rows in all four personalized source trees against roots
absorbed in this same transcript. The caller supplies only row values and
Merkle witnesses. The verifier converts its own OOD seed to a point, retains
the canonical claims it mixed into the transcript, draws its own batch
challenge, and computes CAS09's `RowContext` formula over the authenticated
columns in roster order. It privately retains two original and two
own-quotient insertion values per query. A wrong root, row, or pair index
fails; malformed or noncanonical claims fail before transcript absorption.
An arbitrary canonical claim remains only a transcript-bound assertion at this
stage. Its correctness against the committed source polynomials requires the
future quotient/fold and degree checks; this local source-path API cannot
reject such a wrong claim on its own.
The source roster is deliberately H1 only. Sparse, lower-height columns fail
admission until their checked lifting and claim layout are specified.

This does not yet check the CAS09 one-step relation. For each track that
relation is `fold(previous_pair, line_x, alpha) + alpha² ×
fold(inserted_source_pair, circle_y, alpha) = selected_next_value`.
Here `fold(a,b,c,alpha) = a+b+alpha×(a-b)/c`, matching CAS09's native
unscaled butterfly. The line and circle coordinates and both divisors are
fixed by the checked domain geometry.
The inserted values now have private custody for the H1 source profile, but
the object does not retain fold alphas or enforce the fold equation, terminal
degree condition, or four-root AIR relation. Local Merkle authentication and
insertion computation do not imply proof acceptance.

Query draws reject a zero count without moving the transcript. Once the
terminal query event begins, any sampler failure leaves the plan complete and
cannot be retried on the same object. The query count and block cap still
come from the caller; a selected verifier must derive and freeze them from its
sealed configuration.

This boundary does not derive the statement or manifest from a sealed key.
The caller must supply both from trusted, checked verification data, including
four source-tree descriptors, the circuit digest, FRI parameters, and the
line-tree roster. The full PCS/FRI verifier, non-squaring FRI query
correspondence, and the BCS/ROM reduction across framed transcript hashes,
personalized source hashes, and personalized line hashes remain open. In
particular, the local tests do not establish a 96-bit collision bound for
any of those profiles. Native proven security bits remain unset. A `true`
Merkle opening result is only a local path check, never proof acceptance.

The focused tests check event order, named root absorption, descriptor byte
vectors against independent Python, copied metadata, source and line Merkle
paths, private query projection, claim shape, and rejection of wrong rows,
roots, and source pair indices. These are candidate API tests, not a PCS/FRI
soundness proof.
