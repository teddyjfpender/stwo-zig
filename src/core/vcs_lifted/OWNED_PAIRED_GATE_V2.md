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

Query draws reject a zero count without moving the transcript. Once the
terminal query event begins, any sampler failure leaves the plan complete and
cannot be retried on the same object. The query count and block cap still
come from the caller; a selected verifier must derive and freeze them from its
sealed configuration.

This boundary does not derive the statement or manifest from a sealed key.
The caller must supply both from trusted, checked verification data, including
four source-tree descriptors, the circuit digest, FRI parameters, and the
line-tree roster. The full PCS/FRI
verifier, root and source-tree checks, non-squaring FRI query correspondence,
BCS/ROM reduction, and native security-bit assignment remain open. A `true`
Merkle opening result is only a local path check, never proof acceptance.

The focused test checks event ordering, one root absorption, copied input
metadata, cached opening verification, private query access, and rejection
of a mismatched statement. These are candidate API tests, not soundness tests.
