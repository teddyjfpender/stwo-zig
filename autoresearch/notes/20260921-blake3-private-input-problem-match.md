# Private BLAKE3 input binding

Task: replace public-message boundary rows with authenticated caller-wire
consumption, preserving all 32 bits and partial-word zero padding.
Canonical transfer: the existing signed LogUp wire copy relation. A bridge row
consumes one upstream word and emits its identical four byte coordinates into
the hash graph with the graph-derived multiplicity. Both namespaces and wire IDs
are verifier-owned fixed data. Independent per-byte fixed zero selectors bind
unused bytes of a final partial word. This is an equality/copy constraint, not a
hash computation or caller-admission shortcut.

Existing implementation evidence: blake3_boundary.zig, blake3_g_call.zig and
universal_relation_binding.zig. Reuse their exact registry and compiler; no new
relation ID or handwritten evaluator. Arithmetic degree two; two relation events
paired into one interaction batch. Reject an unbound upstream tuple by requiring
the caller component's balancing emission in the assembled proof.

Alternative: publishing private message words in preprocessing is incompatible
with recursion; accepting a host witness read as authentication is unsound.
The copy bridge preserves the same bounded-byte representation across owners.

Validation: semantic pin, typed definition/degree/direct export, wire closure
against independent source and hash requests, source/destination/byte/weight
mutations, and nonzero unused bytes. Production assembly must still bind caller
identities and compose this bridge into full STARK proofs. This alone does not
qualify a recursive child-proof adapter or arbitrary byte repacking.
