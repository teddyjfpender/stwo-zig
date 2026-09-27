# Shared authenticated digest frame routing

Task: route authenticated transcript state/root digests into canonical BLAKE3
frames without treating private bytes as trusted preprocessing constants.
Exact match: the existing symbolic Merkle frame byte routing, generalized from
fixed left/right roles to explicit digest-role bindings. The native Frame.write
method remains the sole byte-format authority. Literal framing and public scalar
payloads remain fixed; bound digest bytes become authenticated wire selectors.

Transfer: reuse the same two-source byte-selection AIR and source-use accounting.
At most two digest roles occur in a current frame. Adjacent digest bytes can span
two word sources per four-byte destination. Reject missing, duplicate or unused
role bindings, overlapping namespaces and invalid wire ranges. No cryptographic
or constraint change. Keep the Merkle API as a thin compatibility wrapper, removing
its duplicate routing implementation. O(encoded frame length + hash DAG size).
Source semantics: core/channel/blake3_frame.zig, existing blake3_node_route.zig.

Alternative: separate transcript router duplicates byte layout and consumer counts;
rejected. Full private scalar payload conversion is not supplied by digest routing.
This step supplies private state/root wiring, not a complete transcript scheduler.

Validate canonical bytes for draw, integer, root and PoW frames, source counters,
malformed bindings, allocation failures and existing complete routed Merkle proof.
No production speed claim. Subsequent assembly must replace public input boundary
rows and authenticate producer multiplicities before claiming private transcript
state transitions are proven.
