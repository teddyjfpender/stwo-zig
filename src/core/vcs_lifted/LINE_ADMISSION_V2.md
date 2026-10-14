# Candidate one-time line manifest admission

`line_admission_v2.zig` is an internal candidate for the reserved
`S31NAT9F` protocol. It builds on the exact line-tree manifest from
`line_descriptor_v2.zig`. No production verifier selects it.

`AdmittedLineManifestV2.init` checks the complete manifest digest against
`StatementBinding.line_profile_digest`, matches the sealed key digest, and
requires a fresh framed channel at the statement event-0 digest. It hashes
the manifest once, then copies at most 126 opening shapes into an opaque
heap object. The channel's storage must outlive the cache and must not move
after admission. The copied shapes contain track, fold height, tree log size,
column count and exact root-event ordinal. Later mutation of the caller's
manifest arrays cannot change those shapes. Call `deinit` when finished.

At a planned line-root event, `captureRootAtNamedEvent` checks the channel
cursor, mixes that root into the same framed channel, and stores the exact
root bytes once. `verifyCapturedOpening` uses only the stored root and copied
shape, checks row width and canonical M31/path rules, and does not rehash the
manifest per opening. `allRootsCaptured` tells the caller whether all named
line roots were seen.

For a manifest of `B` bytes and `q` openings, admission hashes `B` bytes
once instead of the earlier helper's `q × B`; Merkle-path work remains.
This is a structural cost comparison, not a whole-verifier measurement.
The focused test follows the proposed channel event sequence through the
first fold alpha, captures both line roots, and checks reuse, duplicate
capture, wrong events, wrong statements, row widths and input mutation.

The admitted cache is opaque to normal Zig callers, but the framed channel
is still separately mutable. This module checks the cursor and root bytes;
it does not enforce all preceding Gate event roles, connect each column
identity to a key-owned oracle, or prove that a caller keeps the channel
private. A selected verifier must own the full event-plan wrapper and
channel, derive the manifest from a sealed key and checked geometry, and
make this cache inaccessible to proof-controlled code. It must also prove
consistent raw-query projection through every FRI fold. No BCS/ROM theorem,
native security bits or proof selector follows from this cache.
