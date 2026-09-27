# Production v5 durable bundle transport

`block_v5_cpu_bundle_store_v1` stores all base proof families through typed
ownership sinks, then reopens one proof at a time through the production global
receiver loaders. A successful write consumes the proof only after synced file
publication. A loader slot can be attempted once; an error cannot be followed by
a replacement file in the same receiver session. Store ownership uses the
producer/receiver allocator; no proof receipt is persisted.

The independent `block_v5_cpu_bundle_policy_v1.build` derives each codec's exact
column counts, composition split, FRI bound, admitted claim count, PCS config
and fixed/main roots from complete public receiver pins. Packed execution
sidecars additionally pin their witness root. Genuine external-only shapes omit
ordinary request/projection files only through the existing validated empty
branches. Sparse caller proofs use their actual execution ordinal. No proof
bytes or received manifest choose geometry or a key.

The versioned `block-v5-bundle.files` manifest is a fixed-width canonical roster
of family, index, byte length and SHA256. Both file and aggregate byte caps, file
count, proof bytes, claim count, and metadata bytes are explicit. Read checks
length and SHA before typed decoding. Generic STARK envelopes admit their
structure without allocation before postcard decoding; fresh global receivers
still check transcripts, all equations and global closures. Native, caller
arithmetic and six-table providers retain their existing strict codecs.

`block_v5_cpu_receiver_policy_file_v1` persists complete receiver public pins and
recursive setup schedules with owned reconstruction lifetimes. Its reader
requires an out-of-band SHA256 plus independent job, source-image, program,
initial/final RW roots and PCS security identity. File, owned-allocation,
execution, roster, ROM and schedule caps are explicit. Decoded metadata passes
complete global and recursive policy validation before being exposed. A newly
written digest is a policy proposal; applications must independently admit that
digest before using it to accept a received bundle.

Qualification: the narrow ReleaseFast transport gate passed **9/9** with clean
`std.testing.allocator` teardown. It compiled every typed sink/loader and codec
body, the independent geometry builder, and owning metadata read/write.
Canonical manifest roundtrip, wrong SHA, aggregate caps, duplicate order and
single-use loader negatives passed. Log: `/tmp/block-v5-bundle-store-gate.log`.
The actual production-driver valid-proof roundtrip remains pending; this gate
attests transport/type boundaries and does not confer complete-block authority.
