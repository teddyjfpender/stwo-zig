# Heavy CPU source-seal assessment

This is a witness-free source/resource model, not a proof or a rerun of the heavy guest. All 57 independently reconstructed CPU local GKR rosters fit the 12 GiB child cap, but the complete worker does not fit just because its child does.

The measured retained capture/setup baseline is 25,516,298,742 bytes. The largest checkpointed GKR child needs 7,801,303,296 bytes; that same shard adds 2,599,431,260 bytes of MAIN coefficients and conservative full Merkle payload. Their sum is 35,917,033,298 bytes, already above the 34,359,738,368-byte common cap before source construction and PCS scratch. Schema-2 setup differs from the measured schema-1 baseline, so these are diagnostic payload bounds, not an exact total RSS forecast.

The existing release path already retires raw capture records after ordered ledger append, frees normalized ordinary events on source consumption, and releases temporary ALU/BINARY/SHIFT/MUL/DIV grouping arrays after provider construction. `Prepared.takeCpu` moves the 56-byte-per-retirement metadata into the source. It does not duplicate that large array. That metadata remains necessary for local GKR projection and the post-manifest binding witness. Releasing it without preserving those obligations would be unsound.

The next change should park inactive per-shard metadata with bounded disk ownership and source binding, restoring one active shard at a time. This preserves batch geometry and proof authority. No heavy proving or cap increase is justified by this assessment.

Qualification: `OP retained heavy CPU source checkpoint seal assessment uses exact roster constants` passed in ReleaseFast. The numerical descriptors are never passed to source authority or a prover. The JSON contains every per-shard result and explicit exclusions.
