# Genuine v7 open-batch reduction

The qualified diagnostic fixture executes two native segments with SHA-256 and
Keccak callers, 12 cycles and 77 RAM events. Six actual original STARKs are split
into two independently keyed open batches, then reduced to one 141,280-byte
root. A fresh receiver reconstructs every family frame, checks exact coverage,
verifies the final proof and closes the original global equations. Original
and intermediate proof bytes, captures and producer rows have been destroyed.

| Stage | Original children | Proof bytes | Retained verifier rows/metadata bytes |
|---|---:|---:|---:|
| Direct batch 0: native 0, native 1, caller, ROM, lookup |5|156,945|1,379,494,332|
| Direct batch 1: joint memory |1|128,975|136,464,644|
| Reduction root |two batches|141,280|not separately sampled|

The first batch is intentionally not globally closed. Its memory relation is
closed only after the final root authenticates the singleton memory batch.
The singleton moves its rows while retaining their allocator owner; it creates
no dummy proof. Both direct and reduction keys/schedules/fixed rows matched
independent cold derivation. Missing-batch rejection passed. The companion
one-child nested gate also rejects changed OODS values, range and expected key.

The 12-test process took 68.04s and maximum RSS was6,171,377,664 bytes. This is the
whole qualification job, including original proofs, cold setup, all recursive
proofs, final verification and negatives. Timings are diagnostic/unranked under
concurrent compilation; these are not isolated production measurements.

Security is q8/pow0. This qualifies real multiple-window reduction, not
canonical security, an Ethereum block, or an actual proof with more than 64
original children. Metadata coverage tests exercised 137 original positions.
The current reduction layer admits32 direct batches of at most 64 originals;
arbitrary-depth reduction remains future work.

See the adjacent JSON for exact stage profiles and binary/log hashes.
