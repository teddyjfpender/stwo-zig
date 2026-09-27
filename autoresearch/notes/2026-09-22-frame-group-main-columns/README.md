# Frame and Merkle group main-column destinations

The shared frame builder now forwards caller-owned main columns and metadata to
the canonical hash emitter. Routing, filtered boundaries, digest/source/payload
receipts remain shared with row emission. Prepared explicitly marks metadata-only
G/XOR rows. MainColumns validates complete geometry and derives checked logical
subranges, preserving parent offsets.

Merkle groups now admit complete column geometry before emission, pass consecutive
ranges to leaves and merges, and update digest-use counts in XOR metadata. Both
public path directions and privately selected directions use the existing group
builder. Columns are caller-owned; frame/group arenas own only their receipts and
smaller cohorts. Independent trusted preprocessing remains separate.

Focused ReleaseSafe frame/hash gates: 8/8 steps, 6/6 tests. Frame gate 7 s /4 MiB
reported MaxRSS; hash gate 657 ms /32 MiB. Tests reconstruct every hash row after
receipt destruction, compare independently generated fixed suffixes and all
routing/payload/root receipts, cover nonzero offsets and reject malformed output
geometry before earlier columns are changed. Existing row allocation-failure
checks and primitive/interaction column tests pass. No native parent rerun or
end-to-end performance claim at this stage.

Still required: transcript draw/query adapters and STARK-path aggregate forwarding,
parent-wide allocation and ownership transfer, removal of final hash projection,
full native qualification and production-profile timing.

Migration scope explicitly includes core commitment/transcript hashing for ordinary
RISC-V and CSP CPU/Metal proofs. Current ordinary RISC-V prover/types.zig defaults
are BLAKE2s; recursion/engine_protocol.zig uses Poseidon2. Guest Poseidon execution
semantics are separate and must remain available. New suite admission and artifact
identities must precede changing defaults; CSP measurements retain 70 queries and
26 PoW bits. No CSP gain is inferred from the Poseidon primitive microbenchmark.
