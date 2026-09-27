# Canonical BLAKE3 protocol framing — 2026-09-21

Previous turn: progress, complete private digest composition. This turn removes
separate byte-encoding authorship between the native BLAKE3 suite and recursive
message construction. The production migration and original recursion goal stay
active.

`src/core/channel/blake3_frame.zig` now owns the protocol prefix, nine operation
tags and exact little-endian payload encodings. A Frame streams into the native
hasher or writes the same message into a checked-size byte buffer for recursive
witness generation. The channel delegates absorption and draws to Frame; Merkle
nodes delegate to Frame and streaming leaves share its word writer. PoW retains
its prehashed-prefix grinding path through the same prefix writer. No extra
message allocation was introduced into native hashing.

This is an encoding refactor, not a new hash algorithm or a protocol-version
change. All existing `stwo.blake3.experimental.v1` bytes are preserved. The old
channel-local absorption encoders and Merkle node encoder were removed. The
pinned independent protocol vectors remain unchanged and pass.

The new framing gate covers all nine domains, encoded length/prefix/tag checks,
full-hash witness parity with the standard BLAKE3 implementation, native channel
operations, draw indexing, PoW predicates, streaming leaves and parent nodes.
The existing protocol gate additionally checks independent pinned vectors,
primitive vectors, rejection boundaries and real CPU PCS/FRI verification.

A new complete CPU proof hashes the canonical Merkle-node frame and verifies its
output against the native commitment hasher. Its two child digests include high
bits in every byte. This proof uses public child digests; private byte routing
and Merkle path composition remain unfinished. Existing compression, full-hash
and private-composition proof gates use the shared framing too.

Commands:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-framing test-blake3-protocol -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-proof test-blake3-private-proof -Doptimize=ReleaseSafe --summary all
```

The first command passes six guarded tests; the second passes four, including
the new framed-node proof. Both final logs are recorded alongside source pins. Proof gates retain eight queries, blowup 1 and zero PoW
for short development loops. Their runtimes are not production benchmarks or
security qualification, and no speedup is claimed from this refactor.

Next: bind private digest/field bytes into these exact, potentially unaligned
frames; admit actual recursive caller sources; constrain challenge rejection and
PoW; compose Merkle paths; version trusted keys/artifacts; qualify Metal and
complete parent-of-parent proofs with production security. Product defaults
remain on Poseidon.

Source conformance remains at the same 103 pre-existing finding identities.
Formatting and diff checks pass; earlier evidence snapshots were preserved.
