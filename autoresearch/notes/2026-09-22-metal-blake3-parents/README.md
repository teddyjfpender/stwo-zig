# BLAKE3 Metal resident parent chains

2026-09-22, CPU host + source-JIT Metal, ReleaseSafe, dirty worktree. A shared
seven-round MSL BLAKE3 compression owner now serves PoW and Merkle parents.
The node frame preserves all digest bits: 28-byte protocol/domain prefix followed
by 64 child bytes, compressed with first-block CHUNK_START and final CHUNK_END|ROOT.

Distinct plain, sparse and tail parent pipelines are registered and included in
the generated ABI. A typed family-aware entry point reuses the existing resident
parent-chain plan, ordered command encoding, threadgroup barriers and arena bounds.
The legacy parent-chain API delegates to the same implementation with Blake2s.
BLAKE3 parent admission requires zero seed/prefix arguments (domain is protocol-owned).

Actual device parity covers depths 1, 5, 11, plus a 1,024-parent sparse-only layer;
each plan is executed twice with changed full-bit input digests. Every layer and
every padding/guard word matches the CPU oracle. Nonzero arena offsets are used.
The depth-11 tree has 2,048 leaf digests and 2,047 parent nodes. Its two final
GPU-duration samples were 0.152833 and 0.150500 ms. These are isolated kernel
measurements, not end-to-end prover timing or an A/B speedup verdict.

Combined shader-authority/PoW/parent gates passed 11 tests (9/9 steps). After
adding explicit seed/prefix rejection and sparse-only coverage, the focused
parent gate passed 2/2 tests (3/3 steps; one named device test plus an imported
anonymous test). PoW parity through 26 bits still passed after the shared
compression refactor. ABI generation passed. No actual AOT run was performed.

The resident chain exercises sparse and tail dispatch, including multiple
threadgroups. The plain parent kernel is compiled/registered but is not separately
executed by these chain tests. BLAKE3 full commitment admission remains disabled:
hash_domain.parameters(core BLAKE3) returns null, and generic leaf-family admission
rejects the parent-only family. Leaf absorption/finalization, FRI and resident
transcripts still need implementation and qualification. No full Metal/CSP proof
or default migration claim follows from this gate.

Commands through scripts/zig_serial_build.py, cwd src/backends/metal:
update-abi-declaration-digests; test-blake3-parent-chain test-shader-authority
test-proof-of-work; final test-blake3-parent-chain. All use
-Doptimize=ReleaseSafe --summary all.
