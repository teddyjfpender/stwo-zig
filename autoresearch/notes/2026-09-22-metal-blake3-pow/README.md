# BLAKE3 Metal PoW: actual device qualification

2026-09-22, local dirty worktree, ReleaseSafe, source-JIT Metal runtime.
Core computes the exact CHUNK_START CV for the channel's 64-byte prefix through
its canonical framing/compression owners. A distinct Metal kernel computes the
8-byte nonce block (counter 0, CHUNK_END|ROOT), preserving all nonce bits. The
kernel uses the existing add/xor/rotate round primitive with the BLAKE3 seven-round
schedule, not BLAKE2s compression initialization or finalization.

Backend/FFI/runtime/manifest/ABI dispatch are integrated. The shared bounded
channel search runs ordered intervals of 2^20 candidates and atomically selects
the lowest local match. Generic PCS revalidates the returned nonce with the
canonical host channel before mixing it. No host grinding fallback is used.

| Difficulty | CPU and Metal lowest nonce | Measured device dispatches |
|---|---:|---:|
| 8 | 354 | 1 |
| 12 | 5,017 | 1 |
| 21 | 2,021,245 | 2 |
| 26 | 63,024,448 | 61 |

All cases assert zero CPU fallback telemetry. Prepared-CV terminal compression
also matches all 32 canonical digest bytes for nonce 0, 1, 2^32 and 2^64-1.
This validates high nonce bits in preparation/compression; the device searches
listed above do not themselves cross the 2^32 boundary.

Metal PoW plus shader authority: 9/9 tests, 6/6 steps. The two named device tests
exercise legacy BLAKE2s and new BLAKE3; the run includes an anonymous import test.
Six authority tests validate ABI declarations and common source/AOT initialization.
Actual AOT execution was not run. ABI regeneration passed. CPU BLAKE3 protocol
regression passes 8/8 tests. No runtime/speedup comparison is claimed.

The prior PoW build gate had lazy facade imports and omitted runtime linkage;
it reported an anonymous import test without discovering its intended device
test. An explicit discovery root plus runtime linkage fixes that gap. The initial
misleading run is retained as initial-discovery-only.log and is not device evidence.

Commands (through scripts/zig_serial_build.py, cwd src/backends/metal):
update-abi-declaration-digests, then test-shader-authority test-proof-of-work,
all -Doptimize=ReleaseSafe --summary all. CPU regression: cwd
src/integrations/riscv_cpu, test-blake3-protocol with the same build options.

This qualifies only the PoW stage. BLAKE3 Merkle/FRI/resident transcript dispatch,
end-to-end Metal proofs/CSP, production defaults and Poseidon boundary replacement
remain unfinished. Runtime requires the new kernel in its admitted library;
old AOT libraries must be rebuilt through their existing manifest admission.
