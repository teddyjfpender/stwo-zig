# Metal BLAKE3 direct lifted leaves

2026-09-22. Added canonical BLAKE3 direct leaf hashing to the existing resident
leaf plan and shared compression implementation. Leaf messages stream the exact
28-byte domain frame and LE32 M31 values through BLAKE3's chunk/CV stack. Internal
BLAKE3 parent compression remains distinct from protocol Merkle-parent framing.
Full 256-bit output is retained. No protocol or production default change.

`prepareMerkleLeavesForFamily(..., .blake3)` calls the versioned family ABI;
nonzero seeds or legacy prefix lengths are rejected in Zig and C admission.
The existing BLAKE2s wrapper delegates to the same typed implementation.
One explicitly registered pipeline is present in the common source/AOT runtime
initialization. Actual device execution used source JIT; no AOT execution claim.
Full suite admission stays disabled pending staged leaves, FRI and transcript.

Qualification: 14 widths (1,8,9,10,248,249,250,505,506,761,762,1017,1018,2042),
32 lifted rows each, two distinct inputs per reused plan: 896 CPU/GPU digests
match exactly. Input columns have heterogeneous sizes and nonzero offsets;
entire arenas compare, preserving source data, padding and destination guards.
Cases cross 64-byte and 1024-byte boundaries, exact chunk endings, balanced and
unbalanced chunk trees through nine chunks. Empty-column runtime plans remain
unsupported; no full-u32-width allocation or wide-offset arena test is claimed.

Final ReleaseSafe gate: 24/24 tests, 6/6 steps, including actual leaf dispatch,
AOT profile inventory/declaration tests and shader authority. Parent regression:
2/2 tests passed in device.log. Initial logs retain a missing Zig namespace
compile failure and stale imported AOT expectations. The final assertions pin
the updated core source digest and 171 core/176 Ethereum exports. Existing
recursive coverage assertions now match the manifest and runtime's two sets
of three scan stages; this is inventory validation, not new recursion timing.

Commands:
```sh
python3 scripts/zig_serial_build.py --cwd src/backends/metal update-abi-declaration-digests -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/backends/metal test-blake3-leaves test-blake3-parent-chain test-shader-authority -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/backends/metal test-blake3-leaves test-blake3-parent-chain -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/backends/metal test-blake3-leaves test-shader-authority -Doptimize=ReleaseSafe --summary all
```

The per-dispatch times in logs are diagnostic small-grid timings, not a CSP or
recursion speedup measurement. Remaining migration includes wide/direct and
staged commitment integration, FRI/resident transcript and full Metal proofs;
prover-owned Poseidon statement identities and production recursive keys also
remain. Next design staged BLAKE3 state with bounded per-leaf storage based on
actual column width, avoiding a maximum-size CV stack in every resident leaf.

Algorithm source: https://github.com/BLAKE3-team/BLAKE3/blob/master/reference_impl/reference_impl.rs
See the archived compact match brief for mapping and bounds. Source snapshots
and relative SHA256SUMS accompany the logs.
