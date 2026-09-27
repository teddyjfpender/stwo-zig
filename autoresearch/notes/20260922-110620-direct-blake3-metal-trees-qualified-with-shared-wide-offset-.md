---
title: Direct BLAKE3 Metal trees qualified with shared wide-offset leaf hashing
author: Teddy Pender
created_utc: 2026-09-22T11:06:20Z
---

# Direct BLAKE3 Metal commitments and wide offset dispatch

2026-09-22. Added exact canonical BLAKE3 admission to the ordinary Merkle
commitment entry point, independent of unfinished transcript/staged-state
admission. Direct and heterogeneous commitments share the same typed domain
helper; the latter retains its width-sized staged layout. Small/empty workloads
still follow the existing backend cost policy rather than bypassing it.

A 64-bit-offset BLAKE3 leaf kernel now handles the direct runtime's column arena.
Both u32/u64 kernels call the same templated leaf implementation. Runtime
allocation, offset packing, pipeline selection, canonical zero seed/prefix
checks and mandatory shader initialization are connected. Parent hashing uses
the previously qualified BLAKE3 pipelines. No hash protocol or default changed.

Final direct/leaf/shader gate: 26/26 tests, 9/9 steps. Ten direct full-tree cases
(widths 1,9,249,250,762; uniform and mixed logs) match CPU roots via the actual
resident MerkleTree.commit implementation. The existing all-leaf parity and
AOT inventory/declaration checks also pass. The wide-offset kernel executed
with small arenas; offsets or arenas above 2^32 words were not allocated/tested.
Tests invoke the resident wrapper directly, without claiming an unforced
production cost-policy crossover. Small-grid correctness times are not CSP
or recursion performance measurements.

The shared domain-helper regression passes 3/3 tests, 3/3 steps;
its terminal result is retained in heterogeneous-regression.log. Initial direct
qualification is retained in qualification.log; ABI regeneration in abi.log.
Core inventory now has 174 kernels and Ethereum 179, with the updated source
pin. Actual device execution was source JIT, not an AOT bundle execution.

Commands:
```sh
python3 scripts/zig_serial_build.py --cwd src/backends/metal update-abi-declaration-digests -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/backends/metal test-blake3-direct-tree test-blake3-leaves test-shader-authority -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/backends/metal test-blake3-heterogeneous-commit -Doptimize=ReleaseSafe --summary all
```

Remaining: combined uniform transform/commit selection, resident transcript,
FRI cascade, full Metal BLAKE3 proof and canonical CSP timing. Existing ordinary
and heterogeneous commitment support does not establish those paths. Prover-owned
Poseidon identities and production recursion remain part of the migration.
