---
title: Typed Metal BLAKE3 FRI trees qualified with canonical packed ordering
author: Teddy Pender
created_utc: 2026-09-22T10:46:34Z
---

# Typed Metal FRI commitment trees with BLAKE3

2026-09-22. The existing prepared FRI tree now dispatches packed leaves and
parents by its explicit hash family. A versioned prepare ABI admits BLAKE3 with
zero seeds/prefix and retains the old BLAKE2s wrapper. The BLAKE3 packed kernel
uses the already qualified canonical leaf framing/compression owner, preserving
QM31 row-major coordinate order from planar resident evaluations. This is
integration of the existing hash algorithm, not a new hash construction.

Fixed an existing BLAKE2s packing defect: log_rows_per_leaf=1 was admitted but
read and hashed four rows. The kernel now reads exactly 1<<log_rows_per_leaf
rows and hashes their actual byte count. One/four-row encodings are unchanged.
Preparation rejects overlapping evaluation/layer storage, invalid geometry,
unknown families, incompatible BLAKE3 seeds and prefixes, and spans exceeding
u32 kernel addressing. Execution checks every parent layer before dispatch.
Nonmonotonic offsets remain supported, including root-first arena allocation.

Device qualification covers BLAKE3, prefixed BLAKE2s and plain BLAKE2s; packing
1,2,4 QM31 rows per leaf; 128 evaluations; heterogeneous coordinate stride;
two changed inputs per reused plan. All 18 complete trees (2,670 leaf/parent
digests) match canonical CPU hashing, with full-arena guard/source checks.
BLAKE3 accounts for six trees/890 digests. Invalid plans and a parent-truncated
arena are rejected without mutation. These are small-grid correctness timings,
not CSP or recursion performance results.

The final focused ReleaseSafe gate passes 24/24 tests, 3/3 steps, including
the two u32 overflow cases (bounds-gate.log; 723ms test runtime).
Shader authority passed 6/6 tests in qualification.log. Retained initial logs
include two test compile errors and stale ABI-assertion failures. ABI assertions
now reflect the inspected C fold/cascade signatures and new FRI-tree family
argument. AOT source digest and inventory pins now include 172 core kernels and
177 Ethereum kernels. Device execution is source JIT, not AOT qualification.

Commands (all serialized):
```sh
python3 scripts/zig_serial_build.py --cwd src/backends/metal update-abi-declaration-digests -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/backends/metal test-blake3-fri-tree test-shader-authority -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/backends/metal test-blake3-fri-tree -Doptimize=ReleaseSafe --summary all
```

Remaining: this is a prepared FRI commitment tree, not a complete FRI protocol.
BLAKE3 fold/cascade transcript integration, staged/wide trace commitments,
full Metal proof verification, prover-owned Poseidon identity migration and
production recursive keys remain. Global BLAKE3 suite admission/defaults are
still unchanged. Existing Cairo recipe still explicitly uses its legacy suite.
Next staged-leaf work must replace fixed 8/16-word state assumptions with a
width-bounded chunk state, preserving partial blocks and CV stacks across
heterogeneous lifting without allocating maximum-sized state per resident row.
