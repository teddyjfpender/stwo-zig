# Resident lifted trace commitments and openings

The RV64 CUDA lane can now commit mixed-height base-field columns, mix the
device root into the native OM31 channel, draw raw query positions and extract
compact trace openings without an intermediate field-value transfer. Fresh
native lifted-Merkle receivers accept those openings. This is a PCS building
block, not yet a complete PCS, Stark or Ethereum proof.

The commitment wrapper reuses the existing domain-prefixed Blake2s mixed-leaf
and parent kernels. The `MixedSegment` layout is now shared in one header;
moving its declaration does not change its 32-byte ABI or hashing arithmetic.
Segments contain contiguous column slabs in stable ascending column-height
order, matching native lifted PCS. All source allocations, capacities, heights,
ordering, tree alignment and writable overlaps are checked before enqueue.
The complete tree stays resident in level-packed leaf-to-root storage.

Opening queries preserve the circle-domain pair bit when reducing or expanding
from the global query domain to a tree. The same rule then maps the tree query
to each column's own domain. This differs from a plain right shift. The GPU
gathers base values and sibling paths directly from retained device buffers;
only compact values, paths, roots and channel state leave after completion.

The typed PCS commands borrow generation-checked device slices and retain
sticky enqueue failure. The host assembler restores original column order,
sorts/deduplicates the global raw query positions and compresses redundant
Merkle paths. It checks canonical field words and conflicting duplicate values
or hashes. It performs no field arithmetic, hashing, challenge derivation or
feedback into the GPU. Allocation-failure tests cover the ownership transfer
to the native proof containers.

The cold segment list and column permutation are trusted program geometry,
not producer-authoritative proof data. The accepting execution receiver still
needs its statement/FIXED authorities and the complete PCS/AIR transcript.
Hashing and opening a set of columns does not establish their AIR validity or
their connection to GKR and global claims.

## Qualification

Six native oracle cases cover stable reordering of mixed-height columns,
both tree/query height directions, explicit tree lifting above every column,
duplicate queries, a 512-column tree and a log-14 tree. The GPU root, raw query
list and final channel are byte-exact against native. The assembled queried
values and compressed hash witness are also byte-exact against the native
decommitter. Each fresh receiver verifies the actual assembled proof, rejects
modified values/roots and nonempty paths, then verifies the restored proof.

The GPU driver additionally rejects invalid queries, noncanonical opened
values, sticky prior failures, short allocations, overlapping outputs,
malformed/unsorted segments and foreign-context pointers. Normal execution and
memcheck/racecheck/initcheck/synccheck pass on RTX 5090. Each sanitizer run is
followed by a fresh native Linux receiver; all compact captures are byte-equal.
Host tests pass 72/72 in ReleaseSafe and ReleaseFast, with real native FFI
compilation in both modes.

```
zig build --build-file src/integrations/riscv_cuda/build.zig \
  rv64-trace-fixtures -Doptimize=ReleaseSafe -- export /tmp/rv64-trace-fixtures
zig build --build-file src/integrations/riscv_cuda/build.zig \
  rv64-trace-fixtures -Doptimize=ReleaseSafe -- \
  verify /tmp/rv64-trace-fixtures /tmp/rv64-trace-readback
```

`scripts/rv64_cuda_trace_qualify.py` builds and qualifies the native wrappers
and records source/fixture/dependency/executable/log hashes. Receipts are in
`vectors/reports/rv64-cuda-trace-openings-20261103/`. No whole-block performance
or accepting whole-block GPU proof is claimed.
