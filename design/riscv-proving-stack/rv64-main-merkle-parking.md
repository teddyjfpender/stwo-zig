# Park committed MAIN coefficients and Merkle nodes

The explicit `Store.initFullyParked(path, disk_limit)` capability parks both
already committed native M31 coefficients and actual retained Merkle node values.
Existing `initParked` remains coefficient-only; defaults do not change. The same
concrete native M31 commitment tree underlies Q and OM proofs. No witness replay,
FFT, recommitment, node rebuilding, transcript draw or proof format is added.

## Disk and stable ownership

One private unlinked reserved FD contains a 128-byte versioned header, the native
coefficient payload and the ordered nonempty Merkle layers. The header records
the prefixed unreduced Blake2s-256 schema, M31 modulus/native little-endian layout,
column/layer counts, offsets, root and canonical shape digest. The stable Owner
records a separate Blake2s payload digest. Only supported little-endian native
M31 captures are admitted. This is durable custody across the live worker's
manifest barrier, not process-restart persistence: the FD is intentionally
unlinked and closes when its owner dies.

Before publication, all shape/alias checks, allocations, disk reservations,
writes and fsync finish. Failure leaves the original resident tree retryable.
The original node allocations and coefficient backing are then released. The
outer layer descriptors remain tree-owned; a stable 32-byte root cell inside the
registered Owner backs layer 0. Other layers and coefficient views become safe
empty descriptors. `root()` stays valid while parked. Decommit/hash reads refuse
with InvalidColumnSize until restoration, instead of indexing absent nodes.

Native Merkle storage has two default-false ownership/state flags. A restored
mapped tree borrows layer values, owns its outer descriptors, and leaves mapping
teardown to the existing tree backing token. This prevents slice frees against
mapped interiors. Borrowed trees are not pruned/lifted through ownership-changing
paths. Ordinary native trees retain their existing behavior.

Restore first resolves the callback/context through the numeric Store registry;
it does not dereference foreign token contexts. It checks exact descriptor
addresses, immutable column/layer shapes, root, file length and header. A read-only
mapping and complete payload digest verification precede one infallible publish
of every coefficient/node view. A failed check unmaps temporary storage and
leaves the safe parked tree unchanged. Repeated restore is idempotent. Aborting
before restore closes the FD and destroys the stable owner without ever mapping.

The Store must outlive its workers and callers must hold exclusive worker/tree
access for spill/restore. Scheme tree-array relocation is supported: identity
uses stable heap descriptor arrays, not the enclosing Tree struct address.

## Hard resource accounting

`parkingPlan(tree)` reports actual coefficient bytes, actual nonempty-node bytes,
header bytes, resident root-cell bytes and the combined page-rounded disk bytes.
`Store.MERKLE_HEADER_BYTES` is 128. `stats().merkle_parking_enabled` distinguishes
this capability; do not discount nodes when only coefficient parking is active.
`parked_merkle_bytes` counts live FD-backed node payload, including restored
owners, until final teardown.

The disk cap reserves the entire rounded combined file before any mutation.
When the original tree allocator is an identifiable SharedHostBudget, fully
parked restore also reserves the mapped file bytes externally under that SAME
hard cap. Refusal is OutOfMemory before publication; unmap releases the external
reservation. Normal tree teardown retains allocator lifetime through the backing
callback and final metadata release. Plain allocators retain their normal
caller/scheduler admission contract. Old coefficient-only behavior is unchanged.

Layer descriptors, stable root cell, column descriptions, digest/header and
other owner metadata remain resident. Scheduling must retain that allowance and
admit active mappings separately. Disk-backed/mapped bytes are not measured RSS;
clean OS file pages may remain cached after ordinary writes/unmapping.

|Full CPU trace log 22|Actual full node payload|Still-resident root cell|
|---|---:|---:|
|β1: Merkle log 23|536,870,880 bytes|32 bytes plus metadata|
|β2: Merkle log 24|1,073,741,792 bytes|32 bytes plus metadata|

For 25 such **unpruned** trees, node payload alone is approximately 12.5 GiB/25 GiB.
These are conservative shape calculations, not full-block RSS measurements.
Crucially, the actual native OwnedStreaming MAIN path calls compactForQueries
(tree_builders.zig), which drops four bottom layers at log≥20. If that qualified
path is used, trace log 22 β1 retains 33,554,400 bytes (about 32 MiB), and β2 retains
67,108,832 bytes (about 64 MiB). Thus a full-tree admission model may overestimate
represented MAIN nodes by 16×; do not claim the unpruned model as measured savings.
Parking persists/counts only actual nonempty layers, preserving the pruned shape.
The follow-up focused regression explicitly prunes a tiny tree and verifies
identical reconstructed Merkle openings before/after parking.

Integrity checking streams the full payload at write/restore. It does not rebuild
Merkle nodes, but adds hashing/I/O and may fault all file pages. No speedup is
claimed. Full-block memory and I/O qualification remains necessary; sparse node
verification or selective reads are separate future work.

## Qualification

The focused suite passes 17 tests in ReleaseSafe and ReleaseFast, including:

- Actual CPU Keccak and ADD/DOUBLE service shards produce identical SHA256 over
  full physical OM proof bytes plus canonical claims in resident/full-parking
  modes; each is freshly verified independently.
- Shape/root stability, exact restored nodes and coefficients, idempotence,
  no mapped payload while parked, and guarded reads.
- Header, coefficient, node and file-length tampering refuses before publication.
- Exhaustive allocation-failure cleanup, combined disk-cap refusal, parked CPU
  abort and later-worker OOM, plus mapped SharedHostBudget cap refusal/retry.

The original coefficient-only worker fixtures also execute transitively. The
qualification script and receipts are under
`vectors/reports/rv64-word16-execution-20261101/main-merkle-parking-v1/`.
Coordinator disk/resident admission and the first full-block run require an
explicit subsequent capability-aware integration. Fixed-key parking is separate.
