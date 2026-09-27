# Owning interaction-column transfer into parent PCS

Parent interaction generation previously produced arena-backed slabs, then sent
borrowed slices to PCS. That retained the complete source while PCS prepared its
own copy. The framework now exposes an independently owned output-column variant
of the same fail-atomic interaction generator. It reuses caller-owned inversion
scratch and the existing equations, padding and alias validation.

The parent producer reserves its exact interaction descriptor count, generates
AIR and lookup-table interaction columns through the worker allocator, and moves
the descriptor/value ownership directly into `scheme.commitOwned`. Before transfer,
its cleanup owns every generated value; afterwards PCS owns all values on success
and failure. No shared source slab has to be detached. Large CPU commitments use
the existing owning PCS streaming dispatch, which prepares columns in bounded
batches and preserves canonical commitment order. Coefficient-retention policy
and proof parameters are unchanged.

Main witness commitment remains a borrowing operation. This change addresses
interaction staging, not all PCS copies or the prepared witness metadata.

## Qualification

`python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-memory-update -Driscv-test-filter='compact parent metadata' -Doptimize=ReleaseSafe --summary all`

Passed in 5 seconds / 546 MiB. Every interaction column and claim matches the
full-row oracle. Exhaustive allocation-failure injection covers the independent
output allocations and their cleanup, while existing shape/alias checks remain.

`python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-canonical-chain -Doptimize=ReleaseSafe --summary all`

The comparison fixture keeps both leaf and parent at q70/PoW26, four proof workers,
the same 24 GiB worker allocation cap, 4,214,454,616 prepared bytes and independent
verification after worker/witness destruction. The immediate compact-metadata
baseline worker peak was 21,518,565,568 bytes; the original full-metadata baseline
was 23,106,927,066 bytes. This experiment changes storage/commitment ingestion,
not cryptographic security or the admitted proof statement.

Production activation, canonical multi-segment/next-level qualification, Metal,
precompile migration, default replacement and the original performance objective
remain incomplete. No end-to-end latency speedup is presumed from memory savings.

## Recorded results

The canonical chain passed in 4 minutes with 23 GiB peak process RSS. Both leaf
and parent use 70 queries/26 PoW bits; independent verification passes after
worker and witness destruction. Routed worker peak is 19,514,934,660 bytes,
saving 2,003,630,908 bytes (9.31%) against the compact-metadata baseline and
3,591,992,406 bytes (15.54%) against the original baseline. Artifact size remains
860,503 bytes. These are memory improvements, not measured latency speedups.

The shared native regression completed successfully: 3/3 tests passed,
1 minute compilation / 6 GiB and 49 seconds execution / 1 GiB. Its routed
worker peak is 731,615,650 bytes, versus 930,536,163 before owning transfer.
Persistent plans, bounded pipeline overlap, codec round trips and independent
verification after worker destruction remain qualified.
