# Session 12: SN2 Memory Base Lowering

Date: 2026-07-25
Product state: disabled
Performance claim: none

## Objective

Close the three non-recorded Cairo memory base writers without admitting the
imported 700-line migration monolith or introducing host execution fallback:

- `memory_address_to_id`
- `memory_id_to_big`
- `memory_id_to_small`

The lowering must retain proof-owned execution-context allocation, explicit
stream order, exact resident extents, and Zig SIMD value parity.

## Architecture

The CUDA implementation is split by responsibility:

- `native/cairo/memory_execution.cu` converts compact 256-bit and 128-bit
  little-endian values into the canonical 28- and 8-column 9-bit execution
  tables.
- `native/cairo/memory_base.cu` constructs address and value base traces and
  feeds the eight `range_check_9_9` multiplicity columns.
- `runtime/stages/cairo_base/memory.zig` is the checked launch boundary. It
  validates every device extent, pointer alignment, input/output disjointness,
  component geometry, proof stage, and launch result before telemetry accepts
  the work.
- `base_writer_plan/memory.zig` derives the active address, big-value, and
  small-value entries from the authenticated composition bundle and adapted
  input. For SN2 it admits exactly three entries in proof order and hashes the
  component identity, row geometry, source slice, limb count, and output width.

The address CUDA ABI deliberately consumes the canonical address-ID slice
beginning at Cairo address one. Address zero is omitted exactly as the Rust and
Zig memory component do. Big-value instances consume component-local source
slices, so the ABI does not assume that all future PIEs fit one `2^24` table.

No kernel allocates, copies, synchronizes, compiles, or chooses a fallback.
Host pointer arrays contain already validated device pointers and are copied
into kernel argument storage by the CUDA launch ABI.

## Correctness Evidence

The exact 4090 device smoke exercises the complete memory graph:

1. split three full-width values into 28 limbs;
2. split five small values into eight limbs;
3. construct 32 address columns over all 16 chunks;
4. construct 29 big-value columns including multiplicity;
5. atomically feed all 14 limb pairs into the eight 18-bit range-check tables;
6. download and compare every produced word against independent scalar
   formulas; and
7. release every execution-context allocation and require zero current pool
   use.

The first NVCC compile caught an invalid `atomicAdd` address expression in the
new decomposed source. The device smoke was added before product admission and
the defect was corrected rather than relying on host-only compilation.

Recorded result on the RTX 4090:

```text
native CUDA Cairo memory passed: big/small split, address/value base,
range-check feed, exact resident outputs
```

Additional gates:

- both CUDA units compile with CUDA 12.8 for `sm_89`;
- 103 active CUDA ABI symbols pass product-closure validation;
- the focused resident memory contract passes;
- the exact SN2 plan reads the 162,102,548-byte adapted input and admits
  address, big, and small entries in order; and
- all 17 transitive focused Zig protocol tests pass.

## Boundary

This closes the source, runtime, geometry, and focused device differential for
the three memory base writers. It does not yet establish:

- integration of their buffers into a complete SN2 proof transaction;
- all-58 interaction accumulator parity;
- all-279 constraint-part cumulative parity;
- terminal proof byte parity; or
- any SN PIE CUDA proving time or MHz result.

Those claims remain blocked until their corresponding end-to-end gates pass.
