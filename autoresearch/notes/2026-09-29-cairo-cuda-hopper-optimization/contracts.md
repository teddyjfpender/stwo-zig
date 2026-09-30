# Retained optimization contracts

## AIR root closures

Dependency analysis follows imperative register definitions in reverse order.
A write kills the destination's current dependency before its operands are
visited; self aliases therefore refer to the earlier definition. Extension
`secure_col` reads seed base-register dependencies. Filtered instructions keep
original order, constraint roots keep original ordinal and coefficient, and
runtime constants keep their original full-program ordinal. Duplicate roots
remain separate constraints. Helpers have independent exact closures, so they
may repeat computation but never communicate through an uninitialized register.
No transcript ordering or field representation changes.

The independent SIMD evaluator compares all roots against the unsliced program
for 142 authenticated templates, seven root widths, overwritten registers,
nonconstant columns and full QM31 challenges. Native whole proofs additionally
match original proof SHA256 digests and pass the pinned Rust verifier.

## Tiled relations

Each block owns 256 rows. Its shared tree contains 512 canonical QM31 elements
(8,192 bytes). Large domains retain the previous groups-of-32 product inversion;
a zero in a group therefore has exactly the prior propagation behavior. Small
domains preserve independent inversions. Every fraction coordinate is written
before the separate per-row prefix kernel consumes it on the same stream.
No block reads another block's shared state. Logical denominator storage shrinks
to one unused ABI placeholder per instance; allocation admission and range
validation explicitly distinguish fused and legacy topology.

The GPU differential compares every coordinate to the old CUDA path and claims
to a scalar CPU reference at 16, 256, 512, 1,024, 2,048 and 4,096 rows. Full PIEs
exercise the assembled topology and multiple relation columns. The native
fused kernel uses 48 registers and no stack/spills.

## Request reuse

Only the process runtime, a bounded full-plan-keyed arena and its authenticated
immutable preprocessing snapshot survive requests. The cache key binds both
request plan and resident program identity. A miss invalidates the retained
preprocessing receipt; a hit validates identity, commitment, column/word extent
and expected artifact SHA. Preprocessing coefficient lifetimes span all arena
phases, preventing later allocations from overwriting the retained data.
Each request still ingresses fresh source data, generates its witness, proves,
decodes, verifies in Zig and publishes. Repeated requests must produce identical
proof digests. Startup belongs to the first request and teardown is reported
separately. There is no cached proof or cross-process preprocessing cache.
