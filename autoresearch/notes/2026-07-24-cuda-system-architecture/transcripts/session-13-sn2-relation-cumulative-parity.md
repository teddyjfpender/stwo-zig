# Session 13: SN2 Relation Cumulative Parity

## Scope

This session closes the bounded-memory device differential for the complete
canonical SN PIE 2 interaction plan. It does not claim that Cairo CUDA proving
is production-ready.

The admitted plan is derived from:

- `sn_pie_2_composition.bin` SHA-256
  `fdb84be46893a8bb6eb8eeac19bc8746d064a04c3700accca367911a921a47e9`;
- `cairo_relation_templates.bin` SHA-256
  `2a692328b5e761b7129c82052542ba03221d228089fe1583f2d8043e6b3d231f`;
- relation graph hash `73963831c53df4a2`; and
- relation topology identity
  `ebd25f86d8c0e291ee00c333f4f3a20f7d1e81f170de582cd9aff8e0f3d469c8`.

It contains 58 canonical component instances, 567 relation columns, 9,072
descriptor words, 126 alpha powers, and 1,356,284,992 interaction-coordinate
cells.

## Oracle And Memory Policy

`relation_sn2_parity_fixture.zig` compiles the authenticated
`relation_adapter.Plan`, preserving component order, instance identity, local
padded and real heights, source layout, tuple arity, multiplicity policy,
challenge expansion, and descriptor bytes.

The differential uses deterministic constant source columns. Lookup layouts
are evaluated algebraically at their active and inactive row classes by the
Zig field reference; address, memory, and bitwise layouts evaluate every
canonical row because their tuples depend on the row index. The resulting
claimed sum and four-coordinate cumulative prefix after every component are
checked into the generated fixture.

The native smoke reuses one execution context and one relation graph. It
executes each exact-height instance sequentially, checks its claimed sum,
checks the cumulative prefix, and checks the terminal circle scan value is
zero before releasing component-local buffers. This avoids materializing the
complete 10.86 GiB output-plus-denominator graph twice. The largest live
instance is `blake_g`, modeled at 5,335,154,688 bytes (4.97 GiB).

This fixture proves the complete relation engine topology and accumulator
semantics. Its deterministic source values are not the block's production
witness values, so production admission remains false until recorded witness,
interaction, constraint, commitment, and transcript stages are connected in
one proof request.

## Device Result

- GPU: NVIDIA GeForce RTX 4090
- UUID: `GPU-3dabce32-b71d-9cdf-6392-026267492cb6`
- SM: 89
- driver: `580.126.09`
- CUDA toolkit: 12.8
- frozen archive SHA-256:
  `bbf7426d3e988dbc35a1e777e9d1855c607936e1ab8a8b490da5c773d49a08c2`
- fixture SHA-256:
  `7046b7776747cd40d405bea348bde378e44595b234f308fac281e9c18c632f4a`
- smoke source SHA-256:
  `795c3a849a5039b53403d7e44707c7f4c6e788ea857daa2bbd37bcace1374847`
- executable SHA-256:
  `b87bdb73cb23c8140059e7f20d7d62232a8f1f89e62370544acf62287bf42f15`

Exact stdout:

```text
SN2 relation cumulative parity passed: components=58 coordinate_cells=1356284992 peak_bytes=5335154688 jit=0 fallbacks=0 graph=73963831c53df4a2
```

The process completed in 0.54 seconds wall time with 114,480 KiB peak host RSS.
All 58 component checkpoints matched. No mismatch occurred. The device had no
remaining compute process after the run.

## Admission

The interaction relation differential is complete for the authenticated SN2
topology:

- exact component and instance order: pass;
- exact local padded and real heights: pass;
- exact descriptor tuple and multiplicity policy: pass;
- exact challenge expansion: pass;
- per-component claimed sum: pass;
- four-coordinate cumulative prefix after every component: pass;
- terminal circle scan residue: zero for every component;
- runtime JIT: zero;
- CPU fallback: zero.

`production_ready` remains false. The next admission boundary is the composed
Cairo CUDA request, not relation kernel fusion or optimization.
