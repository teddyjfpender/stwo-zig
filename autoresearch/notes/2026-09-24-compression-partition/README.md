# Canonical compression partition plan

The previous goal turn made progress: persistent pipeline qualification and a pinned,
matched ZisK scalar compression comparison. User direction remains efficient, fully
constrained hash precompiles as the default after qualification, preserving protocol
bindings. This checkpoint implements the canonical plan needed to fuse G calls without
replacing the compression schedule with an independently handwritten witness recipe.

## Implemented

`blake3_compression_partition.zig` partitions the canonical 56-G DAG into public-shaped
contiguous groups. Each group imports each external word once and keeps internal SSA
words local. It exports only words consumed by other groups or the retained final XORs.
Export multiplicities count distinct importing groups plus final XOR consumers, not
old per-G uses. The builder rejects invalid widths and checks fixed-size bounds.
Validation rebuilds the canonical plan and rejects changed schedules or weights.

Three ReleaseSafe checks pass. Across **all 56 widths and eight random cases per width**,
the test evaluates each group using only its declared inputs, checks every internal
read was previously defined, publishes only declared outputs, closes all intermediate
wire balances and compares all sixteen final words to native compression. CV, block,
counter, length and flags vary. Schedule/input/multiplicity mutations are rejected.
This is **plan and native-execution qualification**, not an AIR proof or precompile
promotion. The initial direct test root was below imported source files; the permanent
root at the frontend level fixes module-boundary access. Both logs are retained.

## Geometry and decision

The independently scripted census reproduces the current baseline: 56 × 112 main
cells and 56 × 62 relation events. Estimates use the existing packed G arithmetic,
share external input ranges within each group and remove only internal wire lookups.
Final XOR rows and external boundary machinery are excluded consistently in both arms.

| G calls/group | Groups/compression | Max main columns | Total main cells | Total events |
|---|---:|---:|---:|---:|
| 1 | 56 | 112 | 6272 | 3472 |
| 2 | 28 | 224 | 6272 | 3472 |
| 4 | 14 | 448 | 6272 | 3472 |
| 8 | 7 | 832 | 5824 | 3024 |
| 14 | 4 | 1360 | 5440 | 2688 |
| 28 | 2 | 2592 | 5184 | 2464 |
| 56 | 1 | 5056 | 5056 | 2352 |

Pairs and groups of four have **no internal dependency to eliminate**: simply widening
those groups buys no cell or event reduction. Eight calls span both half-rounds and
reduce main cells 7.1% and events 12.9%. Fusing all 56 removes more routing but grows
the component to 5,056 main columns, with a much wider query/next-level verifier cost.
Thus fewer rows alone is not an acceptance criterion. These are static estimates;
no timing, memory reduction or proof-cost win is claimed by this checkpoint.

Next implementation: use the checked partition in the typed compression author and
witness emitter, qualify real constraints/lookup closure and malformed caller bindings,
and measure full proof plus next-level geometry. Start with a round-sized candidate
and compare it against a larger group only with those costs visible. The current
92-byte framing, all canonical parameters and default production G/XOR path remain
unchanged until the precompile is qualified. The requested final default precompile
is not yet implemented; this is its shared scheduling foundation.

```sh
zig test -O ReleaseSafe --dep stwo_core -Mroot=src/frontends/riscv/blake3_compression_partition_test_root.zig -Mstwo_core=src/core/mod.zig
python3 autoresearch/notes/2026-09-24-compression-partition/census.py
```

The Python census is a diagnostic cross-check. The Zig plan derives from the repository's
canonical compression topology and is the implementation source of truth.
