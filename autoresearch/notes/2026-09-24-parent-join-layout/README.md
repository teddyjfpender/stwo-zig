# Destination-order parent column joining — 2026-09-24

## Hypothesis and implementation

The previous tree checkpoint explicitly admitted CPU leaf workers, cutting its
complete fixture to about 72 seconds. Profiling the frozen executable with
`STWO_RISCV_PARENT_PREPARATION_PROFILE=1` accounts for 7.071 seconds in the two root
child witness preparations out of 11.871 seconds for encompassing root preparation.
The remaining 4.800 seconds includes namespace planning, rebasing, joining and
cleanup; this observation alone does not isolate joining.

The shared parent join formerly zeroed all destination main columns and then copied
logical rows through source and destination committed-row permutations. This change
computes a destination-order source-index tile once per cohort, reuses it across
columns, and writes each destination field exactly once, including zero padding.
The 1,024-index scratch tile occupies 8 KiB on this 64-bit host. There is no heap
permutation table or full logical witness materialization. Left/right namespaces,
compact fixed metadata, padding domains, key derivation and proof parameters remain
unchanged. This applies to all joined cohorts and both backend paths.

## Validation

The focused `test-riscv-blake3-memory-update` ReleaseSafe target passes. Its new parity
case compares every column against logical-row concatenation over empty children,
asymmetric domains, odd boundaries, exact powers of two and multi-tile output.
Existing namespace rejection, malformed-column, source-preservation and memory-update
checks remain enabled. No performance conclusion is drawn from these small tests.

## Measured result — retained

The canonical tree qualification passes **7/7 checks**. All four measured fixtures
also pass all seven checks and independently verify all three aggregates (12 measured
artifacts), retaining 70 queries / 26 PoW bits at every level and proof sizes
918,746 / 911,657 / 904,156 bytes. Equal sizes do not establish byte-identical proofs.

M5 Max, ReleaseFast, SMP allocator, eight configured workers, frozen ABBA runs:

| Run | Arm | Complete fixture seconds | Peak physical GB |
|---|---|---:|---:|
| 1 | control | 71.193 | 45.153 |
| 2 | candidate | 65.749 | 44.892 |
| 3 | candidate | 65.180 | 45.153 |
| 4 | control | 73.609 | 45.153 |

Complete fixture median falls **72.401 to 65.465 seconds**, **9.6% less time**
(1.106×). Both candidates are faster than both controls. The shared implementation
is retained. The maximum observed physical peak is effectively identical at 45.153 GB;
routed peak remains 30,309,734,580 bytes under 48 GiB. No memory reduction is claimed.

| Phase median | Control seconds | Candidate seconds |
|---|---:|---:|
| Left leaf pair + preparation | 9.397 | 7.566 |
| Left aggregate + checks | 12.812 | 12.975 |
| Right leaf pair + preparation | 9.745 | 7.671 |
| Right aggregate + checks | 13.288 | 13.230 |
| Root preparation | 12.311 | 8.921 |
| Root aggregate + checks | 14.477 | 14.412 |

Root preparation falls **12.311 to 8.921 seconds**
(27.5% less time). Leaf-pair phases also include
aggregation joins and improve. Aggregate proof/check times show no corresponding
improvement. The phase sums exclude some setup, negative checks and cleanup and
are not the complete fixture duration. Canonical parameters and recursive constraint
counts are unchanged; this is a host witness-layout improvement.

## Reproduction and limits

```sh
python3 scripts/zig_serial_build.py test-riscv-blake3-memory-update -Doptimize=ReleaseSafe --summary all
STWO_RISCV_PARENT_BENCH_ALLOCATOR=smp STWO_RISCV_PARENT_BENCH_WORKERS=8 python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal test-blake3-native-tree-aot -Dmetal-core-aot-bundle="$PWD/zig-out/share/stwo-zig/metal/core" -Doptimize=ReleaseFast --summary all
```

Frozen measurement uses the preceding leaf-pool executable as control and its same
archived AOT bundle. `measure.py` runs control/candidate/candidate/control sequentially,
asserting canonical q70/PoW26, independent aggregate verification, root segment/cycle
coverage, exact artifact sizes and routed budget bounds. It records wall time,
physical peak, RSS, binary SHA-256 and phase receipts. These are complete tiny-tree
fixtures, not ordinary CSP results or bare proving latency. Two samples per arm do
not establish a broad workload distribution. No samples are discarded.

This dirty-worktree checkpoint does not contain a full clean-checkout snapshot of
every dependency. The control executable and AOT bundle retain their previous
checkpoint manifests. Full CSP recovery, materially faster recursion, effective
persistent bounded scheduling, further fusion and the separately reviewed parameter
experiment remain open.

## Remaining engineering direction

The tree's child preparations are still sequential. Any parallel preparation must
admit both temporary witnesses and stacks under a shared budget, preserve input
capture lifetimes, and join all work before returning failures. Persistent workers
also need qualification across heterogeneous tree keys, not just identical jobs.

The STARK path builder currently emits each query's full opening separately; its
plan cache reuses graph construction, not all hash witnesses shared by Merkle paths.
A census of repeated authenticated nodes is a candidate for reducing recursive
work itself. Sharing must constrain every query direction, input and output to the
shared node and preserve multiplicities; host-side digest equality alone would not
justify deleting hash constraints. This is an investigation lead, not an implemented
optimization or measured savings claim.
