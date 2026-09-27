# Bounded consuming parent-column join — 2026-09-24

The preceding goal turn made progress: compact trusted transcript storage was
implemented and qualified on native and canonical recursive paths, with measured
logical storage reduction but no demonstrated end-to-end speedup. This checkpoint
addresses simultaneous source/destination ownership in the much larger column join.

The borrowed join previously kept every child column alive while allocating the
complete aggregate matrix. Owned aggregate preparation already consumes both child
witnesses. Its join now allocates/copies at most 16 destination columns at a time,
then frees and clears the corresponding source buffers with their source allocator.
Fixed schedules are concatenated and their source buffers released per cohort.
Destination-order tiling, padding, row permutation, namespace admission and input
counts remain the same. No proof parameters or semantic identities change.

Namespace/geometry admission occurs before mutation. After admission the draining
API is intentionally destructive: the caller must deinit both children on success
or failure and cannot reuse their rows. Empty slices mark released allocations;
partial destination ownership is cleaned independently on failure. Aggregate
preparation already owns the two deferred child destructors. Aliased owners are
rejected before mutation. The borrowed join remains available for callers that need
their input owners intact and as a differential reference.

The tradeoff is extra permutation-index computation per 16-column batch instead of
once across all columns. End-to-end measurement must determine whether that cost is
worth lower preparation memory. No speed claim follows from the smaller fixture.

## Qualification

Four focused ReleaseSafe checks passed. They compare every output column and fixed
field against the borrowed join across empty/unequal/power-boundary counts, including
nonzero source padding, and inject every destination allocation failure with
independently allocated input owners. In the 4,096+4,097-row G fixture, routed peak
falls **11,409,648 → 7,073,360 bytes (38.0%)**. An intermediate hard budget is now
checked to reject the borrowed join while admitting the draining join; the final focused gate passed **4/4** with that hard-budget check. Canonical
Metal tree qualification passed **7/7**, with eight admitted hash kernels and all
three aggregate artifacts independently verified at 70 queries/26 PoW bits.

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-parent-join -Doptimize=ReleaseSafe --summary all
```

Control/candidate snapshots, relative patch, frozen executables, raw logs and checksums
will retain the experiment. Worktree is dirty; HEAD alone does not reproduce it.
No all-prover/CSP speed claim, 10× claim or parameter weakening is part of this work.

## Matched canonical tree result

The frozen control includes compact trusted transcript storage and the worker lease
fix; the candidate additionally drains column ownership during the join. Both use
the same accepted ABI24 bundle, eight leaf proof workers, two root-preparation
workers, SMP allocator and four actual leaves with two aggregate levels/six cycles.
The driver checks the admitted hash kernels, real G device dispatch, canonical
parameters, worker counts, budgets, phase receipts and independent verification.
All **twelve timed aggregate artifacts** independently verify. Their sizes remain
**845,993 / 849,496 / 889,364 bytes**; sizes alone are not a byte-identity assertion.

| Arm | Complete fixture (s) |
| --- | ---: |
| control | 37.850 |
| candidate | 38.636 |
| candidate | 37.936 |
| control | 38.321 |

Complete median **38.08566 → 38.28606 s (+0.53%)**. Root preparation median
**3.87577 → 3.84129 s (−0.89%)**. Routed peak is exactly **26,459,992,736 bytes**
in both arms; peak physical footprint **39,162,273,720 → 39,162,388,384 bytes**
is effectively unchanged. Two samples per arm establish neither a throughput gain
nor a meaningful timing regression. No observations were discarded.

The bounded consuming join is retained because it demonstrably admits a workload
under a routed-memory limit that rejects the borrowed implementation, with exact
column parity and complete failure cleanup. This does **not** imply a lower whole-
prover peak or faster canonical tree. The root proof/check phase remains about
12 seconds; column joining is not the overall peak-memory or latency bottleneck in
this fixture. Further work should target actual root proof cost and PCS/DEEP row
reduction, rather than assume smaller preparation buffers imply a speedup.

```sh
STWO_RISCV_PARENT_PREPARATION_PROFILE=1 STWO_RISCV_PARENT_BENCH_ALLOCATOR=smp STWO_RISCV_PARENT_BENCH_WORKERS=8 python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal test-blake3-native-tree-aot -Dmetal-core-aot-bundle="$PWD/autoresearch/notes/2026-09-24-blake3-rotate7-limbs/core" -Doptimize=ReleaseFast --summary all
python3 autoresearch/notes/2026-09-24-draining-parent-join/measure.py
```

This reduces simultaneous ownership during final-layout copying; it does not yet
emit both child witnesses directly into one shared aggregate destination or remove
all copies. Persistent multi-job scheduling and the separately reviewed parameter
experiment remain part of the active broader objective.
