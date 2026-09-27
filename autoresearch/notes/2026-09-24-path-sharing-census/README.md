# Authenticated Merkle-path sharing census — 2026-09-24

## Question and scope

The previous shared join optimization reduced complete canonical tree time by 9.6%
but left recursive AIR work unchanged. This read-only diagnostic counts repeated
upper Merkle node positions within each authenticated commitment tree. Heights stay
separate; different trace/FRI trees never share census state. FRI positions are shifted
by the fold step before counting the upper path. Repeated leaf groups are counted
separately. Empty paths, duplicate groups, asymmetric positions and invalid geometry
have focused tests.

`STWO_RISCV_PATH_SHARING_CENSUS=1` enables reporting in the existing native path
builder after its complete opening inventory is constructed. Default proving is
unchanged. Node G-row cost comes from the canonical node-frame hash plan, not a
hard-coded estimate. `gross_candidate_g_rows` counts repeated upper-node hash rows
before any new routing/equality costs. It excludes duplicate leaf/subtree savings and
is not an implemented saving, security proof, padded-domain reduction or speedup.

The focused PCS qualification passes **13/13 checks**, with its explicit name guard
updated to include the new census test. The diagnostic has no authority to remove
hash rows or change the lookup multiplicities.

## Canonical measured census

Seven canonical tree checks pass with reporting enabled. The fixture independently
verifies all three aggregate artifacts at 70 queries / 26 PoW bits, with unchanged
artifact sizes 918,746 / 911,657 / 904,156 bytes and routed peak 30,309,734,580 bytes.
The six records describe the four leaf captures prepared into pair witnesses, then
the two aggregate captures prepared into the root witness.

| Child capture | Path G rows | Upper hashes | Unique upper hashes | Gross candidate G rows | Fraction of path G |
|---|---:|---:|---:|---:|---:|
| Leaf 1 | 2,367,680 | 17,290 | 9,291 | 895,888 | 37.8% |
| Leaf 2 | 2,367,680 | 17,290 | 9,418 | 881,664 | 37.2% |
| Leaf 3 | 2,359,840 | 17,290 | 9,311 | 893,648 | 37.9% |
| Leaf 4 | 2,399,040 | 17,290 | 9,471 | 875,728 | 36.5% |
| Aggregate 1 | 3,594,640 | 26,040 | 16,398 | 1,079,904 | 30.0% |
| Aggregate 2 | 3,594,640 | 26,040 | 16,166 | 1,105,888 | 30.8% |

The canonical node frame costs **112 G rows**. Repetition is substantial, including
late FRI layers where 70 openings visit only 2, 4, or 8 groups. This supports designing
shared path verification, but the table excludes equality/routing overhead and cannot
predict total proof time. In particular, fewer logical rows may leave padded domains
unchanged, and recursive verification of a new component adds next-level work.

Sharing only the final root hash has a smaller gross ceiling: 170,016
G rows for the first leaf verifier and 208,656 for the first aggregate
verifier. It is a bounded first design option rather than a route to the entire table's
savings by itself. All reported candidate savings remain **unimplemented**.

## Design constraints and path forward

The current builder emits a complete independently routed opening per query. Its
plan cache reuses immutable graph construction, not all repeated hash witnesses.
Every path-select consumes an authenticated query bit, current digest and sibling,
and produces the ordered inputs to its node-frame hash. Root equality consumes the
computed root and the canonical root producer. Sharing must preserve those checks
and exact producer/consumer multiplicities for every query.

The parent key identity includes the preprocessed commitment and log sizes. Selecting
a new fixed routing graph from private query positions can therefore change the
admitted key and defeat immutable-plan reuse. Candidate topology savings do not
justify that migration silently. Two possible engineering paths are:

- A fixed schedule that shares guaranteed-common computations, starting with the
  final root compression in each tree, while proving equality of all selected input
  words and maintaining canonical-root and query-bit consumers.
- A separately designed dynamic path DAG whose routing, node identities, input/output
  equality and multiplicities are constrained under a stable admitted key.

A first-query root input pair can supply the shared root computation, but all other
queries must constrain their ordered inputs to it. Omitting their equality checks
would disconnect those paths. A dense shared upper subtree also cannot assume the
capture reveals every unqueried node's preimage. Count and qualify actual net cost,
including routing cohorts and next-level verifier work, before accepting either.

## Commands and evidence

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-recursive-fused-pcs-opening -Doptimize=ReleaseSafe --summary all
STWO_RISCV_PATH_SHARING_CENSUS=1 STWO_RISCV_PARENT_BENCH_ALLOCATOR=smp STWO_RISCV_PARENT_BENCH_WORKERS=8 python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal test-blake3-native-tree-aot -Dmetal-core-aot-bundle="$PWD/zig-out/share/stwo-zig/metal/core" -Doptimize=ReleaseFast --summary all
```

This is a dirty-worktree source checkpoint, not a complete clean-checkout snapshot.
No new performance comparison is run because this diagnostic is not an optimization.
Full CSP recovery, materially faster recursion, persistent bounded scheduling, further
fusion/direct emission and the separately reviewed parameter experiment remain open.
