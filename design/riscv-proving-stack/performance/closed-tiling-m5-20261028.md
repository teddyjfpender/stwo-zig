# Complete bundle cost versus execution partitioning

The same 1,310,734-cycle execution took **75.250 s in four segments versus
39.826 s in one segment** (1.889×). Both complete bundles passed fresh global
and recursive native-batch verification. This is a CPU experiment, not a
completed recursively closed Ethereum proof or a block-time forecast.

## Workload and boundary

Source: `5ea22942f51327b13af1b4fb6cb37d78b21569c8` on the experimental block
branch. Apple M5 Max, 64 GiB, eight workers, ReleaseFast. The 20-instruction
guest performs two SHA-256 compressions, one Keccak permutation, then a loop
with arithmetic, a RAM store, a RAM load and a branch. It publishes one byte
and halts. The loop repeatedly accesses **one RAM word**; this does not model
Ethereum's distinct-address distribution or its precompile mix.

The measured driver includes collection, all base proof generation and file
publication, native batch recursive preparation/setup/proving, and fresh
verification of the complete bundle. Input preflight and source creation are
reported separately. A further detached verification after all driver owners
are destroyed is also outside the driver timer. No required global provider
proof is omitted. The batch proof alone is insufficient: global files remain
necessary and the receiver's exact recursive forest is explicitly pending.

Every arm checks identical ELF, input, output, memory roots, PC endpoints,
cycle span and global memory/byte counts. Each nonterminal cut contributes one
additional public unretired ROM fetch; the benchmark independently requires
`fetches = cycles + segments - 1`. A changed independently pinned final memory
root and removal of the batch proof file are both rejected.

## Canonical q70 / PoW26, 262,144 loop iterations

| Metric | One segment | Four segments |
|---|---:|---:|
| Complete driver | 39.826 s | 75.250 s |
| Collection | 3.948 s | 4.210 s |
| Base proving and publication | 21.208 s | 23.994 s |
| Recursive preparation | 5.175 s | 20.202 s |
| Recursive setup | 1.407 s | 4.733 s |
| Recursive proving | 5.711 s | 19.411 s |
| Fresh bundle verification | 2.321 s | 2.623 s |
| Additional detached verification | 2.105 s | 2.360 s |
| Charged shared allocator peak | 4.509 GB | 12.925 GB |
| Base proof files | 8 | 14 |
| Native committed cells | 95,945,796 | 95,946,046 |
| Companion auxiliary cells | 146,802,056 | 146,802,484 |
| Memory committed cells | 89,128,960 | 89,128,960 |
| Recursive component cells | 499,791,872 | 1,648,877,568 |

One sample per arm. PoW search is stochastic; these are observations, not
stable medians. Charged memory is not process RSS. Component cell counters
exclude PCS expansion, temporary storage and some provider/fixed-table work;
they are not a complete whole-job area sum. Family timings in the CSV overlap
because providers run concurrently and must not be added together.

The smaller 20,494-cycle diagnostic q8/PoW0 pair also passed: 7.637 s versus
12.545 s. In that pair the one-segment native area is slightly larger due to
padding, yet the complete driver still wins. Padding area alone therefore
cannot choose a good execution partition.

## Architectural consequence

Native and memory area are almost constant in the large pair, but recursive
area changes 3.30×. Partitioning to reduce individual base proof size can
increase complete proof cost substantially. Plan by the independently sized
component domains and recursive verification work, subject to memory bounds.

The remaining native 65,536-row shard cap also converts longer execution into
more columns and wider openings. The next experiment changes that aspect
ratio while preserving all equations and security settings; see
[native-domain tiling](native-domain-tiling-problem-match-20261028.md).

## Reproduction and evidence

Build once, then run each profile without another LLVM build:

```sh
python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v6_closed_tiling_test_root.zig \
  -OReleaseFast --test-filter 'closed mixed tiling' \
  --test-no-exec -femit-bin=/tmp/closed-tiling
/tmp/closed-tiling
STWO_CLOSED_TILE_CANONICAL=1 STWO_CLOSED_TILE_ITERATIONS=262144 /tmp/closed-tiling
```

Both runs ended with all 12 selected tests passing. The strict
`closed-tiling-results.py` parser checks complete arm coverage, execution
identity, negative checks, timing partitions and memory budget before emitting
[JSON](block-v6-closed-tiling-m5-20261028.json) and
[CSV](block-v6-closed-tiling-m5-20261028.csv). JSON retains source and raw log
SHA-256 digests. No external timing is used in this comparison.
