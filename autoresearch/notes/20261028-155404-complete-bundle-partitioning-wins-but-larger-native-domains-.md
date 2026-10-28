---
title: Complete bundle partitioning wins but larger native domains regress and are reverted
author: Teddy Pender
created_utc: 2026-10-28T15:54:04Z
---

# Complete proof graph matters more than native component count

Task: minimize complete verified bundle latency under a 40 GiB shared budget,
without changing execution, security, event custody or global closure.
Canonical problem: constrained matrix/domain tiling with proof-graph cost.
The simple area surrogate omits domain-dependent verifier work and recursively
padded AIR cohorts; selecting on component count alone is insufficient.

On the M5 Max, eight workers, ReleaseFast, q70/PoW26, the same 1,310,734-cycle
mixed guest took 75.250 s across four segments versus 39.826 s in one segment.
Charged peak fell from 12.925 to 4.509 GB; recursive component area fell from
1.649B to 499.792M cells, with essentially unchanged native and memory area.
The complete receiver checks all original global providers and the direct
native recursive batch. This is a complete bundle, not a standalone root.
The guest repeats arithmetic/store/load/branch on one RAM word with two SHA
compressions and one Keccak permutation; it is not an Ethereum distribution.

Two next-step hypotheses were falsified. Raising native shards from log16 to
log20 reduced components but inflated padding: one-segment time 68.890 s,
charged peak 15.044 GB. A descending dyadic layout preserved old padded area
but still took 45.315 s and 7.391 GB; recursive area increased to 518.486M.
Four-segment versions also regressed. Both larger-domain implementations are
retained only in experimental commit history and reverted at branch HEAD.
Do not claim them as optimizations or repeat them without a different model.

All three canonical complete pairs passed all 12 selected tests. The small
original diagnostic pair passed too. Four dyadic unit tests covered legacy
compatibility, malformed layouts, exact padded area and cross-shard routing.
Independent final-root mutation and missing batch proof are rejected; cold
detached verification runs after driver owners are destroyed. One sample per
arm, random PoW: timing ratios are observations, not stable medians. Charged
allocator memory is not RSS. No full Ethereum block-time forecast follows.

The transfer was motivated by larger independent AIR domains in
[ZisK's pinned topology](https://github.com/0xPolygonHermez/zisk/blob/1e22630bb7e143c30705a1603ed87cfd3da8c6ec/pil/zisk.pil)
and [Stwo's multi-component PCS](https://github.com/starkware-libs/stwo/blob/dev/crates/stwo/src/prover/mod.rs).
They are mechanism references, not transferable performance claims; no code
was copied. The empirical result rejects a simplistic topology transfer.

Next structural work: one native/companion relation basis and a binding event
interface that eliminates repeated wide trace commitments while preserving
commit-before-challenge global buses. Neither is demonstrated by changing a
row cap. Independently plan native executions and provider domains, with the
full recursive verifier area and memory budget in the objective.

See [complete partition measurements](../../design/riscv-proving-stack/performance/closed-tiling-m5-20261028.md)
and [rejected-domain experiments](../../design/riscv-proving-stack/performance/native-domain-tiling-m5-20261028.md)
for all phase timings, JSON/CSV evidence, source commits and log digests.
