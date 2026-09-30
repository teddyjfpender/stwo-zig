# Circuit recursion performance baseline (Zig vs Rust) — 2026-09-30

The first measurement of the integrated Zig recursion (leaf wrap, fold, root,
verify) against StarkWare's release binaries (`proving@5a7c5ed`,
`stwo-zig-ops/proving/target/release`). This is the §9.1 measurement that
[`02-design.md`](02-design.md) asks for before optimising. It also records a
first optimisation pass on branch `recursion/perf-baseline`. That pass cut a
2^23-row fold reduction from **46 s to 15 s**, and every proof byte is
unchanged.

## 0. Summary

| Workload (committed test registry) | Zig before (integration `69bbb83`) | Zig after (`recursion/perf-baseline`) | Rust `5a7c5ed` |
|---|---:|---:|---:|
| One fold reduction, 2^23 rows (`fold_reduce_*`) | 46.3 s (45.4–49.0) | **15.2 s** (15.0–15.6) | 21.1 / 21.3 s (internal) |
| `fold-tree`, 4 leaves (`four_leaves`), wall | 136.3 s | **46.5 s** | 66.5 s (2.2 s canonical build + 20.5 / 22.4 / 20.9 s reductions) |
| `fold-tree`, 1 leaf (root pass only), wall | 47.6 s (46.6–50.9) | **16.4 s** (16.2–17.6) | n/a (Rust copies a single leaf's proof through; no reduction) |
| Leaf wrap R8 (`use_all_opcodes`, canonical_small), wrap only | 37.3–41.3 s | **14.5 s** | not measurable: killed at 20.5 GB after the base commit |
| Leaf wrap R8, whole command, wall | 38.8–42.8 s | **16.0 s** | — |
| Leaf wrap R8b (leaf simple bootloader, `recursive_tree_test`), wrap only | 38.4 / 50.8 s | **15.9 / 16.5 s** | not run |
| Peak footprint, leaf wrap R8b | 18.2 GB | **15.3 GB** | — |
| Peak footprint, fold (4 leaves) | 15.73 GB | **15.28 GB** | 26.20 GB (max RSS 20.95 GB) |
| Peak footprint, leaf wrap R8 | 17.34 GB | **15.06 GB** | > 20.5 GB |
| Circuit verify (R7 multiverifier proof), wall | 0.03–0.04 s | unchanged | 0.03 s |

The after-column root proofs are byte-identical to the goldens:
`four_leaves/{root.proof, root_outputs.json, root_packed.json}`, and the
leaf-prover `expected_output.json` for R8. The full `circuit-parity` ladder
passed on the final commit (§5).

Headline:

- **Before the pass, Zig was about 2.2x *slower* than Rust per fold
  reduction** (46 s vs 21 s). The design assumed the opposite.
- After the pass it is **1.4x faster** than Rust per reduction, and uses at
  0.58x Rust's peak footprint on `four_leaves` (15.3 vs 26.2 GB). End to
  end, `four_leaves` is 46.5 s vs 66.5 s (1.43x). The Rust root is
  byte-identical to the committed goldens (`cmp` of all three outputs).
- The §9.4 targets are "warm fold ≥ 2.5x faster than Rust" (≈ 8.4 s) and
  "leaf wrap ≥ 2x faster" (≈ half of Rust's wrap). They are **not reached
  yet**, but they look reachable on CPU (§4).
- **An order-of-magnitude fold (≈ 4.5 s per reduction, ≈ 2 s vs Rust's 21 s
  for a 10x-over-Rust claim) is not reachable on this CPU.** After the pass a
  reduction does about 93 CPU-seconds of work. A perfect 14-core schedule
  (10P + 4E) still takes ≈ 7–8 s. An order of magnitude needs:
  - less work: native composition kernels, a preprocessed-tree cache, and no
    compact-storage re-expansion;
  - the Metal prover (M12), for most of the remaining step.

  §4 gives the ladder.

## 1. Method and conditions

- **Host.** Apple M4 Max, 14 cores (10P + 4E), 36 GB. On AC power: `pmset -g
  batt` reported "AC Power, 100%, charged" before every quoted run.
- **Contention.** Other agents' jobs ran concurrently under the shared
  memguard budget. Treat every timing as indicative. The A/B pairs were
  interleaved (A, B, A, B) to share whatever load was present.
- **Builds.** `zig build stwo-circuit-recursion-cpu -Doptimize=ReleaseFast
  -j2`. "Before" is integration head `69bbb8344` plus the stage profiler
  commit (`75308a828`). The profiler is a no-op without `--profile`, and the
  before-runs used `--profile` just as the after-runs did. "After" is
  `8f39f9d02`.
- **Memory.** Every run went through `memguard run --gb 15`. Timings come
  from `/usr/bin/time -l` (wall, user, max RSS, peak footprint).
- **Profiles.**
  - Phases come from the new `--profile` on `fold-tree` and `leaf-wrap`
    (`prover.stage_profile`; commit `75308a828`).
  - CPU attribution comes from `/usr/bin/sample` at 1 ms over a 1-leaf fold.
  - Rust phases come from its `tracing` spans (`RUST_LOG=info`), plus the gaps
    between span timestamps.
- **Rust runs.** Only the committed test-registry workloads were run. The
  first attempt used memguard 15 GB (hard kill at 18.75 GB):
  - `stwo_run_and_prove_recursive_tree` on `four_leaves` completed the two
    internal reductions (21.1 s, 21.3 s). memguard killed it at 20.4 GB
    during the root reduction's `Compute FRI quotients`.
  - `leaf-prover` on `use_all_opcodes_and_builtins` (canonical_small) was
    killed at 20.5 GB after the wrap's base-trace commit.
  - A second run of `four_leaves` used the host's largest reservation,
    memguard 20 GB (kill at 25 GB), and completed: 66.5 s wall, 541.8
    user-s, max RSS 20.95 GB, peak footprint 26.20 GB. Its root proof,
    outputs and packed tree are byte-identical to the goldens. Its reductions
    took 20.5, 22.4 and 20.9 s, consistent with the first run's 21.1 and
    21.3 s. The per-phase Rust column in §2 comes from the first run.
- **Workloads.** All inputs are committed in `vectors/circuit/official`:
  - **fold**: `four_leaves/leaf.json` ×1 (root pass only) and ×4 (2
    internal + 1 root), under `registries/recursive_tree_test.json`. Every
    reduction is a 2^23-row multiverifier: canonical_small targets, eq 20,
    qm31_ops 23, m31_to_u32 21, triple_xor 20, blake_g_gate 23.
  - **leaf R8**: `use_all_opcodes_and_builtins` wrapped under
    `leaf_prover_canonical_small.json`, a 2^23-row leaf circuit.
  - **leaf R8b**: the leaf simple bootloader under `recursive_tree_test.json`.
  - **verify**: the R7 multiverifier `proof.bin`.

## 2. Per-phase breakdown of one 2^23-row reduction

The run is a 1-leaf `fold-tree` (the root pass). Zig columns come from
`--profile`. The Rust column is the first internal reduction (layer 1,
pair 0) of the 4-leaf run.

| Phase | Zig before | Zig after | Rust | Before → after | Gap after vs Rust |
|---|---:|---:|---:|---|---|
| Builder: multiverifier with values (`fold_build`) | 0.64 | 0.67 | 0.60 | — | ≈ |
| Preprocessed tree commit | **3.69** | 0.72 | 0.46 | pooled deferred commit | 1.6x slower; cacheable (§3.4) |
| Base witness (gathers + tables) | 2.94 | 0.72 | ≈ 7.1 ¹ | row-parallel | ≥ 5x faster |
| Base commit (LDE + Merkle) | 1.44 | 1.48 | 1.31 | — | ≈ |
| Interaction grind (20 bits) | 0.004 | 0.003 | (in ¹/²) | — | negligible |
| Interaction witness (LogUp) | **8.63** | 1.40 | ≈ 1.9 ² | parallel `logup_columns` | 1.3x faster |
| Interaction commit | **5.44** | 1.94 | 2.54 | wide LDE preparation | 1.3x faster |
| Composition evaluation | **17.39** | 3.23 | 2.96 | pool-exclusive components | 1.1x slower |
| Composition interpolate + commit | 0.31 | 0.33 | 0.76 | — | 2.3x faster |
| OODS sampled values | 0.28 | 0.28 | 0.47 | — | faster |
| FRI quotients + FRI commit | 2.38 | 2.44 | 2.24 | — | ≈ |
| FRI grind (26 bits, M31 channel / root: Blake2s) | 0.11 | 0.11 | 0.16 | — | ≈ |
| FRI + trace decommit | 2.03 | 2.18 | ≈ 0.55 ³ | — | **4x slower** |
| **Reduction total** | **45.4** | **15.6** | **21.1** | 2.9x | 1.35x faster |

Notes on the Rust column:

1. The 7.10 s gap between the preprocessed Merkle close and the base
   `Commitment` enter. It covers Rust's base `write_trace`, circuit-hash and
   claim mixing.
2. The 1.89 s gap between the base and interaction commitments.
3. The remainder of `prove_ex` (7.14 s) after its instrumented children.

Grind: both grinds are negligible on this registry (≤ 0.16 s). §9.1 feared
26-bit grinds on the critical path; the test registry's FRI `pow_bits` does
not show that. Re-measure on the production registry (M7) before building
grind kernels (§9.2.7).

Builder: `fold_build` is 0.67 s of 15.6 s (4.3%). `fold_canonical_build`
(topology plus preprocessing) costs 1.2 s once per process; Rust pays 2.31 s.
**The builder is below the 10% line, so the M13 tape is not justified**
(§9.2.8).

### 2.1 Leaf wrap (R8, canonical_small, after)

The leaf's circuit proof has the same profile as a fold reduction:

| Phase | s |
|---|---:|
| build | 0.53 |
| preprocess | 0.26 |
| preprocessed commit | 0.65 |
| base witness | 0.41 |
| base commit | 1.46 |
| interaction witness | 1.35 |
| interaction commit | 1.83 |
| composition | 3.02 |
| FRI quotients | 2.22 |
| decommit | 2.01 |
| **wrap** | **14.45** |

The Cairo proof takes 1.49 s. Before the pass, the wrap took 37.3–41.3 s.
Rust reached the end of its base commit in 7.4 s (Zig: 3.3 s) before
memguard killed it.

R8b (leaf simple bootloader under the recursive-tree registry), interleaved
A/B/A/B: wrap 50.8 / 38.4 s before, 16.5 / 15.9 s after; whole command
52.5 / 39.7 s before, 17.8 / 17.1 s after. Peak footprint 18.2 GB before,
15.3 GB after. All four output JSONs are byte-identical (md5 `c1ec466e…`).
The spread in the before runs is contention from concurrent agents.

## 3. Hotspots, ranked (after the pass)

Ranked by wall time per 2^23-row reduction. CPU attribution comes from
`sample`: 93 busy CPU-seconds over 16.4 s wall, which is ≈ 5.7 of 14 cores
on average.

1. **Composition evaluation: 3.2 s wall, ≈ 17 CPU-s.**
   - The circuit components run the SIMD AIR *interpreter*
     (`EvaluationContext.evaluateRange`, `cpu_ir_air_part`). They have no
     native executor.
   - The trace lease (`trace_lease.Lease.initWithExecutor`) spends a further
     ≈ 0.7 s serially on the main thread. Compact storage dropped the LDE, so
     it re-expands the columns from coefficients to the composition domain.
   - Remedy (§9.2.3): generate native kernels for the five circuit AIR
     programs with the existing composition AOT generators
     (`native.Executor`, which Cairo already uses). Run the lease expansion on
     the pool.
   - Expected: ≤ 1 s.
2. **FRI + trace decommit: 2.2 s vs Rust ≈ 0.55 s.**
   - `pcs.coefficient_opening.Expansion.run` spends ≈ 1.3 s re-running full
     forward FFTs to recover the LDE rows at query positions, because compact
     storage kept only coefficients.
   - Remedy options:
     - evaluate only the queried rows (barycentric / per-point,
       `coefficient_storage` already has the pieces);
     - or keep the LDE for the trees whose memory fits.
   - Expected: ≤ 0.4 s.
3. **FRI quotients + commit: 2.4 s.**
   - `lazy_provider_init` → `buildCombinedContributionPlan` re-expands the
     columns again (`evaluateBuffersWithTwiddles`, ≈ 0.5 s main-thread FFT
     plus the plan itself, ≈ 0.8 s).
   - Share one expansion between the composition lease, the quotients and
     the decommit, or tile them (§9.3 policy b).
   - Expected: ≈ 1 s.
4. **Interaction commit 1.9 s + base commit 1.5 s + composition commit
   0.3 s.**
   - Now fully parallel.
   - What remains is LDE (`fft_radix8.forward`, ≈ 14 CPU-s over the whole
     proof) plus Blake2s leaf hashing (`compressParallel4`,
     `updateM31Columns4`, ≈ 19 CPU-s).
   - This is honest work. The CPU lever is streaming witness → LDE → hash
     per tile (§9.2.4); the real lever is Metal.
5. **Interaction witness 1.4 s.**
   - It is parallel now. Next steps:
     - `pairFractions` and `blake_g_gate` fill dominate;
     - the last column's `inclusivePrefixSum` is still serial (≈ 0.1 s ×
       4 coordinates).
   - Remedy: direct-index xor lookups and a vectorised blake_g fill
     (§9.2.2).
6. **Preprocessed commit 0.7 s.** It is identical for every reduction of a
   registry. Cache the committed tree per key (§9.2.1). The Cairo lane
   already has `tree_digest_cache` and `prepared_columns_cache` keyed by
   binding. Expected: 0 s warm.
7. **Base witness 0.7 s and builder 0.7 s.** Minor. Builder u32 SoA gates
   (§9.2.5) only matter after 1–6.
8. **Grinds.** Negligible on this registry.

## 4. Which §9 targets look reachable

The §9.4 targets and their status:

| Target | Rust reference | Status after this pass | Reachable? |
|---|---|---|---|
| Warm fold ≥ 2.5x faster than Rust (CPU) | 21.1 s per reduction → ≤ 8.4 s; `four_leaves` 66.5 s | 15.2 s per reduction (1.4x); `four_leaves` 46.5 s (1.43x) | **Yes, likely.** Items 1–3 and 6 of §3 are ≈ 6 s of exact CPU work removal, giving ≈ 9 s. Streaming commits (§9.2.4) close the rest. |
| Leaf wrap ≥ 2x faster (CPU) | not measurable to completion (≥ 7.4 s by base commit) | 14.5 s wrap | Probably. Same levers as the fold (the leaf is the same 2^23 circuit prover). A fair Rust number needs a host with more than 18.75 GB of headroom. |
| Peak RSS ≤ 0.5x Rust (resident) | 20.95 GB RSS / 26.20 GB footprint (`four_leaves`) | 15.3 GB (0.73x RSS, 0.58x footprint) | Needs §9.3's static budget. The ≈ 15 GB peak is the compact coefficient store plus quotient buffers. Not yet profiled per phase. |
| Metal/CUDA 5–10x over Rust CPU | 21.1 s | — | Plausible only with Metal (M12). The CPU floor after §3's work removal is ≈ 5–7 s per reduction. |
| **User ask: order of magnitude on fold** | 46 s before (Zig) / 21 s (Rust) | 15.2 s (3x vs the Zig before) | **CPU alone: no.** Reaching ≈ 4.6 s from 46 s needs §3 items 1–3 and 6 (→ ≈ 9 s) plus Metal for LDE, Merkle and composition. |

The iterative loop to drive this down is below. Each step is a separate
commit gated by the fold-1 byte compare, then the ladder.

1. Native circuit composition kernels (composition AOT) and a pooled lease
   expansion. Target: reduction ≈ 12.5 s.
2. Query-point decommit instead of full re-expansion. Target ≈ 10.8 s.
3. One shared expansion for the lease, the quotients and the decommit, or
   LDE residency for small trees. Target ≈ 9.5 s.
4. Per-key preprocessed-tree cache. Target ≈ 8.8 s. This reaches §9.4's
   2.5x.
5. Metal prover for LDE, Merkle, composition and quotients (M12). Target
   ≤ 4 s per reduction, an order of magnitude from 46 s.

Re-measure after each step with this document's method: fold-1 A/B
interleaved ×3, then `four_leaves`, R8 and R8b.

## 5. What changed on `recursion/perf-baseline`

Each change is exact and order-free; no transcript input changes. Every
change was checked by `cmp` of the 1-leaf root proof after each step, and
at the end by `four_leaves` byte-equality and R8 `expected_output.json`
byte-equality.

| Commit | Change | Effect (per 2^23 reduction) |
|---|---|---|
| `75308a828` | Stage profile. `StageScope` around the circuit prover's commits, witnesses, grind and bind; around the leaf wrap's build, preprocess and serialize; around each fold reduction. New `fold-tree --profile`. | Measurement only |
| `f718c4f2d` | Circuit components run `pool_exclusive_domain`. Each of the five 2^20–2^23 domains gets the whole pool, row-split, instead of one core per non-dominant component. | composition 17.4 → 3.1 s |
| `f718c4f2d` | `pcs/deferred_commit` borrows the coordinator's scoped pool (the Cairo `preprocessed_commit.Worker` pattern). Before, the deferred first-tree build saw a live scoped pool elsewhere and ran every FFT and Merkle layer on one thread. The circuit prover joins it immediately, so the old path was pure loss. | preprocessed commit 3.7 → 0.7 s |
| `f718c4f2d` | `air/logup_columns.build` fills, batch-inverts and accumulates 4096-row chunks on the pool. Each worker has its own scratch; partial claimed sums are exact. It no longer materialises the whole fraction table (−2 GB peak on R8). | interaction witness 8.6 → 1.4 s |
| `2709d41df` | Circuit prover backend `configured(.{ .wide_preparation = true })`: the Cairo product's fused per-column LDE jobs. The 2^23 streaming batches of 4–5 columns left 10 cores idle. | interaction commit 5.4 → 1.9 s |
| `8f39f9d02` | Base witness gathers are row-parallel. Small tables are per-worker and merged; xor_12 (2^24 slots) uses shared atomics. One shared atomic table for everything contended badly: +25 CPU-s, 3.0 → 2.4 s only. | base witness 3.0 → 0.7 s |

The shared-code changes (`deferred_commit`, `logup_columns`) also reach the
Cairo lane and the blake example. The Cairo lane's R10b/R10c rungs are part
of the ladder below.

Parity: `zig build circuit-parity -j2` (the local lane, then the large lane)
on `8f39f9d02`, under `memguard run --gb 16`: **exit 0, green**. 1062 s
wall, 15.3 GB max RSS (memguard sampled 14.3 GB). Every local rung passed
(R0 wire formats, R1, R4, R6 fold/leaf, R4 values, R7, registry generation,
R10b/R10c Cairo leaf, R11 accept plus every tamper rejected). Large lane:
R8 (the rung's own timing: wrap 78.3 s), R8b (85.4 s) and R9 passed. The
rung timings ran under the ladder's test harness with other agents' jobs
active; they are not comparable with the CLI numbers above. `circuit-parity-r7-multiverifier` printed its
documented skip: `STWO_CIRCUIT_MULTIVERIFIER_INPUTS` is not set on this host,
so that rung was not exercised.

## 6. Open items

- The Rust fold is now measured end to end (§1). A complete Rust leaf-wrap
  run (R8) needs the 20 GB reservation too. Such a job only starts when the
  shared memguard ledger is empty, and it starved behind other agents'
  15 GB ladders during this pass. Rerun
  `leaf-prover --program …/use_all_opcodes_and_builtins_compiled.json
  --circuit_registry_json …/leaf_prover_canonical_small.json` under
  `memguard run --gb 20` when the host is quiet.
- Production-registry shapes (M7) may change the split. For example, the
  26-bit grind at production `pow_bits` and 70 queries would change the
  decommit cost.
- Per-phase peak memory: this report has only process peak footprints.
