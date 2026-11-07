# RV64 M9 recursion architecture: cost per verified proof and tree depth

Status: M9/M10 prep, 2026-11-07. Branch `codex/rv64-m9-recursion-arch`, cut from `codex/rv64-m7-integrate` @ 95e3d7e15. It ran in parallel with the GPU-native landing and used no GPU: the census is CPU only, built under memguard. Everything is a new file or a default-off diagnostic, except for one build-list line and one catalog line (§7).

Labels: **[M]** measured, with a receipt; **[D]** arithmetic on measured numbers; **[E]** estimate.

Receipts, in `vectors/reports/rv64-m9-prep/m9-recursion-arch/`:
- `census.jsonl`: rows by phase per verified child, for 37 (child, variant) cases [M];
- `model.json`: the padded recursion tree for every lever and for all 15 basket blocks [D on M];
- `plan_model.json`: the M9 plan model with the new levers [E].

## 0. TL;DR

1. **Cost of one verified recursion child** (log-23 child, production outer profile `m6_outer_diet_k4_cap3_r1_b2_q108_p20_fold4_v1`): **390.7 M unpadded cells** [M]. The rows equal the unmodified `V.verify` exactly; production match is checked on 6 cases.
   - **Merkle and FRI hashing is 92.3% of it**: trace-tree paths 35.3%, FRI leaf hashing 24.7%, FRI paths 19.9%, queried-row leaves 12.4%.
   - Transcript is 1.7%, DEEP 2.4%, FRI folding arithmetic 2.0%.
   - Composition (OODS) evaluation is only **0.1%**.
2. **Per-child levers [M]** (unpadded cells of one child, against production):

| lever | per child |
|---|---:|
| sibling quads proven as one proof (batch 4) | **×0.365** |
| sibling pairs proven as one proof (batch 2) | ×0.577 |
| Blake3 outer commitments | ×0.757 |
| FRI last layer 2⁸ | ×0.923 |
| q100/P28 | ×0.928 |
| whole-coset FRI leaves | ×0.938 |
| q102/P26 | ×0.946 |
| last layer 2⁴ | ×0.953 |
| fold step 3 | ×0.991 |
| cap 4 / cap 5 | ×0.995 / ×0.998 |
| cap 7 | ×1.149 (worse) |

   - Combined, without a structural change ("**diet**" = q102/P26 + Blake3 + coset leaves + last layer 2⁴): **×0.650**.
   - Diet plus batch 2: ×0.384. Diet plus batch 4: ×0.252.
   - Higher outer blowup cuts the per-child cost (b4 q54 ×0.532, b8 q36 ×0.376), but each child's own prover pays more than the parent saves (§3.3). Rejected.
3. **At the tree level, padding and leaves absorb most of the per-child cut [D].**
   - On the fan-in tree (the tree the plan's best set uses), leaves are **74%** of recursion cells (26235168: 42.5 of 57.5 G).
   - Those leaves verify *native* D2 proofs, so no outer-profile lever touches them.
   - Folds sit at 2^23 padding. A cheaper child only pays once the fold arity is raised, and **re-optimised arity 6** is what makes the diet bite.
   - Padded recursion cells, against the same tree at today's profile:

| lever | 26235168 (p50 proxy) | 26235159 (p95 proxy) | basket | fits the post-P1 job cap | proof change |
|---|---:|---:|---:|---|---|
| **RECDIET** (fan-in tree, arity 6) | **×0.930** (×0.917 without the log-24 tax) | ×0.928 | ×0.931 | yes (2.11 G) | new outer profile |
| RECDIET on the post-M8 tree (arity 5) | ×0.901 | ×0.907 | ×0.905 | yes | new outer profile |
| **RECBATCH** (diet + sibling pairs, fan-in tree) | **×0.843** | ×0.849 | ×0.847 | **no**: 4.21 G jobs, needs a streaming batch prover | multi-circuit outer proof |
| batch 4 + diet (fan-in tree) | ×0.808 | ×0.821 | ×0.810 | no: 8.42 G | multi-circuit outer proof |
| RECNB3 (diet + Blake3 native commitments) [E] | ×0.877 | ×0.898 | ×0.885 | yes | **native** proof format |

   - Depth on 26235168 drops from 3 to 2 under RECDIET and RECBATCH, which is one fold fewer on the serial tail.
4. **Plan-model effect** on top of the best 2-GPU set #1–#9 (central, [pess..opt]) [E]:

| set | p50 | p95 | basket | 4 GPUs (p50 / p95 / basket) |
|---|---|---|---|---|
| #1–#9 | 11.04 s (−43.8%) | 18.84 s (−42.7%) | 166.6 s (−43.2%) | −64.3 / −65.3 / −63.6% |
| + RECDIET | **10.61 s (−46.0%)** [14.22..8.37] | 18.14 s (−44.8%) | 160.7 s (−45.3%) | −66.0 / −66.8 / −65.0% |
| + RECBATCH | **10.02 s (−49.0%)** [13.37..7.94] | 17.32 s (−47.3%) | 152.1 s (−48.2%) | −68.4 / −68.7 / −67.5% |
| + RECNB3 | 10.44 s (−46.9%) | 18.02 s (−45.1%) | 158.6 s (−46.0%) | −66.3 / −66.8 / −65.2% |

   - Recursion GPU-s at p50 after #1–#9: 7.63 → 7.07 (×0.927) with RECDIET, 6.38 (×0.836) with RECBATCH.
   - **Recursion architecture is not the ×0.67 lever.** It recovers 0.55–1.24 of the −5.3 GPU-s needed at p50, about 10–23%. No 2-GPU set reaches 60%: the best central set is −47.3%, with RECBATCH.
5. **Where the remaining recursion cost is.**
   - It is the in-leaf verification of *native* proofs, dominated by Blake2s hashing of the queried native rows, at about 8.8 k words per query × 54 queries [D/E, §3.5].
   - The next work-reduction hunt belongs in the native commitment format: committed columns, and the hash of the native trees. The outer profile is not where it is.

## 1. Method

**Census harness** (`src/integrations/riscv_cpu/rv64_recursion/om31_native/m9_recursion_census{,_test}.zig`; step `zig build test-riscv64-m9-recursion-census`):
- It builds the in-circuit verifier of one recursion child:
  - exactly `om31_outer.verifyChild`'s statement: transcript, LogUp claim sum, composition at OODS;
  - then the 4-tree capped decommitment, DEEP and FRI.
- The child is a correctly shaped synthetic proof, all zeros, in a trace-only context.
- The child authority comes from `Authority.initVerifier` on the padded component sizes of the real child classes:
  - a CPU leaf `2^18/2^23/2^19/2^20/2^22`;
  - a 4-ary fold of log-23 children `2^16/2^23/2^20/2^21/2^23`;
  - a k-leaf pair `2^19/2^24/2^20/2^21/2^23`.
- Gate counts of a trace-only graph do not depend on witness values. Production trace-only fold builds rely on the same property.
- **Validation:**
  - The phased copy of `mod.zig verify` / `fri.zig decommit` / `merkle.decommitTreesCapped` reproduces the **unmodified `V.verify` row for row** on the same guessed proof, for cap 0, 3, 4 and 5 and on all three child classes. The test fails otherwise.
  - The census child's blake rows are 1,944,960. The fold4/4 D2 receipt gives 1,941,780 per log-23 child [M] (+0.16%). qm31_ops is 3.4% lower, because table admission and summary binding are not in the bare verifier.
- **What-if gadgets** (census only, values never assigned):
  - BLAKE3 compression: 7 rounds of the same `blakeGGate` (BLAKE3's G is BLAKE2s' G), the BLAKE3 message permutation and flags, chunk chaining, parent nodes;
  - whole-coset FRI leaves;
  - batch proofs: B copies' columns side by side in trees 0..2, one composition tree, one FRI; the statement mixes each copy's public input and claims and sums the compositions.
- Run cost [M]: 37 cases in 16.3 s wall with a cached build, 1.10 GB max RSS (`/usr/bin/time -l` over memguard's child), under `memguard --gb 6`.

**Tree model** (`scripts/rv64_m9/recursion_arch_model.py`):
- It runs on the vendored, unchanged fan-in model `scripts/rv64_m9_leaf_fanin_model.py` (`codex/rv64-m9-fewer-leaves` a056cee67).
- A fold child costs `CHILD[log]` (the measured D2 rows) × the census ratio, per component. A batch of B siblings costs the census batch-B rows.
- Padded cells use the fan-in model's widths and fixed tables.
- Tests check the production trees: it reproduces the fan-in model's trees and cells exactly (24628607, 26235156, 26235168, and the fan-in plan).
- Fold arity is a profile constant, re-optimised per lever. It is the basket-minimising arity with every fold inside the envelope:
  - `env23`: all components ≤ 2^23, with a 3% margin and ≤ 2.2 G cells;
  - `blake23`: as `env23`, but qm31_ops and the cheap components may reach 2^24, as k-leaf nodes already do.
- "Taxed" adds the unvalidated log-24 composition/FRI tax of fewer-leaves review r1 (+134 M cells per log-24 node) to both sides.

## 2. Decomposition of one verified child [M]

Child: log-23 fold, production profile (b2, q108, P20, fold step 4, cap 3, lifting log 24, 6 FRI layers).

| phase | eq | qm31_ops | triple_xor | m31_to_u32 | blake_g_gate | M cells | share |
|---|---:|---:|---:|---:|---:|---:|---:|
| ingress (guessed proof wires, identity, outputs, claims) | 0 | 227,232 | 0 | 720 | 0 | 6.4 | 1.6% |
| transcript (absorb/draw, claim sum, sampled values, FRI roots, PoW, query bits) | 1,100 | 42,612 | 3,048 | 4,648 | 30,480 | 6.7 | 1.7% |
| composition at OODS + reconstruction | 13 | 13,672 | 0 | 0 | 0 | 0.4 | 0.1% |
| trace leaves (432 row hashes, 479 words per query) | 0 | 0 | 26,784 | 51,732 | 267,840 | 48.3 | 12.4% |
| **trace paths** (4 trees × 108 × 21 nodes + caps = 9,100 nodes; cap mux) | 3,488 | 387,072 | 72,800 | 0 | 728,000 | **137.8** | **35.3%** |
| DEEP quotients | 880 | 336,621 | 0 | 0 | 0 | 9.4 | 2.4% |
| **FRI leaves** (4 packs + 3 in-coset nodes per query and layer) | 0 | 133,056 | 51,840 | 76,032 | 518,400 | **96.4** | **24.7%** |
| **FRI paths** (5,003 nodes) | 5,224 | 279,936 | 40,024 | 0 | 400,240 | **77.7** | **19.9%** |
| FRI folding, twiddles, last layer | 3,618 | 271,101 | 0 | 0 | 0 | 7.6 | 2.0% |
| **total** | 14,323 | 1,691,302 | 194,496 | 133,132 | 1,944,960 | **390.7** | |

- One Blake2s node is 80 G rows + 8 triple-xor rows + 32 qm31 rows (path flip): 14,840 cells [M].
- A BLAKE3 node is 56 G + 8 xor: 9,936 cells (×0.670) [M].

## 3. The levers

### 3.1 Per child [M] and tree level [D]

The table gives the padded factor on the fan-in tree for 26235168, with the arity the lever re-optimises to.

| lever | what changes in the proof | per child [M] | fan-in tree [D] | post-M8 tree [D] |
|---|---|---:|---:|---:|
| **fewer queries via PoW**: q108/P20 → **q102/P26** (1·102 + 26 = 128) | outer `PcsConfig`: new profile domain. Grinding 2^26 Blake2s ≈ 2–3 ms/node [E] | ×0.946 | ×1.000 alone (arity 4) | ×1.000 |
| q100/P28 | as above; 2^28 ≈ 10 ms/node [E] | ×0.928 | ×1.000 | ×1.000 |
| Merkle cap c = 4 / 5 / 7 (static multi-proof dedup of the top c levels) | cap sidecar from the prover's tree (c ≥ 4 is not derivable from 108 paths) | ×0.995 / ×0.998 / **×1.149** | — | — |
| whole-coset FRI leaves (16 OM31 in one leaf; no in-coset nodes) | FRI layer tree layout | ×0.938 | ×1.000 alone | ×1.000 |
| FRI last layer 2⁴ / 2⁸ coefficients | `log_last_layer_degree_bound` | ×0.953 / ×0.923 | ×1.000 alone | ×1.000 |
| fold step 3 | FRI fold step | ×0.991 | — | — |
| **Blake3 outer commitments** (channel stays Blake2s) | hash of every outer Merkle tree and FRI layer; new GPU Merkle kernels for recursion trees | ×0.757 | ×0.954 (arity 5, blake23) | ×0.926 |
| **diet** = q102/P26 + Blake3 + coset + last layer 2⁴ | all of the above | ×0.650 | **×0.917 / taxed ×0.930** (arity 6) | ×0.901 (arity 5) |
| batch 2: sibling pairs as one outer proof | multi-circuit outer proof (shared trees, one FRI) | ×0.577 | ×0.900 (all levels, arity 6) | ×0.851 |
| batch 4 | as above | ×0.365 | ×0.839 | ×0.766 |
| **batch 2 + diet** | both | ×0.384 | **×0.837 / taxed ×0.843** (arity 6) | ×0.767 |
| batch 4 + diet | both | ×0.252 | ×0.808 | ×0.721 |
| higher outer blowup b4 q54 / b8 q36 | outer blowup | ×0.532 / ×0.376 | rejected (§3.3) | rejected |
| diet + Blake3 *native* commitments [E] | native proof format | — | ×0.872 / taxed ×0.877 | ×0.823 |

Why single levers show ×1.000 at the tree level:
- A 4-ary fold of log-23 children holds 7.77 M blake rows, which is 93% of 2^23. Removing 5–8% of a child's rows leaves every fold at the same power of two.
- Only a lever, or a sum of levers, large enough to admit a fifth or sixth child pays. It pays by cutting the *number* of folds: 26235168 on the fan-in tree goes from 9 folds to 5, depth 3 to 2.
- On the fan-in tree the diet's 6-ary folds are qm31-bound at 2^24. That is why the `blake23` envelope is needed, and why the log-24 tax applies.

### 3.2 Which cut is largest, and the prototype

- **The largest per-child cut is batching sibling proofs** (×0.365 at B = 4) [M]. This is the "verify several children's FRI in one batched check" option, done the only sound way.
  - FRI cannot be batched across *independent* proofs without a joint challenge after every child commits.
  - A multi-circuit outer proof gives that challenge and also shares the Merkle paths. That sharing is worth more than the FRI: trace paths go 137.8 → 34 M per child at B = 4.
- **The largest memory-feasible cut is the diet** (×0.650 per child; ×0.93 padded on the fan-in tree). It needs only an outer-profile change and a Blake3 Merkle kernel. Each job keeps today's envelope (max job 2.11 G cells).
- Both are prototyped in the CPU circuit builder and counted [M]. The Blake3 compression gadget, the coset-leaf FRI and the batch geometry/statement are in `m9_recursion_census.zig`.

### 3.3 Rejected

- **Higher outer blowup.** Fewer queries cut the parent's per-child cost by 0.47 × 390.7 M = 0.18 G cells at b4, but the child's own prover LDE doubles.
  - Break-even needs the LDE-proportional share of a node's GPU-s to be under 17% (leaf child, 1.1 G cells) or 10% (fold child, 1.87 G) [D].
  - FFT (35%) and Merkle (18%) alone exceed that [M, `ab8-kernels`]. Rejected.
  - It also OOMed on the GPU in M6 (23.7 GB interaction LDE) [M].
- **Merkle caps above 3.** The in-circuit cap lookup is a binary mux over 2^c hashes per query per tree (`selectHash`), so its cost grows as 2^c and outruns the c path nodes saved past c ≈ 5 [M].
  - A logarithmic lookup would need a memory/lookup argument the circuit AIR does not have.
- **Poseidon2 for recursion commitments.** Wave 1 measured a GPU kernel cost ×9.95 [M]. BLAKE3 keeps the same G gate in the circuit (×0.70 G rows per compression) and costs at most Blake2s on the GPU: the leaves are HBM-bound at 1.4–1.6 TB/s, and the node layers are compute-bound at ×0.7 work. **BLAKE3 is the cheaper-hash answer.**
- **One wide aggregation layer.** The arity sweep runs 2..16. At today's per-child cost the optimum stays 4. After the diet it is 6, and wider folds pad to 2^24 in blake rows.
  - One wide layer only wins with batch 4 (arity 10–16, depth 2), and that needs 8.4 G-cell jobs.
- **Different final wrap.** The root is in the tree model as the last fold. The wrap only affects the serial tail, which the depth cut (3 → 2) already shortens by one fold [D]. A separate wrap (another field or hash) does not reduce work.

### 3.4 Soundness (D2 target: 128 conjectured bits per proof under the ethSTARK assumption with credited PoW, ideal-hash Fiat–Shamir)

- **q102/P26:** 1·102 + 26 = 128, the same accounting as the reviewed `m3_b4_q51_p26` profile (2·51 + 26), which already credits 26 PoW bits. The PoW is checked after the last FRI commitment and before query derivation, as today. New profile domain string, so identities, wire and transcript all change.
- **BLAKE3 outer commitments:**
  - The binding relies on BLAKE3 collision resistance (256-bit output, 128-bit generic) instead of BLAKE2s. BLAKE3 has a smaller round margin: 7 rounds against 10.
  - The Fiat–Shamir channel stays BLAKE2s.
  - Receivers need a CPU BLAKE3 Merkle verifier (Zig std has BLAKE3).
  - **This changes the proof and the assumption set; it needs a security-review note.**
- **Coset leaves and last layer 2⁴:** these are layout and degree-bound changes. The FRI query term is unchanged; the commit-phase terms move by less than 2^-100 [E, needs `model.py` rerun]. Proof bytes change.
- **Arity 5/6 folds:** a profile constant, bound in the topology fingerprint as `STWO_RV64_FOLD_ARITY` already is. Fewer recursive proofs make the union bound strictly smaller.
- **Batch proofs:**
  - One transcript covers B sibling circuits, with one query phase (2^-128) for B circuits. The union bound shrinks.
  - Each circuit's identity and FIXED root is mixed and admitted in T_rec exactly as today.
  - Changes needed: a new outer wire, a receiver, and a tamper corpus (cross-circuit mask swap, a copy-count lie, a missing circuit).
- **Native BLAKE3:** changes the native D2 proof, its golden and the native GPU kernels. This is outside "recursion-only" and listed for the owner.

### 3.5 Where leaf cost lives (not measured here) [D/E]

- A CPU leaf's 3,376,320 blake rows at q54 are 781 compressions per query.
- Paths and FRI at the outer geometry account for about 230 per query.
- The rest, about 550 compressions per query (≈ 8.8 k M31 words), is the hashing of the queried native rows across the native trees.
- So about 70% of a leaf's Blake work, and about 51% of its unpadded cells, is hashing native rows. Outer-profile levers cannot reach it.
- The native-side options are:
  1. **fewer committed native columns**: native GKR v2 is already in the plan at ×0.936 per leaf;
  2. **BLAKE3 native commitments** (RECNB3, ×0.877 [E]);
  3. **native batch proofs** (natives sharing paths and FRI): small, because row hashing dominates.
- The native per-phase split was not measured: synthesising the D2 CPU geometry is the next census step. It needs `cpu_capture` column counts.

## 4. Plan-model variants (`scripts/rv64_m9/plan_model.py`, vendored from `codex/rv64-m9-plan` + this diff)

- New levers, off the order and in the exhaustive search:
  - **`RECDIET`**;
  - **`RECBATCH`** (gated on a streaming batch prover);
  - **`RECNB3`** (native format change).
- `REC_ARCH` holds the per-block factors, folds and depth from `model.json`. Synthetic p50/p95 use the 26235168/26235159 factors.
- Scenarios:
  - central = taxed factor;
  - pess = taxed × 1.03, covering BLAKE3 Merkle kernel parity, PoW grinding and the last layer;
  - opt = untaxed.
- The outer-profile levers shrink fold GPU-s only; leaves are unchanged.
- Results are in §0.4. Tests: `scripts/tests/test_rv64_m9_recursion_arch_model.py` (10/10) and `test_rv64_m9_plan_model.py` (16/16). One bound was relaxed: best central < 0.49, since RECBATCH lifts it to 0.473.

Commands:
```
zig build test-riscv64-m9-recursion-census -Doptimize=ReleaseSafe          # census (CPU, ~3 min, memguard --gb 6)
python3 -I scripts/rv64_m9/recursion_arch_model.py --out vectors/reports/rv64-m9-prep/m9-recursion-arch/model.json
python3 -I scripts/rv64_m9/plan_model.py --gas-sample <gas_sample.json> --json vectors/reports/rv64-m9-prep/m9-recursion-arch/plan_model.json
python3 -I scripts/tests/test_rv64_m9_recursion_arch_model.py && python3 -I scripts/tests/test_rv64_m9_plan_model.py
```

## 5. Risks

1. **The tree factor is padding-quantised.** A fold that grows 3% more than the census (admission, summary, extra outputs) can fall back to arity 5. The fan-in tree's 6-ary folds are at the 2^24 qm31 boundary. Measure one real 6-ary fold before choosing the arity.
2. **The log-24 tax is unvalidated** (fewer-leaves r1). Taxed against untaxed differ by 0.013 on 26235168.
3. **Outer GKR (OGKR_ENG) overlaps.** It changes the child's interaction tree, which takes the 304 → 128 columns out of the trace leaves. The census child is today's non-GKR outer proof. The factors are applied multiplicatively on top of OGKR_ENG [E].
4. **Batching needs a new prover shape.**
   - A batch job proves 2 sibling circuits under one transcript.
   - Memory stays per-circuit only with streaming leaf hashing: chained Blake state per leaf, 32 B × 2^24, as in the stream-commit branch's column-chunked absorption, plus composition and DEEP accumulation per circuit.
   - Latency: a pair waits for both siblings.
   - Not prototyped on the GPU.
5. **BLAKE3 GPU kernels do not exist** for the recursion Merkle path (`mixed_leaf`, `child_layer`, `fri_leaf`). Pess charges +3%.

## 6. Integration after GPU-native lands (in order, each default-off)

1. Rebase this branch on integrate. It adds files only, apart from one build-list entry (`build_support/products/riscv_recursion.zig`) and one catalog entry (`catalog.zig`). Run the census and the tests.
2. **Outer profile `m9_outer_diet2_k6_cap3_b2_q102_p26_blake3_coset_ll4_v1`**, selected with `STWO_RV64_OUTER_PROFILE` (the environment flag `STWO_RV64_M9_RECURSION_DIET=1` is only an alias), landed in four steps:
   1. `protocol.zig`: the profile, config (q102/P26, last layer 4), `foldMerkleCapLog` 3, `requiredFoldArity` 6, and the domain string.
   2. The FRI coset-leaf layout in the outer prover and verifier (`fri/merkle_queries`, `om31_native/fri.zig`).
   3. BLAKE3 outer Merkle:
      - CPU hasher;
      - in-circuit gadget (promote the census `blake3Compress` into `native_verifier/merkle.zig` behind the profile);
      - CUDA `mixed_leaf`/`child_layer`/`fri_leaf` BLAKE3 variants, with parity tests against the CPU hasher.
   4. Plan arity 6 in `ready_dag` with the fold-arity guard (fall back to 5 where a fold would cross 2^24 blake rows).
3. **Gates:**
   - fold-child rows equal to the census (`M9_RECURSION_CENSUS` against `RECURSION_NODE_SHAPE`);
   - one real 6-ary fold ≤ 2^23 blake rows and ≤ post-P1 memory;
   - paired 3+3 A/B on 607 + 26235168 (recursion GPU-s ≤ 0.95× flag-off);
   - fresh receiver with tamper corpus (wrong cap, coset leaf, last-layer coefficient, PoW nonce).
4. Refit `REC_ARCH` from measured trees; replace the [D] factors.
5. **Batch proofs (RECBATCH), only after P1 and the stream-commit chunk plan:**
   - multi-circuit outer prover with per-circuit streaming commit;
   - batch wire, receiver and corpus;
   - fold statement admits B identities per child proof;
   - gate: a 2-batch job ≤ 13 GB.
6. Owner decision, separately: native-commitment work (BLAKE3 natives, fewer committed native columns). It is where 74% of recursion cells sit.

## 7. Files

- New:
  - `src/integrations/riscv_cpu/rv64_recursion/om31_native/m9_recursion_census.zig`;
  - `src/integrations/riscv_cpu/rv64_recursion/om31_native/m9_recursion_census_test.zig`;
  - `src/integrations/riscv_cpu/rv64_m9_recursion_census_test_root.zig`;
  - `scripts/rv64_m9/recursion_arch_model.py`;
  - `scripts/tests/test_rv64_m9_recursion_arch_model.py`;
  - this doc;
  - the receipts.
- Edited (one line each): `build_support/products/riscv_recursion.zig` and `build_support/products/catalog.zig`, for the census step.
- Vendored:
  - `scripts/rv64_m9_leaf_fanin_model.py` (byte-identical to `codex/rv64-m9-fewer-leaves`);
  - `scripts/rv64_m9/plan_model.py` and `scripts/tests/test_rv64_m9_plan_model.py` (from `codex/rv64-m9-plan`, with the RECDIET/RECBATCH/RECNB3 diff and one relaxed bound).
