# RV64 M9 frontier gap: where our work per gas exceeds ZisK, Airbender (v3) and SP1

Status: 2026-11-07, M9/M10 prep stream `m9-frontier-gap`, branch `codex/rv64-m9-frontier-gap` (cut from `codex/rv64-m7-integrate` @ 1088a894d). It only adds files. No GPU was used: every new number is either taken from a receipt, derived from receipts or frontier source, or estimated.

Labels:
- **[M]** measured, with a receipt;
- **[D]** arithmetic on measured numbers or on frontier source;
- **[E]** estimate;
- **[code]** read in a frontier source tree;
- **[pub]** published by the vendor or by ethproofs.org (fetched 2026-11-07), not reproduced by us.

Model: `python3 -I scripts/rv64_m9/frontier_gap_model.py --gas-sample <gas_sample.json> --json vectors/reports/rv64-m9-prep/frontier-gap/model.json`. It is a **variant of `plan_model.py`** (M9 plan rev 4, `codex/rv64-m9-plan`). It loads that model unchanged and adds five levers by scaling the plan's own inputs: native GPU-s per Minstr, the recursion fit, and the leaf/fold split.
- Tests: `python3 -I scripts/tests/test_rv64_m9_frontier_gap_model.py`, 8/8 pass. They check identity with the plan model when no new lever is on, that the leaf/fold/native scaling is exact, that globals are restored, the grind cost and its serial tail, the NGKRFULL verifier cost under STACK, and pin the central and production results.

> **Review 1 (2026-11-07) changed the headline.** Central best is now **p50 8.22 s (−58%)**, not 7.92 s (−60%). In the central case it no longer reaches 60% on 2 GPUs in any metric. Findings and fixes are in §8; every changed number below is marked [R1].
- Census: `scripts/rv64_m9/frontier_gap_width_census.py` → `width-census-24628607-d2.json` [M], read from the producer log of the accepted D2 request.

Frontier trees (read-only clones):
- `zksync-airbender` @ 0decdcd;
- Airbender **v3** @ 36e57d3;
- `pil2-proofman` @ 27b2fc2;
- `zisk` @ 64a1f16;
- `zisk-ethproofs` @ 5a72736.

There is no SP1 clone. SP1 facts come from its docs and L2BEAT [pub].

---

## 0. TL;DR

1. **On the same hardware the frontier is 2–6× ahead** [pub vs E]. Ethproofs averages over mainnet blocks (mean about 30 M gas):

   | system | GPUs | average time |
   |---|---|---:|
   | Airbender v3 | 1×5090 | 5.9 s |
   | Airbender v3 (Zilkworm) | 2×5090 | 3.4 s |
   | ZisK | 2×5090 | 6.0 s |
   | SP1 Twin Peaks | 2×5090 | 28.8 s |

   Ours on 2×5090:
   - today (bench15-1 fit): about 38 s at p50. [R1] This is extrapolated: p50 is 93 M instr and the largest measured bench15-1 block is 57.8 M instr, so label it [E];
   - post-M8 baseline: 19.7 s;
   - plan rev 4 best set: 11.0 s [E].

   The security claims differ (§1.3). ZisK claims the most: 128-bit Johnson-bound. Airbender v3 claims 100-bit under a pessimistic conjecture, and we claim 128-bit conjectured. So the gap is not a security discount.
2. **Against ZisK, the gap is not work.** Our committed native LDE bits per instruction at D2 roughly equal ZisK's per step: 23.9 k vs 23.5 k [D]. The old "2× below ZisK" figure was at blowup 2; D2 doubled the LDE. Recursion cost per verified 2²²-row proof is also of the same order (§2). ZisK's lead is execution: busy time and ns/bit. That is the subject of `rv64-frontier-gpu-delta.md`.
3. **Against Airbender v3, the gap is work.**
   - It commits 40–58 BabyBear columns per RV32 cycle at blowup 2, with no committed lookup or composition columns (GKR + WHIR). That is about 3.1 k LDE bits per cycle, **×7.8 below our 23.9 k per RV64 instruction** [D from code].
   - [R1] **×7.8 is an upper bound.** It counts the six opcode-family circuits only. It leaves out the delegation circuits (`keccak_special5` 267, `bigint_with_control` 258, `blake2_with_compression` 872 columns per row), `inits_and_teardowns` (32 per row), lookup multiplicities and the GKR prover's compute. Our 193 cells/instr and ZisK's 23.5 k/step both include Keccak, and Keccak is 47% of ZisK's area (20.8 of 44.6 G, `committed-work-comparison-v1.json`). If Airbender's delegation share is similar, the like-for-like gap is about ×4 [E].
   - RV32 needs more cycles per gas than RV64, about ×1.3–1.8 [E].
4. **The largest structural difference is how wide our proofs are to open.**
   - A native CPU-segment proof opens **5,833 values per query** [M]. ZisK's Main proof opens 247 [code], and an Airbender circuit opens about 50.
   - The reason: our columns are short. The median native tree's average column is 2^16.2 rows, against 2^22 for the tallest component [M, census].
   - Opened-row hashing is **68% of a CPU leaf's cells** [D]. In ZisK, Merkle paths are 70–75% of verifier hashes [code].
   - Stacking short columns into equal-height ones would need about 151 opened values instead of 5,833 [D]. [R1] It was 136. That figure counted composition as 1, but composition is already 16 full-height columns.
5. **Plugged into the plan model** (§4). Each lever alone against the post-M8 baseline, central [E]:

   | lever | p50 GPU-s alone |
   |---|---:|
   | stacked columns | −5.6 |
   | BLAKE3 (7-round) recursion hash | −2.8 |
   | full native GKR | −1.7 |
   | query grinding 20 → 26 [R1] | **+4.5** at the as-built device grind (was −0.5 at an assumed 25 G/s) |

   Reverting D2 (b4 → b2) loses alone (+5.6) but **wins once leaves are cheap**. Plan best + STACK + BLAKE3R + NGKRFULL + D2REV reaches, central [R1]:
   - **p50 8.22 s (−58%), p95 13.81 s (−58%), basket 124.4 s (−58%)**;
   - kernel GPU-s at p50 16.12 → 11.59, a **×0.72 cut**, against the ×0.67 needed;
   - mainnet-weighted mean 8.4 s **warm**, meaning repeat blocks with class hits, as in plan rev 4.
   - **[R1] Production** means every request is a new block, so the host class build is on the critical path: p50 14.1 s (−53% against a 29.7 s production baseline). Mainnet-weighted mean 14.2 s.

   The pessimistic case reaches −47% (12.7 s) and the optimistic −67% (5.8 s). **No case reaches 60% on 2 GPUs except the optimistic one**, so this is a candidate set, not a plan of record. With 4 GPUs, STACK + BLAKE3R gives −72% central and −64% pessimistic. The set turns on the gates in §5.
6. **What changes the proof.**
   - Every lever except grinding changes the commitment or the hash, so every one needs a new profile, a new identity and a soundness note.
   - The query-phase security of each layer stays 128-bit conjectured, unchanged.
   - Stacking costs at most about 15 bits of algebraic (OODS) margin, out of about 181 [D].
   - BLAKE3 is a standard hash with a 128-bit claim. Airbender's ad hoc 7-round Blake2s is not, and we should not copy it.

---

## 1. Facts versus marketing

### 1.1 What is published (ethproofs.org/clusters, 2026-11-07) [pub]

| cluster | GPUs | avg time | GPU·s per block (upper bound, GPUs × time) | cost/proof |
|---|---:|---:|---:|---:|
| Airbender v3 1×5090 | 1 | 5.9 s | 5.9 | $0.0010 |
| Zilkworm Airbender v3 2×5090 (on-prem) | 2 | 3.4 s | 6.8 | $0.0012 |
| Airbender v3 4×5090 | 4 | 2.4 s | 9.6 | $0.0016 |
| ZisK 2×5090 | 2 | 6.0 s | 12.0 | $0.0021 |
| ZisK 4×5090 | 4 | 7.3 s | 29.2 | $0.0064 |
| Axiom OpenVM 16×5090 | 16 | 3.2 s | 51 | $0.0099 |
| Succinct SP1 Twin Peaks 2×5090 | 2 | 28.8 s | 57.6 | $0.0093 |
| **ours, post-M8 baseline / plan best / + frontier levers [E, R1]** | 2 | 19.7 / 11.0 / 8.2 s (p50, warm) | 39 / 22 / 16 | — |

**Caveats on these numbers:**
- They are averages, not p99. Ethproofs did not show soundcalc values for any of these clusters.
- The ZisK 4×5090 entry being slower than its 2×5090 entry suggests different block mixes or versions over time, so treat each row as an order of magnitude.
- ZisK's own `proving_time` excludes witness fetch (`cluster-common/src/types.rs:444-450`) [code], and ethproofs proving time similarly starts after input.
- Our numbers are warm proving on our basket model, with capture included.
- The team-level page lists Zilkworm (Airbender v3) at 9.6 s and ZisK at 8.4 s over all their history.
- Older vendor posts ("SP1 Hypercube 99.7% real-time on 16×5090", "Airbender 35 s on one H100") describe older configurations and are not used here.

### 1.2 What is in the code [code]

| | ours (D2, M7/M8) | ZisK (pil2-proofman) | Airbender v3 | SP1 Hypercube [pub] |
|---|---|---|---|---|
| field | M31; QM31/OM31 challenges | Goldilocks; cubic extension | BabyBear; e4 | KoalaBear; degree-7 extension |
| IOP | univariate Circle STARK, LogUp (native GKR v1 partial) | univariate STARK; FRI (default) or STIR | GKR + WHIR (multilinear) | multilinear: LogUp-GKR + jagged PCS + Basefold |
| committed per row | MAIN + INTER + composition | stage1 + stage2 + quotient | **base layer only** (memory + witness); GKR layers uncommitted | real data only (jagged) |
| native width | **203 M31 cells/instr** (MAIN 100.5, INTER 68.9, comp 23.7, fixed 9.6) [M] | Main: 2 + 152 + 87 + 6 GL columns per row at 2²² (`recursion-cell-memory-model.html`, `MAIN`) | 40–58 BabyBear columns per cycle, unrolled per opcode family at 2²⁴ rows (`circuit_defs/unrolled_circuits/*/generated/layout.json`) | — |
| native blowup | **4** (D2) | 2 | 2 (`DEFAULT_LDE_FACTOR`) | — |
| queries / grinding | native q54 p20; outer q108 p20 | solved for 128-bit JBR: about 211 at b2 with 24 bits (`hash_family.rs`, `security/pcs/fri.rs`) | 87 + 15 + 8 + 6 + 5 over WHIR rounds, PoW 25–28 (`example_configs.rs`) | — |
| security claim | 128 conjectured (ethSTARK) | 128 JBR | **100**, pessimistic conjecture | 98 proven (soundcalc via L2BEAT) |
| recursion hash | Blake2s, 10 rounds, in-circuit (about 22.7–28.2 k committed cells per compression) | Blake3 (7 rounds) default, Poseidon2 option | **reduced-round Blake2s (7 rounds)**, one round per row, 872 committed columns (`blake2_with_compression` layout; `REDUCE_ROUNDS_BIT_IDX`) | Poseidon2 |
| recursion shape | leaf per segment or truth, 4-ary folds, 19 nodes on 24628607 | recursive1 per instance (+ compressor), recursive2 tree of arity 2, then final | a linear chain of verifier-program layers, each verifying the whole previous proof | normalize → compress groups of 3–4 → shrink |

### 1.3 Normalising security

At equal security our query-proportional work would *grow* if we moved to ZisK's regime:
- **JBR-128** at b4 needs q ≈ (128 − 20)/0.99 = **109 queries against our 54** [D].
- **Airbender's 100-bit pessimistic rule** credits our D2 native profile with 2·54/1.2 + 20 = **110 bits** [D].

So none of the frontier's lead comes from weaker security than ours, except Airbender's roughly 10–28 bits. At most that is worth ×1.2–1.3 on its query-proportional work [E].

---

## 2. Work per instruction and per gas, component by component

| component | ours | ZisK | Airbender v3 | basis |
|---|---:|---:|---:|---|
| native LDE bits per instr/step/cycle (fixed excluded) | **23.9 k** (D2 b4); 12.0 k at b2 | 23.5 k (b2) | **3.1 k** (b2, base only) | [D] cells × 31/64 bits × blowup |
| native LDE bits per gas | 76.6 k (basket 3.20 instr/gas) | 95.2 k (4.04 steps/gas) | — (Zilkworm cycles/gas unpublished) | [D] |
| values opened per query, per native proof | **5,833** (FIXED 203, MAIN 3,606, INTER 2,008, comp 16) | 247 (Main) | about 50 per circuit | [M] / [code] |
| average committed column height, native | **2^16.2** (median tree), against 2^22 tallest | one AIR per proof, 2²² | 2²⁴ per circuit | [M] census |
| verifier hashes per verified proof | CPU leaf at q54: 366 row + 92 path compressions per query, **68% row hashing** | Main: 36,201 Blake3 at about 211 queries, **70–75% paths** | — | [D] / [code] |
| verifier bits per query | about 318 Mbit (17.2 Gbit / 54) | about 60 Mbit (12.7 Gbit / 211) | — | [D] |
| in-circuit hash cost per compression | 14.4 k raw (MAIN 4.8 k + INTER 9.6 k), 22.7–28.2 k committed | Blake3: 56 rows × about 98 GL columns (`README.md` grid) | 7 rows × 872 base columns ≈ 6.1 k (GKR, so lookups uncommitted) | [M] / [code] |
| recursion cells relative to native cells | 6.6× (M6, q108); the post-M8 model has recursion at 1.3× native GPU-s | recursive1 about 0.2× its Main proof [D] (+ recursive2 tree) | verifier about 1 M cycles per circuit proof [code] | [M/D] |

**Reading.**
- **Per verified proof we hash as much as ZisK, but ZisK does it at 4× our queries.** Our cost per query is about 5× theirs, because our rows are about 24× wider.
- Width comes from proving all components of a segment in one proof. Most components are short: a median of 2^16.2 rows, and truth proofs down to 2^12 rows over 7,409 columns [M].
- In a lifted VCS **every column costs one opened value per query, regardless of its height**.
- ZisK proves each AIR in its own proof. Airbender proves each opcode family as a tall, narrow circuit. Their verifiers pay for depth, not width.

---

## 3. The five structural differences and what adopting each would give us

The effects below are relative to the post-M8 baseline at p50 (29.1 M gas, 93 M instr), central [E]. All are in `model.json` → `single`.

### 3.1 Wide openings: stack short columns (`STACK`, flag `STWO_RV64_M9_STACKED_COLUMNS`)

**Change.** Commit groups of 2^s short columns c_j (height 2^k) as one column T of height 2^(k+s), with c_j = T restricted to the j-th coset.
- **Prover:** its LDE is c_j's LDE plus s fused butterfly layers, one extra HBM pass over the stacked cells.
- **Verifier:** opens **one** value of T per query instead of 2^s values.
- **Fiat–Shamir:** OODS samples T at the 2^s preimages of z. The verifier recovers c_j(z) with an inverse 2^s-point butterfly, once per proof.
- **DEEP:** the quotient on T uses the degree-2^s vanishing polynomial and interpolant. The per-query arithmetic count is unchanged (it still sums 2^s terms), but the hashes are divided by 2^s.

**Evidence.**
- The census (§2): ideal stacking leaves 151 of 5,833 opened values [D]. [R1] It was 136, which counted composition as 1 instead of 16.
- The model takes 15% (pess 35%, opt 6%), keeping mid-height components unstacked.
- Opened-row share of leaf GPU-s: 0.66 (pess 0.55: truth leaves and NGKR overlap).
- Native ×1.03 (pess 1.08) for the extra pass.

**Effect.**
- Leaf ×0.44 (pess ×0.64).
- **p50 −5.6 GPU-s alone** (native +0.3, recursion −5.9); p95 −9.5; wall −4.0 / −6.7 s.

**Frontier precedent.** SP1's jagged PCS is the general form: it commits only real data, and stacking makes opening cost independent of column count. ZisK and Airbender avoid the problem through their proof partitioning.

**Proof change.** A new commitment layout, OODS point set and DEEP quotient.
- FRI query bits: unchanged.
- OODS/DEEP algebraic term: grows by log₂ 2^s ≤ s ≈ 13 bits on a margin of about 181 (`rv64-m7-profiles.md` §2) [D].
- Needs a soundness note and a new native profile identity.

### 3.2 Hash rounds: BLAKE3 for recursion-facing trees and the channel (`BLAKE3R`, flag `STWO_RV64_M9_BLAKE3_RECURSION`)

**Change.** Every tree a leaf opens, plus the channel, moves to BLAKE3: 7 rounds of the same G function, a different message schedule and flags.

**Frontier.**
- ZisK's default family is Blake3 [code].
- Airbender's recursion uses a **reduced-round (7) Blake2s** delegation [code]. That is not a standardised hash, so we do not copy it.

**Effect.**
- In-circuit G-gate cells ×0.7.
- The model saves 0.3 × 0.8 of hash cells (pess 0.3 × 0.6): message load, `m31_to_u32` conversion, feed-forward and tables do not scale with rounds.
- No native gain: Merkle leaves already run at 1.4–1.6 TB/s, so they are HBM-bound [M].
- **p50 −2.8 GPU-s alone**, all in recursion; p95 −4.7.
- After STACK it shrinks to about −1.1, because hashes become a smaller share of the leaf.

**[R1] Prior art to reuse; it is not a green field.** `codex/rv64-m7-integrate` already has:
- an experimental BLAKE3 channel and lifted Merkle hasher (`src/core/channel/blake3.zig`, `src/core/vcs/blake3_hash.zig`);
- the 7-round compression (`src/core/crypto/blake3_compression*.zig`);
- Metal kernels;
- in the pre-RV64 product line, a typed in-circuit BLAKE3 G component: 124 columns, 80 degree-2 equations and 56 lookup requests per G, 72 rows per compression (`design/riscv-proving-stack/blake3-migration.md`, 2026-09-21–23 entries).

Gate 3 starts from these. The typed G is wider per call than our Blake2s G (about 60 MAIN cells per G), so the cell saving still comes from 56 G calls against 80, not from a better G. None of it is qualified for production.

**Relation to Poseidon2.** This is the cheap alternative to Poseidon2, which the reviewed stream found a net loss as built because of the ×23.9 serial transcript [M]. BLAKE3's serial channel costs the same as Blake2s per block or less, so it needs no transcript re-engineering [E].

**Proof change.** A new hash in every native and outer tree and in the channel, so new identities and VKs. BLAKE3 claims 128-bit collision resistance, the same class as Blake2s. The security-level target is unchanged.

### 3.3 Blowup, queries and grinding (`D2REV`, `GRIND26`, flag `STWO_RV64_M9_GRIND26`)

**Frontier.** Both commit the base trace at blowup 2. ZisK grinds 24 bits and its comments argue for grinding on recursion layers [code]. Airbender grinds 25–29 bits per WHIR round [code].

**We chose D2 (b4) because each query is expensive to verify.**
- D2REV alone: native −3.0, but recursion +8.6, so **+5.6 GPU-s**: a loss, as the plan says.
- **With STACK the trade flips.** Doubling the queries now doubles a much cheaper leaf. The central top set includes D2REV, which takes native from 8.05 to 5.75 GPU-s.
- So the D2 decision should be re-taken after STACK, not before.

**GRIND26.**
- Native q54 → q51 and outer q108 → q102. Both stay at exactly 128 conjectured bits: 2·51 + 26 = 1·102 + 26 = 128.
- The leaf/fold per-query share is 0.95.
- ~~Grinding costs 2^26 Blake2s per proof at about 25 G/s per GPU [E]: about 0.25 GPU-s at p50 over 83 proofs.~~
- **[R1] The as-built device grind is about 1.1 G Blake2s/s, not 25.** Source: `codex/rv64-m8-gpu` `vectors/reports/rv64-m8-20261106/runtime/pipeline-diagnostic-1.json` [M, diagnostic]. Twelve jobs take 3.149 s at 28 bits against 0.192 s at 25 bits, about 0.246 s per 28-bit grind. That gives 2^28 / 0.246 s = 1.1 G/s at the expected nonce, and P(rate ≥ 5 G/s) < 1% [D].
  - At 1.1 G/s, 87 proofs × 2^26 cost 5.3 GPU-s at p50.
  - The last leaf and one fold per level grind serially, adding about 0.24 s to the tail. The model now charges that tail on the wall.
- **p50 +4.5 GPU-s alone: a loss.** The break-even rate on the top set is **16.7 G/s per GPU**. That is above even the 13.4 G/s engineered estimate in `rv64-gpu-2s-block-plan.md` row 10, which the model uses as the optimistic case. GRIND26 is out of every recommended set until a grind kernel measures ≥ 17 G/s.

### 3.4 Committed intermediates: native GKR for all INTER (`NGKRFULL`, flag `STWO_RV64_M9_NATIVE_GKR_FULL`)

**Frontier.**
- Airbender v3 commits only base-layer columns; LogUp and permutation intermediates live in GKR layers [code].
- SP1 uses LogUp-GKR [pub].
- The plan's NGKR covers v2 strict classes: native ×0.826, leaf ×0.936.
- INTER is still 68.9 cells/instr [M]. v2 strict halves it [D, 4-GPU §4.2].

**Effect.**
- Native ×0.92 (pess ×1.0, gated on the GKR prover's ns/fact as outer GKR was [M]).
- Leaf ×0.92 when STACK is off.
- **[R1]** With STACK on, the opened-width saving is gone, but the in-circuit GKR verifier stays. The model now adds +0.04 of today's leaf (pess 0.06, opt 0.02) [E]. For comparison, outer GKR as built was a recursion loss (`ogkr_alone` ×1.07).
- **p50 −1.7 GPU-s alone.** In the best set its marginal gain is now 0.05 s at p50 (8.27 → 8.22).

**Proof change.** Like NGKR: a new native profile and a GKR soundness term.

### 3.5 [speculative] Airbender-v3-style native IOP (`MLE`, not in any recommended set)

**Change.** Base columns only, at blowup 2, with no committed composition (zerocheck/sumcheck) and a WHIR PCS. Airbender's native LDE bits per cycle are ×7.8 below ours. RV32 cycles per gas run ×1.3–1.8 [E], and the GKR prover compute replaces our FFT and Merkle passes [E].

**Effect.** The model's central assumption is native ×0.55 and leaf ×0.55, giving **p50 −9.5 GPU-s**: the largest single lever. It is a new prover, not an M9 change. It is in the model only to bound what M10+ could buy.

---

## 4. Plan-model result: plan rev-4 best set (IO, INPLACE, STREAM, WITNESS, OCC, LEAVES, NGKR, OGKR_ENG, GPUCAP) plus the new levers [E]

All subsets of {STACK, BLAKE3R, GRIND26, NGKRFULL, D2REV} were searched. Cut is against the post-M8 baseline (p50 19.7, p95 32.9, basket 294 s central).

| added to plan best | p50 s (cut) | p50 kernel GPU-s (native / rec) | p95 s (cut) | basket s (cut) |
|---|---:|---:|---:|---:|
All rows below are [R1], recomputed after review.

| added to plan best | p50 s (cut) | p50 kernel GPU-s (native / rec) | p95 s (cut) | basket s (cut) |
|---|---:|---:|---:|---:|
| (plan best alone) | 11.04 (44%) | 16.12 (8.50 / 7.63) | 18.84 (43%) | 166.6 (43%) |
| + STACK + BLAKE3R | 8.74 (56%) | 12.59 (8.75 / 3.84) | 15.17 (54%) | 132.4 (55%) |
| + STACK + BLAKE3R + NGKRFULL | 8.46 (57%) | 12.10 (8.05 / 4.05) | 14.59 (56%) | 128.2 (56%) |
| + STACK + BLAKE3R + D2REV | 8.27 (58%) | 11.70 (6.25 / 5.45) | 13.98 (57%) | 125.2 (57%) |
| **+ STACK + BLAKE3R + NGKRFULL + D2REV (central best)** | **8.22 (58%)** | **11.59 (5.75 / 5.83)** | **13.81 (58%)** | **124.4 (58%)** |
| previous best + GRIND26 at the as-built grind | 11.18 (43%) | — | 18.77 | 168.0 |
| pessimistic best (+ STACK + BLAKE3R) | 12.70 (47%) | 17.09 | 21.82 (47%) | 191.7 (47%) |
| optimistic best (central-best set) | 5.79 (67%) | 8.68 | 9.72 (66%) | 88.4 (66%) |
| 4×5090 + STACK + BLAKE3R (central / pess) | 5.57 (72%) / 8.59 (64%) | — | 9.19 / 14.15 | 85.4 / 130.1 |

**Mainnet-weighted mean wall** (2,897-block sample, central, warm): baseline 20.1 s → plan best 11.3 s → **central best 8.4 s** (p95 13.8 s).

**[R1] Production view** (`model.json` → `production`, `mainnet_production`). Every mainnet request is a new block, so leaf classes and most fold classes miss. The host class build (`plan_model` `miss_s`, 5.6 s central at p50) then sits on the critical path, and none of these levers touches it. The plan's search is warm, and so was the original headline.

| central | baseline | plan best | + central-best set |
|---|---:|---:|---:|
| p50 | 29.66 s | 16.98 s (−43%) | 14.08 s (−53%) |
| p95 | 49.52 s | 28.09 s | 22.95 s (−54%) |
| mainnet-weighted mean | 30.2 s | 17.2 s | 14.2 s |

Pessimistic −45%, optimistic −61%. For production, the class build (canonical classes or a GPU planner) matters as much as any lever here. STACK may shrink the class build too, if the build scales with leaf cells. That is not modelled.

**Is this the ×0.67?** No. Kernel GPU-s at p50 goes 16.12 → 11.59, which is **×0.72**. The warm cut is 58% in the central case, about 2 points short of 60% in every metric.
- **The two levers that carry it are STACK (−5.6) and BLAKE3R (−2.8).** D2REV adds about 0.5 s on top. NGKRFULL adds 0.05 s once STACK is on, so it is not worth a new native profile for this alone [R1]. Both are work reductions: fewer opened values and hashes, and fewer rounds.
- Neither touches a near-bandwidth kernel.
- The pessimistic case stays at −47% on 2 GPUs and needs 4 GPUs (−64%).

---

## 5. Gates before any of this is believed (measure, do not extrapolate)

1. **STACK census gate (CPU only, a day).**
   - Dump per-component (columns, log rows) for one CPU segment and one truth proof of each family.
   - Compute the exact opened width for stacking thresholds 2^18, 2^19 and 2^20.
   - Run the leaf `CG.measure` shape-only cost on a re-shaped section; the `verifier-cost.json` tooling on `codex/rv64-m9-outer-gkr` already pins shape-only = honest.
   - **Kill** if the leaf cell factor is above ×0.65 at threshold 2^19.
2. **STACK prover gate (dev pod, ≤ 15-minute holds).** Run the s-layer lift kernel and multi-point DEEP on a 2^16 × 2^6 stack. **Kill** if native GPU-s exceeds ×1.06.
3. **BLAKE3R gate.**
   - Build the in-circuit BLAKE3 compression on the existing G-gate component. Only the message schedule, rounds and flags change.
   - Measure committed cells per compression. **Kill** if it is above 0.80× Blake2s's 22.7 k.
   - Native BLAKE3 Merkle leaf kernel on the dev 5090: **kill** if it is slower than Blake2s at log 22–24.
4. **D2REV re-decision.** Only after gates 1–2 pass. Run the A/B on the composed stack (b2 q108 vs b4 q54).
5. **GRIND26.** Profile-only. [R1] The as-built device grind measures about 1.1 G/s, and break-even is 16.7 G/s per GPU. **Kill** unless an optimised Blake2s grind kernel measures ≥ 17 G/s at 26 bits on the dev 5090, quiet-gated with independent nonces per job.
6. **NGKRFULL.** Gated like the outer GKR was: standalone GKR prover ns/fact at the INTER shapes.

## 6. Integration after GPU-native lands

All flags are new and default off. Nothing here edits `rv64/jobs/` or gn-* files.
1. Merge `codex/rv64-m9-plan` first; this model loads `scripts/rv64_m9/plan_model.py` as a sibling. Then merge this branch: scripts, tests and receipts only.
2. Re-run `plan_model.py` and `frontier_gap_model.py` on the GPU-native bench15. Recalibrate `k_m8`, busy, and the leaf/fold split from the new census, plus the truth-split roster from p-truth-split.
3. Run gates 1 and 3; they need CPU only and can run while GPU-native settles.
4. On pass, implement in this order:
   - `STWO_RV64_M9_BLAKE3_RECURSION` (hash profile + in-circuit component, starting from the existing BLAKE3 suite in §3.2);
   - `STWO_RV64_M9_STACKED_COLUMNS` (native commitment layout + leaf verifier);
   - then the D2REV A/B;
   - then `STWO_RV64_M9_NATIVE_GKR_FULL`, only if its marginal gain stays above noise after STACK;
   - `STWO_RV64_M9_GRIND26` only after gate 5 passes. Registry entries: `d2_native_b4_q51_p26_fold4`, `r1_outer_b2_q102_p26_fold4`. A p26 outer candidate, `m3_outer_b4_q51_p26_fold4`, already exists in `rv64-m7-profiles.md` §1 [R1].
   - **[R1] Integration costs the model leaves out:**
     - STACK changes every leaf class, so the `FANIN_SAME` fan-in ratios, measured on today's leaf shape, must be re-measured.
     - Recursion trace heights are powers of two, so a ×0.44 cell cut lands as ×0.5 or ×1.0 per leaf until fan-in is re-packed.
     - Every new profile needs a VK, a receiver and a tamper corpus.

   Each gets its own soundness note in `rv64-m7-profiles.md` style, a fresh-receiver test and a tamper corpus.
5. Fold the frontier comparison into M10 planning: the MLE row is the bound for a multilinear native rewrite.

## 7. Could not determine

- Zilkworm (Airbender v3) cycles per gas and its block mix. Without them, per-gas Airbender figures stay [E].
- Per-cluster p99 and soundcalc bits on ethproofs: the page shows none.
- SP1 Twin Peaks internals: no clone.
- ZisK recursive2 node sizes at production. `recursive_n_bits` is setup-dependent.
- Our per-component (columns, height) table. The census gives per-tree totals only, so the STACK factor is a range until gate 1.

## 8. Review 1 (2026-11-07): findings and fixes

All fixes are on this branch; the tests went from 6/6 to 8/8.

1. **GRIND26 used a grind rate about 23× too high.** It assumed 25 G/s; the as-built rate is about 1.1 G/s [M diag, `pipeline-diagnostic-1.json`].
   - The serial grind on the tail (last leaf plus one fold per level) was also spread over 2 GPUs instead of being charged on the wall.
   - Fixed: rate (0.8, 1.1, 13.4) G/s and `grind_tail_s`. GRIND26 alone is now +4.5 GPU-s, and it left the central best set. Break-even is 16.7 G/s.
2. **The headline was warm only.** "Mainnet-weighted mean 8.1 s" assumed class hits, but mainnet requests are always new blocks.
   - Added the `production` view: central best p50 14.1 s (−53%), mainnet mean 14.2 s.
   - The warm numbers stay, labelled as warm.
3. **NGKRFULL under STACK was free.** It had no leaf-side GKR verifier cost. Added `ngkrf_verify` (0.06 / 0.04 / 0.02 of today's leaf). Its marginal gain in the best set is now 0.05 s.
4. **Ideal stacked width.** It was 136; it is 151, because composition is 16 full-height columns. Ideal STACK factor 0.026; the central 0.15 is unchanged.
5. **Airbender ×7.8 is opcode-circuits only.** It excludes delegation (Keccak/bigint/Blake), init/teardown and multiplicities, while ours and ZisK's include Keccak. Now stated as an upper bound, about ×4 like-for-like [E].
6. **"Today 38 s"** is extrapolated beyond the largest measured block (57.8 M instr) and is labelled [E].
7. **BLAKE3 prior art** in `src/core/{channel,vcs,crypto}/blake3*` and `blake3-migration.md` is now cited for gate 3.

Re-checked and left unchanged:
- the [M] census reproduces byte-identically from the producer log (sha256 `c4bb809a…`);
- the 5,833 / 2^16.2 / 7,409-at-2^12 figures;
- 0.852 / 0.681 hash shares;
- 23,944 bits/instr and ZisK 23,527;
- Airbender widths 48/58/55/40/46/50 [code];
- the ethproofs rows (re-fetched 2026-11-07);
- the 128-bit conjectured arithmetic for q51/q102 + p26 and the OM31 algebraic margin of about 181 bits (`rv64-m7-profiles.md` §2), so STACK's ≤ 15-bit OODS cost leaves more than 40 bits of headroom.

Still open:
- STACK's interaction with WITNESS/OGKR_ENG, which is multiplicative and overlaps by less than 0.1 GPU-s [E];
- leaf trace power-of-two quantisation.
