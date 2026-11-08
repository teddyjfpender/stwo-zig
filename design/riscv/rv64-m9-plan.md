# RV64 M9 plan: gas-weighted targets and the >60% cut budget (2×RTX 5090, then 4×)

Status: plan of record, revision 4, 2026-11-07. It folds in the four reviewed wave-2 prep streams (outer GKR, streaming commit, witness without the DAG, GPU capture replay; §3.2) on top of the wave-1 streams (§3.1) and re-runs the budget. Every number is regenerated from `scripts/rv64_m9/plan_model.py`. Written **in parallel with** the GPU-native landing (workflow round 3, `codex/rv64-m8-gpu`, `codex/rv64-m8-gn-*`); it touches no code those streams own.
Branch `codex/rv64-m9-plan`, cut from `codex/rv64-m7-integrate @ 95e3d7e15` (this branch only adds files).

Labels: **[M]** measured, with a receipt; **[D]** arithmetic on measured numbers; **[E]** estimate.

Model: `python3 -I scripts/rv64_m9/plan_model.py --gas-sample <gas_sample.json> --json vectors/reports/rv64-m9-prep/m9-plan/model.json` (tests: `python3 -I scripts/tests/test_rv64_m9_plan_model.py`, 16/16). Receipt: `vectors/reports/rv64-m9-prep/m9-plan/model.json`. The raw gas sample stays out of git (sha256 in the receipt README).

---

## 0. TL;DR

1. **Targets are unchanged** (gas-weighted, ≥ 60% below the post-M8 baseline [E]): **p50 ≤ 7.9 s** (from 19.7), **p95 ≤ 13.2 s** (from 32.9), **15-block basket ≤ 118 s** (from 294) on 2×5090.
2. **All four wave-2 levers came in far below their rev-3 factors.** Each one is now measured or derived:
   - **Outer GKR as built is a loss**: recursion GPU-s ×1.07 on the post-M8 tree and ×1.13 on the fan-in tree [D/E]. At p50 that is +1.0 GPU-s, against the −6.0 assumed. The ×0.57 was a cell factor. Only an engineered 0.25 ns/fact kernel with a fused binding pass gains (×0.81, −2.7 GPU-s) [E]. It is gated on a standalone microbenchmark and on GKR memory (16.6 GB per 2²³ fold [M]).
   - **Streaming commit is worth ×0.955 on FFT + Merkle, not ×0.70.** The fused LDE → leaf kernel loses ×1.03–1.61 at log 22–24 [M]. Aligned 32-column chunks save −0.11 GPU-s [D/E]. Partial trees save memory, not time [M]. At p50 that is −0.6 GPU-s, against −3.9.
   - **Witness without the DAG is ×0.70, not ×0.2**, and only on class hits. Measured: leaf ×0.513, fold ×0.760 [M]. At p50 that is −0.8 GPU-s, against −2.2, and about 0 in production.
   - **For GPU capture the floor is the serial first pass, not 160 MIPS.** On 26235168 the first pass runs at 62.8 MIPS because curve services take 64% of it [M]. Fixing the service arithmetic and porting narrow capture recovers the lever (−0.6 s at p50). Replay alone, the prototype that exists, gives −0.4 s at p50 and 0 at p95.
3. **No 2-GPU combination reaches 60%, in any scenario.** The best set is #1–#9 (§4.1), with engineered outer GKR: **p50 11.0 s (−44%), p95 18.8 s (−43%), basket 167 s (−43%)** central [E]. The pessimistic case reaches −39% and the optimistic −55%. Closing to 60% on 2 GPUs needs a further **×0.67 on all remaining kernel GPU-s** (p50 16.1 → 10.8 GPU-s) at busy 0.85 [D on E]. No lever on the table provides that. Busy 0.95 alone only reaches −48%.
4. **60% needs 4×5090 (M10).**
   - With #1–#10, central: **p50 7.0 s (−64%), p95 11.4 s (−65%), basket 107 s (−64%)** [E]. Pessimistic: −59 / −61 / −59%.
   - Without engineered outer GKR, 4 GPUs reach −60.2 / −61.6 / −59.6%: the basket misses.
   - So the 4-GPU 60% case rests on the outer-GKR microbenchmark.
5. **Order after GPU-native and the cleanup** (§5):
   - wave 0, CPU: service-arithmetic fix;
   - wave 1, byte-identical: IO, D2D, aligned stream plan, witness rowpar on class hits, P1 → occupancy (the largest at −2.1 s);
   - wave 2, profiles: k-leaf fan-in with a fold-arity guard, native GKR v2, production miss path;
   - wave 3: GPU narrow-capture port, then outer GKR only if the kernel bench shows ≤ 0.3 ns/fact;
   - M10: 4 GPUs.
   - **Decision for the owner:** either take 60% as an M10 (4-GPU) target, or fund a new 2-GPU kernel-efficiency lever worth ×0.67.
6. **Production is still the gap.** With the best 2-GPU set, a new block per request costs p50 **17.0 s** against the bench 11.0 s (miss +5.6 s serial upper bound [E]). Rowpar gives nothing on a class miss. E8 and a miss path remain prerequisites.

---

## 1. Targets

### 1.1 Mainnet gas and the basket [M/D]

Source: `gas_sample.json` (2,897 distinct blocks, 26,019,159–26,236,159, 2026-09-20 to 10-20, about 60 M limit).

| p5 | p10 | p25 | **p50** | p75 | p90 | **p95** | p99 | mean |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 8.3 M | 15.8 M | 23.4 M | **29.1 M** | 37.2 M | 47.1 M | **55.8 M** | 60.0 M | 30.4 M |

- The basket over-weights big blocks: 5 of 15 blocks are above 40 M and hold 62% of basket gas; on mainnet those are 19% of blocks and 31% of gas.
- It also over-weights tiny ones: 5 of 15 are at or below p8. Only 26235168 (p50) lies between p21 and p79.
- Mainnet weights by nearest gas: 26235168 0.33, 24697073 0.20, 25229955 0.19, 24628590 0.06, all others ≤ 0.04 [D].
- Percentiles: 24628607 p4, 25229955 p79, 26235159 p96.

### 1.2 Targets (warm proving, Ethproofs boundary; request = proving + about 0.01 s [M])

| metric | post-M8 baseline [E, central (pess–opt)] | **M9 target, 2×5090** | best 2-GPU set #1–#9 [E] | 4×5090 #1–#10 [E] |
|---|---:|---:|---:|---:|
| **p50** (29.1 M gas, 93 M instr, 23 seg) | 19.7 s (23.8–17.4) | **≤ 7.9 s** | 11.0 s (−44%) | 7.0 s (−64%) |
| p50 proxy **26235168** (113 M instr, 28 seg) | 23.3 s | ≤ 9.3 s | 13.1 s | 8.2 s |
| **p95** (55.8 M gas, 178 M instr, 43 seg) | 32.9 s (41.1–28.9) | **≤ 13.2 s** | 18.8 s (−43%) | 11.4 s (−65%) |
| p95 proxy 26235159 (205 M instr, 49 seg) | 37.9 s | ≤ 15.2 s | 21.5 s | 12.9 s |
| **15-block total** | 294 s (361–259) | **≤ 118 s** | 167 s (−43%) | 107 s (−64%) |
| mainnet-weighted mean | 20.1 s | ≤ 8.0 s | 11.3 s | 7.2 s |
| production p50 (new block per request) | 29.7 s | ≤ 8.7 s | 17.0 s (15.4 with canonical leaves) | — |
| 24628607 (continuity) | 8.5 s | ≤ 3.4 s | 4.7 s | 3.6 s |

### 1.3 Benchmark set

- **3+3: 24628607 (continuity) + 26235168 (mainnet p50).** Scale probe: 25229955 (p79). Cheaper probe: 24697073 (p21).
- **Prerequisite:** all three middle blocks are refused today by `OneTruthPerFamilySourceCapacity` [M, bench15-1]. Round-3 p-truth-split has to land first, and it changes the truth roster, so recalibrate the shapes afterwards.
- Allow 26235168 in the 3+3 runner and the owner-rule allowlist.
- Every bench also reports the mainnet-weighted basket mean Σ wᵢ·tᵢ (weights from §1.1).

---

## 2. Baseline (unchanged by the streams; still [E] until GPU-native bench15)

- **bench15-1 fits [D]** (6 proved blocks, `codex/rv64-m8-gpu:vectors/reports/rv64-m8-20261106/bench15/`):
  - kernel GPU-s = 1.46 + 0.284·Minstr (R² 0.980);
  - native = 0.119 GPU-s/Minstr (K607 = 8.333, T2 off);
  - **recursion = 0.046 + 0.306·nodes** (R² 0.954).
  - The fewer-leaves cell model reproduces this independently: node wall 0.455 ns/cell, kernel 0.262 ns/cell + 0.118 GPU-s/Minstr native [D].
- **Kernel families on 24628607 [M]** (`opt-combined/ab8-kernels.json`): FFT 2.98 GPU-s (35%), Merkle 1.52 (18%: mixed_leaf 1.250, child_layer 0.180, layer 0.080, fri_leaf 0.010), `chain_run` 1.00 (12%), `channel_mix` 0.078 over 363 calls.
- **Request model (`plan_model.model`)**:
  - wall = fixed + max(head + S1/(G·busy), capture + S1/seg/busy) + (K − S1 − tail)/(G·busy) + IO + D2D + tail;
  - Stage 1 is 37% of native work [M, M8 §5];
  - central busy is 0.72, the capture fit uses T1 (default-off: promoting it is a cleanup prerequisite);
  - D2 and native-GKR factors apply to leaves only.
- Post-M8 central kernel GPU-s: p50 24.5 (native 10.5, recursion 14.0); p95 43.5 (20.2 / 23.3).
- **Production miss [E]:** on a new block, every leaf class misses and so do 97% of fold classes (exact outer shape, 204/210 [D/E, canon-leaf review]). The host builds classes at 0.84 CPU-s each, 4-way parallel.
  - The model charges this serially (an upper bound): +10.0 s at p50 and +16.7 s at p95 on the baseline.
  - The earlier revision charged leaves only (7.4 / 12.6 s).

---

## 3. What the prep streams changed

### 3.1 Wave 1 (rev 3, unchanged)

| lever | stream result (reviewed) | in the model |
|---|---|---|
| packed ingress | 4.48 ms decode per 1.03 GB node [M]; 0.455 vs 15.86 GB per request [D]; 46% of the link exposed [D] | link 0.31 s/GPU × 0.46, residual ×0.03, +0.004 GPU-s per leaf |
| k-leaf fan-in | recursion cells ×0.76–0.86 [D/E]; pair leaf 30.7 GB against the 30.06 GB gate: needs P1 [E] | per-block ratios and tree shapes (`FANIN_SAME`) |
| canonical leaves R=4 | held-out native padding tax ×1.55 [D]; 79% of folds still miss [D/E] | ×1.55 (2.07…1.22); off the order |
| Poseidon2 leaves | P2/Blake GPU cost ×9.95 [M], serial transcript ×23.9 [M] | three scenarios; off the order |

### 3.2 Wave 2 (this revision)

| lever | rev 3 assumption | stream result (reviewed) | now in the model (pess, central, opt) |
|---|---|---|---|
| **outer GKR** (DW-R1) | recursion ×0.57 (0.65…0.50) [E] | ×0.57 is the **cell** factor: cells ×0.562–0.568 on the post-M8 tree and ×0.575–0.630 on the fan-in tree [D]. In GPU-s: committed cells cost 0.262 ± 0.053 ns [D], while the GKR prover costs 0.82 ns/fact with the MAIN projection [D] (0.575 on precomputed inputs [M]). Break-even is 0.55–0.68 ns/fact [D]. **Recursion GPU-s ×1.07 on the post-M8 tree** (LOO ×1.04–1.17, 95% CI ×0.92–1.63), **×1.13 on the fan-in tree** [D/E]. A free GKR still leaves ×0.65 [D], so ×0.57 is unreachable. The v2 binding pass is not priced in the 0.82 ns; with it, ×1.19–1.28 [E]. Workspace 64.25 B/fact = 16.6 GB at a 2²³ fold [M]. Soundness 206–209 bits against 151 [D]. | `ogkr_alone` (1.28, 1.07, 0.90), `ogkr_fanin` (1.35, 1.13, 0.95): **off the order**. **`OGKR_ENG`** (0.90, 0.81, 0.78) [E], with a 0.25 ns/fact kernel and a fused binding pass, takes its slot as #8. It is gated (§5). |
| **streaming commit** | ×0.70 (0.80…0.60) on FFT + Merkle [E] | Parity 43/43, 0 mismatching words; chunk invariance 20 roots [M]. **Fused LDE → leaf loses at log 22–24** (×1.03–1.61; 24×304 ×1.27) and wins ×0.93–0.95 at log 20–21 [M]. Aligned 32-column chunks: 76.2 vs 83.8 ms at 24×304 [M], −0.11 GPU-s calibrated to the T6 census [D/E]. Partial trees: layers 1.03 → 0.06 ms per log-24 tree but net ×1.00–1.24 with the final call, so memory only (1 GiB → 1 MiB) [M/D]. Recursion `outer_trace_commit` runs at 2²⁶ words, 164.8 vs 76.2 ms aligned c32 [M]; its share is unmeasured. | `stream` (0.975, 0.955, 0.90) [E]: opt = recursion chunk fix pays −0.41 GPU-s plus the fused tail at log ≤ 21 |
| **witness without the DAG** (rowpar) | chain share residual ×0.2 (0.4…0.1) [E] | Exact (0 mismatched vars) on 2 recorded real nodes [M]. **Leaf ×0.513** (41.13 → 21.08 ms), **fold ×0.760** (strands off) [M]. The Blake family is ×0.21 [D]; a serial QM31 accumulation tail is 54–62% of what remains [M]. Production whole assignment ×0.70 (×0.60–0.80) [E, calibrated on the M6 census]. Planner 0.36–0.87 s CPU per node [M]: **class hits only** (on a miss, run the DAG and plan off the critical path). `srec` costs about 0.38 GB per production leaf [D/E]. | `wit` (0.80, 0.70, 0.55) [E]: opt = tail on `chain_run` hybrid (×0.55, not prototyped). In production only fold hits (1 − `fold_miss`) get it. |
| **GPU capture replay** | `cap = head + Minstr/160 MIPS + 0.2` [E] | Replay kernel byte-identical: 24628607 7/7, 26235159 49/49 segments; op corpus 106,496 cases, all 69 ops; 5 fault classes caught [M]. 7.3 GIPS for the whole 607 block, **46–83× the serial first pass** [M/D]. But **the floor is the serial seeded first pass**: basket 105 MIPS, **26235168 at 62.8 MIPS (curve services 1.26 of 1.95 s)** [M]. The walk is 23% of capture CPU [D/E]; replay alone, net of the 48 B/step tape read-back, is worth about a quarter of the lever [E]. | `GPUCAP` = full (replay + narrow capture + ledger on GPU + service fix): `cap = head + first_pass_fixed(block) × (1.15, 1.0, 0.90) + 0.2`, per-block [M] with curve calls at 1 µs [E]; synthetic blocks 0.033 + 5.93 ms/Minstr = 169 MIPS marginal [D]. **`REPLAY`** (prototype only): capture CPU × (1 − (0.111, 0.204, 0.287)) [D/E]. The stream script had the pess/opt walk shares swapped; corrected here. |

---

## 4. The budget (2×5090, then 4×)

"Alone" applies one lever to the post-M8 baseline; "cumulative" applies them in the §5 order. Central values with (pess…opt).

### 4.1 Lever table: p50 (29.1 M gas) and p95 (55.8 M gas) [E]

| # | lever (flag) | basis | p50 ΔGPU-s alone | p50 Δwall alone | p50 cumulative (cut) | p95 ΔGPU-s alone | p95 Δwall alone | p95 cumulative (cut) |
|---|---|---|---:|---:|---:|---:|---:|---:|
| — | **post-M8 baseline** | §2 | 24.5 GPU-s | 19.7 s | 19.7 (23.8…17.4) | 43.5 GPU-s | 32.9 s | 32.9 (41.1…28.9) |
| 1 | packed ingress + copy stream (`STWO_RV64_M9_CLASS_PACKED_INGRESS`) | 4.48 ms/node [M]; 46% exposed [D] | +0.1 | −0.2 | 19.4 (1%) | +0.2 | −0.4 | 32.4 (1%) |
| 2 | in-place coset / D2D (`_D2D_INPLACE`) | ≤ 0.11 s/GPU on 607 [D] | 0 | −0.3 | 19.1 (3%) | 0 | −0.5 | 31.9 (3%) |
| 3 | streaming commit, aligned plan (`_STREAM_COMMIT`) | ×0.955 on FFT + Merkle [E from M] | −0.6 | −0.4 | 18.8 (4%) | −1.0 | −0.7 | 31.2 (5%) |
| 4 | witness rowpar, class hits (`_WITNESS_ROWPAR`) | ×0.70 of the chain share [E from M] | −0.8 | −0.6 | 18.2 (7%) | −1.4 | −1.0 | 30.2 (8%) |
| 5 | **occupancy**: class graphs, 2 jobs/GPU (`_CLASS_GRAPHS`; needs P1) | busy 0.72 → 0.85 [E] | 0 | −2.1 | 16.2 (18%) | 0 | −3.9 | 26.7 (19%) |
| 6 | **k-leaf fan-in** (`_LEAF_FANIN=4`, `_POLICY=same`; needs P1) | cells ×0.76–0.86 [D] | −3.4 | −2.3 | 14.6 (26%) | −5.6 | −3.8 | 24.0 (27%) |
| 7 | native GKR v2 (`_NATIVE_GKR_V2`) | native ×0.826, leaf ×0.936 [D] | −2.5 | −1.3 | 13.6 (31%) | −4.7 | −2.5 | 22.2 (32%) |
| 8 | **outer GKR, engineered** (`_OUTER_GKR`; gated on ≤ 0.3 ns/fact bench + GKR memory) | ×0.81 recursion GPU-s [E] | −2.7 | −2.0 | 12.4 (37%) | −4.4 | −3.2 | 20.3 (38%) |
| 9 | **GPU capture, full** (`_GPU_REPLAY` + narrow-capture port + service fix) | first pass floor, services fixed [M/E] | 0 | −0.6 (bites late) | **11.0 (44%)** (14.6…8.8) | 0 | 0 (bites late) | **18.8 (43%)** (24.7…15.1) |
| 10 | 4-GPU placement (M10) | 92% scaling [E] | 0 | −6.2 | **7.0 (64%)** (9.9…5.4) | 0 | −11.2 | **11.4 (65%)** (16.0…8.7) |
| — | *off the order:* outer GKR **as built** | ×1.07 / ×1.13 fan-in [D/E] | +1.0 | +0.7 | +2.1 instead of #8 | +1.6 | +1.2 | +3.3 instead of #8 |
| — | *off the order:* replay only (the prototype) | capture CPU × (1 − 0.204) [D/E] | 0 | −0.4 | +1.0 instead of #9 | 0 | 0 | +0.7 instead of #9 |
| — | *off the order:* Poseidon2 leaves (2-to-1 + ×0.6) | rev 3 §3 | +1.0 | 0.0 | +0.3 on top of #9 | +3.6 | +2.2 | +1.4 on top of #9 |
| — | *off the order:* revert D2 | native ÷1.4, leaf ÷0.55 [E] | +5.6 | +4.7 | loses | +8.9 | +7.6 | loses |
| — | *off the order:* canonical leaves R=4 | held-out tax ×1.55 [D] | +5.8 | +3.4 | loses (prod −1.5) | +11.1 | +7.7 | loses (prod −1.7) |

After #1–#9, kernel GPU-s falls 24.5 → 16.1 at p50 (−34%) and 43.5 → 29.0 at p95 (−33%). The p50 wall of 11.0 s splits into 2.2 s pre-seal, 7.1 s post-seal, 1.4 s tail and 0.3 s fixed. Post-seal kernel work at busy 0.85 is now the whole problem [E].

### 4.2 Basket total and proxies [E]

| step (cumulative) | 15-block total, central (pess…opt) | cut | 26235168 | 26235159 | 24628607 |
|---|---:|---:|---:|---:|---:|
| post-M8 baseline | 294 (361…259) | — | 23.3 | 37.9 | 8.5 |
| + IO, D2D | 286 | 3% | 22.6 | 36.8 | 8.3 |
| + streaming commit | 280 | 5% | 22.2 | 36.0 | 8.2 |
| + witness rowpar | 272 | 7% | 21.5 | 34.9 | 7.9 |
| + occupancy | 242 | 18% | 19.1 | 30.6 | 7.2 |
| + k-leaf fan-in | 220 | 25% | 17.1 | 27.2 | 6.9 |
| + native GKR v2 | 205 | 30% | 16.0 | 25.2 | 6.6 |
| + outer GKR, engineered | 187 | 36% | 14.5 | 23.0 | 6.0 |
| + GPU capture, full | **167 (219…133)** | **43%** | **13.1** | **21.5** | **4.7** |
| + 4 GPUs (M10) | **107 (149…82)** | **64%** | 8.2 | 12.9 | 3.6 |

### 4.3 Which combination reaches >60% [E]

The search is exhaustive over {streaming, witness, occupancy, k-leaf, native GKR, outer GKR as built or engineered, GPU capture full or replay only, Poseidon2, D2 revert}, with IO and D2D always on. A set passes only if it reaches ≥ 60% on the p50 block, the p95 block **and** the basket at once.

| case | 2×5090: sets reaching 60% | best 2-GPU set: p50 / p95 / basket | 4×5090: sets reaching 60% |
|---|---|---|---|
| **central** | **none** | #1–#9: −43.8 / −42.7 / −43.2% | **9 minimal sets**. All contain occupancy and full GPU capture; 7 contain engineered outer GKR and the other 2 Poseidon2 2-to-1 (also unbuilt). Best: {occupancy, k-leaf, native GKR, outer GKR eng, GPU capture} at −62.5 / −63.5 / −61.8%. The full #1–#10 reaches −64.3 / −65.3 / −63.6%. |
| pessimistic | none | #1–#9: −38.9 / −39.9 / −39.3% | none (#1–#10: −58.6 / −61.0 / −58.8%) |
| optimistic | none | #1–#9 + Poseidon2 + D2 revert: −55% | 28 minimal sets |

Per metric, central on 2 GPUs: the p50 block reaches −44% (11.0 s against the 7.9 s target), the p95 block −43% (18.8 against 13.2), and the basket −43% (167 against 118).

**What would close the 2-GPU gap** [D on E]:
- Every remaining kernel GPU-s (native and recursion) would have to fall a further **×0.67**: p50 16.1 → 10.8 GPU-s, about −5.3 GPU-s. Without engineered outer GKR the factor is ×0.60.
- Occupancy cannot do it: busy 0.90 gives −46%, busy 0.95 gives −48%.
- No lever reviewed so far is that size. FFT (35%) and Merkle (18%, near the HBM bound for the Blake2s leaves) are what is left to attack.

**What the search says:**
1. **The rev-3 −58% came from the optimistic factors of the four unmeasured levers.** Measured, the four alone are worth −0.9 s at p50 as built (streaming −0.4, witness −0.6, GPU capture −0.6, outer GKR +0.7), against −9.0 s in rev 3 (−2.4, −1.6, −0.6, −4.4).
2. **Occupancy, k-leaf fan-in and native GKR v2 now carry M9.** Together they cut −4.6 s cumulative at p50 (18.2 → 13.6), more than half of the set's −8.6 s. All three need P1 node memory or new profiles.
3. **Outer GKR is the 4-GPU swing lever.** As built it costs +0.7 s. Engineered it gains −2.0 s, and only with it does the 4-GPU basket clear 60% (−63.6% against −59.6%).
4. **Poseidon2 no longer loses alone, but it loses on top of the best set.** The central 2-to-1 + ×0.6 scenario is −0.3 s at p50 on #1–#7 + GPU capture (no outer GKR) and +0.3 s on #1–#9. It stays off the order.

---

## 5. Ordering after GPU-native lands and the cleanup pass

Rules (unchanged):
- Nothing lands on `codex/rv64-m7-integrate` before GPU-native is the default and the post-M8 cleanup is done.
- Every flag is new and default-off (`STWO_RV64_M9_*`).
- Wave 1 is byte-identical to the frozen D2 golden.
- Waves 2–3 are named profiles with fresh receivers and corpora.

| step | content | depends on | gate |
|---|---|---|---|
| 0 (cleanup) | T1 capture default; p-truth-split so all 15 blocks prove; landed bench15 → refit `plan_model.py`; 3+3 = 607 + 26235168; **E8 different-blocks run**; **CPU service-arithmetic fix** (Montgomery 6×64 limbs in `candidate_curves.zig`; 26235168 first pass 1.95 → about 0.8 s [E]) | GPU-native default | refit within 5 points of §4.2; service fix: `captured_values_sha256`/`advice_all_sha256` identical on the basket |
| 1a | packed ingress → D2D in place | `ClassCache`, `MemoryPlan` | byte identity |
| 1b | **aligned stream plan** (no new kernel): calls cut at absorbed % 16, banks 8 + (absorbed & 15), chunk 32 columns; **recursion `outer_trace_commit` 2²⁶ → aligned c32** first (its share is the unmeasured upside). Fused tail only at log ≤ 21. | PCS enqueue | node-dump root parity; kernel census `mixed_leaf` −0.1 GPU-s or more |
| 1c | **witness rowpar on class hits** (`ClassCache.Template` holds plan + `srec`; DAG on a miss; planner off the critical path) | node plans in `ClassCache` | assignment dump 0 mismatches; `chain_run` GPU-s ≤ 0.75× flag-off on 24628607 |
| 1d | **P1 node memory ≤ 11–13 GB → occupancy** (count `srec` 0.38 GB/leaf and GKR scratch) | all of GPU-native | busy ≥ 0.85 measured |
| 2a | **k-leaf fan-in** + fold-arity guard (3 children where 4 cross 2²³ blake) | P1 | ≤ 13 GB per node post-P1; −18% cells on 607 |
| 2b | native GKR v2 in production | native Stage 1 device channel | fresh receivers |
| 2c | **production miss path**: overlap class builds with capture; class-stable outer shapes; rowpar plans built off the critical path | E8 | production p50 ≤ bench p50 + 10% |
| 3a | **GPU narrow-capture port** (`Prepared`, ROM counts, dedup, ledger phase 1, `Batch` aggregates) on top of the replay kernel. Replay alone is not integrated. | T1, GPU-native `Feed`, service fix | T10DIGEST parity; pre-seal ≤ 2 s at p50 |
| 3b | **outer GKR**, three gates in order: (i) standalone 5090 bench of the fused MAIN-projection GKR on a D2 leaf class (137.4 M facts) and a 2²³ fold (257.9 M), killed above 0.45 ns/fact and scheduled at ≤ 0.3 including the binding pass; (ii) chunked GKR memory under global admission; (iii) a time-based hybrid rule (only blake_g_gate and xor12 go to GKR) | recursion jobs, P1 | paired request time, never cells |
| M10 | 4-GPU placement, now **required** for 60%; Poseidon2 only for node memory and compression; canonical-leaf envelope redesign | — | p50 ≤ 7.9 s, p95 ≤ 13.2 s, basket ≤ 118 s on 4×5090 |

---

## 6. Branches holding each prototype

| prototype | branch @ head | key files (new) | state |
|---|---|---|---|
| plan + model | `codex/rv64-m9-plan` | this doc, `scripts/rv64_m9/plan_model.py`, `scripts/tests/test_rv64_m9_plan_model.py` | 16/16 tests |
| outer GKR | `codex/rv64-m9-outer-gkr` @ a45530dc7 | `riscv_cpu/outer_gkr/m9_node{,_test}.zig`, `rv64_m9_outer_gkr_tool_main.zig`, `scripts/rv64_m9/outer_gkr_{factor,review}.py`; doc `rv64-m9-outer-gkr.md` | CPU node round on the real D2 roster up to 1/8 scale [M]; Zig 6/6, Python 4/4; no GPU kernel bench yet |
| streaming commit | `codex/rv64-m9-stream-commit` @ 42ce18195 | `native/commitment/stream_commit.{cuh,cu}`, `commitment/bench/stream_commit_bench.cu`; doc `rv64-m9-stream-commit.md` | 43/43 parity [M]; not called by the prover |
| witness rowpar | `codex/rv64-m9-witness-rowpar` @ 4459242f1 | `native/rv64/m9_witness_rowpar.cuh`, `riscv_cuda/rv64/m9_witness_rowpar/plan{,_main,_test}.zig`, `tools/rv64-m9-witness-rowpar/*`; README in receipts | exact on 2 recorded nodes [M]; production leaf dump not yet run |
| GPU capture replay | `codex/rv64-m9-gpu-replay` @ 7d9850bab | `native/rv64/m9_gpu_replay.cu`, `riscv_cpu/rv64_m9_gpu_replay{,_dump_main,_opcorpus}.zig`, `scripts/rv64_m9/gpu_replay_model.py`; doc `rv64-m9-gpu-replay.md` | byte-identical on 2 blocks + op corpus [M]; narrow capture not ported |
| packed ingress | `codex/rv64-m9-packed-ingress` @ 805d1a105 | `native/rv64/m9_class_unpack.{h,cu}`, `rv64/m9_class_packed_ingress.zig` | parity on 2 GPUs [M] |
| k-leaf fan-in | `codex/rv64-m9-fewer-leaves` @ a056cee67 | `om31_native/leaf_fanin.zig`, `scripts/rv64_m9_leaf_fanin_model.py` | planner only |
| canonical leaf catalog | `codex/rv64-m9-canon-leaf` @ 64a2cb991 | `rv64_recursion/canon_leaf*.zig` | 10 tests; shelved as built |
| Poseidon2 leaves | `codex/rv64-m9-poseidon2-leaves` @ 37e581cfc | `vcs_lifted/poseidon2_m31_mixed_leaf.zig`, `tests/cuda/rv64/m9_poseidon2/*.cu` | 336/336 GPU parity; off the order |
| IO streaming design | `codex/rv64-m9-io-design` | `rv64-m9-io-streaming.md` | design (E8 defined there) |

Still not prototyped: occupancy/P1 (now the largest single 2-GPU lever), GPU narrow capture, the engineered outer-GKR kernel, and 4-GPU placement.

---

## 7. Open risks

1. **2×5090 at 60% is out of reach on the identified levers.** The best central case is −43% and the optimistic −55%. The owner must either move the 60% bar to M10 (4 GPUs) or fund a new ×0.67 kernel-efficiency lever.
2. **The baseline is [E].** Every cut is relative to a modelled post-M8 baseline calibrated on 6 small blocks; p95 extrapolates. The outer-GKR verdict itself sits inside this fit's error (r_k ±20%).
3. **The 4-GPU 60% case hangs on engineered outer GKR.** Without it the basket reaches −59.6%. The kernel does not exist; 0.25 ns/fact is 3.3× faster than today's 0.82. Its memory (16.6 GB per 2²³ fold, 30.6 GB where fan-in pushes blake_g to 2²⁴) breaks P1 unless GKR is chunked.
4. **P1 memory gates occupancy, k-leaf and outer GKR.** Rowpar's `srec` (about 0.38 GB per leaf) and GKR scratch now also count against the 11–13 GB per-node budget.
5. **Production miss.** It adds +5.6 s at p50 even on the best set, and rowpar gives nothing on a miss. Without E8 and a miss path, production p50 is 17.0 s [E].
6. **Unmeasured upsides.** The recursion streams' 2²⁶ commit chunk (−0.41 GPU-s if their share is large) and the rowpar tail hybrid (×0.55) are opt-case only.
7. **GPU capture needs the narrow-capture port and the service fix.** Replay alone is −0.4 s at p50 and 0 at p95. The replay kernel is a second engine implementation; it is protected only by parity tests and runtime chunk-end checks (fails closed to the CPU walk).
8. **Soundness work per profile** (unchanged): k-leaf, native GKR v2, outer GKR (206–209 bits [D]) and GPU capture all need notes, fresh receivers and tamper corpora. Rowpar and the stream plan are proof-neutral: a wrong witness only causes a rejected proof.

---

## 8. Integration steps after GPU-native lands

1. Rebase `codex/rv64-m9-plan` on integrate (adds files only).
2. Cleanup step 0 (§5): refit `RFIT`, `KFIT`, `k_m8`, `busy`, `head`, `STAGE1_FRAC`, `IO_LINK_607_POST_M8`, `FANIN_SAME` and `FIRST_PASS` (after the service fix); regenerate `model.json` and §4.
3. Run E8; set `fold_miss` and `miss_par`.
4. Land waves 1–3 one flag at a time. After each wave, run a 3+3 A/B on 607 + 26235168 and bench15, and replace each [E] triple with the measured factor: `stream` from the bench15 kernel census, `wit` from a production leaf dump, `ogkr_eng` from the standalone GKR bench, `cap_fp_spread` from a quiet-host A/B.
5. Re-score §4.3 and take the 2-GPU-vs-M10 decision (§7.1) on measured numbers.

---

## 9. Sources

- Gas sample `gas_sample.json` (out of git); basket `vectors/reports/rv64-cuda-real-segment-20261103/basket-input-readiness.json`, `vectors/riscv/rv64/m3-basket/summary.json`.
- bench15-1 and kernel census: `codex/rv64-m8-gpu:vectors/reports/rv64-m8-20261106/{bench15,opt-combined}/`.
- Wave-2 receipts under `vectors/reports/rv64-m9-prep/` on their branches (§6):
  - `m9-outer-gkr/{factor,review,gates,verifier-cost}.json`;
  - `stream-commit/{summary.json,review/}`;
  - `witness-rowpar/README.md` and `review-residual-model.jsonl`;
  - `m9-gpu-replay/{first_pass_basket,model}.json` (`FIRST_PASS` in the model is copied from it).
- Wave-1 receipts: `vectors/reports/rv64-m9-prep/{packed-ingress,m9-fewer-leaves,canon-leaf,m9-poseidon2-leaves}/`.
- `rv64-4gpu-realtime.md`, `rv64-frontier-gpu-delta.md` (`codex/rv64-4gpu-realtime-design`); `rv64-m8-gpu-native.md` (`codex/rv64-m8-gpu`); `rv64-m9-io-streaming.md` (`codex/rv64-m9-io-design`).

## 10. Revision history

- **r1** (6064251e6): first budget; claimed −61%.
- **r2** (fba033dfe, review): per-node recursion fit, leaf-only D2/GKR factors, integration costs. M9 −56%, −62 to −64% with GPU capture.
- **r3** (4caa4dc29, wave 1): fan-in replaces truth batching; Poseidon2 and canonical leaves off the order. Best 2-GPU set −58/−59%; 4 GPUs −73 to −75%.
- **r4** (this revision, wave 2): outer GKR as built ×1.07/×1.13 (off the order; the engineered variant is gated); streaming ×0.955; witness ×0.70 on class hits; GPU capture bounded by the serial first pass, with replay alone as a separate lever. Result: **no 2-GPU set reaches 60% in any scenario (best −43% central); 4 GPUs −64/−65/−64% central, and only with engineered outer GKR.**
