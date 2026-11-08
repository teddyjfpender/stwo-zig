# RV64 M9 stream m9-proof-params: PCS/FRI parameters per layer at equal security

Status: prep stream, 2026-11-07. Branch `codex/rv64-m9-proof-params`, cut from `codex/rv64-m7-integrate @ 95e3d7e15`. It ran in parallel with the GPU-native landing and touches nothing under `rv64/jobs/`. Every change is default-off.

Labels: **[M]** measured, with a receipt; **[D]** arithmetic on measured numbers; **[E]** estimate. Receipts are in `vectors/reports/rv64-m9-prep/m9-proof-params/`.

Reproduce:
- `python3 -I scripts/rv64_m9/proof_params.py --json …/model.json`
- `python3 -I scripts/rv64_m9/plan_model.py --gas-sample gas_sample.json --json …/plan-model.json`
- tests: `scripts/tests/test_rv64_m9_proof_params.py` (8/8) and `test_rv64_m9_plan_model.py` (16/16).

## 0. TL;DR

1. **Proof parameters cannot deliver the ×0.67.**
   - The best equal-security set cuts p50 kernel GPU-s after #1–#9 by **×0.967 central** (16.12 → 15.59 GPU-s, about −0.5 GPU-s) [D/E]. The gap needs −5.3 GPU-s.
   - In the plan model: **p50 11.04 → 10.66 s, p95 18.84 → 18.23 s, basket 166.6 → 161.0 s on 2×5090** (−43.2% → −45.2%) [E].
   - On 4×5090: basket −63.6% → −65.0%, and the pessimistic case goes from −58.8% to −59.8%.
2. **Every blowup move loses on this stack**, because leaves dominate recursion (61–72% of cells) and their cells are set by the *native* queries:
   - native b8 (q36 p20): p50 ×1.07–1.12;
   - revert D2 to b2: ×1.13–1.14;
   - outer b4 (m3 q51 p26): ×1.05–1.14;
   - outer b4 on folds only: ×1.02–1.04;
   - outer b2 q96 p32: ×1.20–4.1 (PoW cost).
   - The recursion layers already run the minimum blowup (log 1), and D2's b4 is the optimum for natives [D].
3. **What wins is verifier-side, not proof-side: Merkle caps in the parent circuit.**
   - In the leaf circuit, native proofs are verified today with full paths. With a cap of 3, the measured census gives **raw Blake-G rows ×0.935 and cells ×0.983**, and the circuit stays satisfied on the unchanged native proof [M, CPU exact census].
   - In fold circuits, the cap goes 3 → 7 (model fold ×0.919 packed) [D/E].
   - Native proofs stay byte-identical. Only the leaf and fold circuits change, which gives new VKs and a new outer profile.
4. **PoW is not free here.**
   - About 70 proofs per p50 block each grind once.
   - The as-built grind runs at about 2 G candidates/s (one atomic per candidate): p26 costs 27.9 ms per proof and p28 costs 144 ms [M dev-5090].
   - An engineered check-every-64 kernel reaches 19–25 G/s (p24 0.76 ms, p26 2.7 ms, p28 15.9 ms) with the same minimal nonce on 28/28 grinds [M dev-5090].
   - Even then only PoW ≤ 24–26 pays. p32 costs 0.25 s/proof, about 18 GPU-s per block.
5. **A correction to the plan.** Native b2 → b4 costs **×1.140–1.144 native GPU-s** [M, nsys A/B, M6 vs D2 on 24628607/26235156], not the ×1.40 [E] in `plan_model.d2_nat`. Post-M8 the blowup share is 0.25–0.39, so ×1.14–1.24 [D]. `d2_nat` and `d2_leaf` are corrected. The rev-4 central numbers do not move, because D2REV is not in the central set.

## 1. Parameters per layer, from the code [code + D]

Security uses the profile's own formula, conjectured (ethSTARK) bits = log₂(blowup)·q + PoW, with the PoW checked after the last FRI commit and before query sampling (`core/pcs/verifier_family.zig`). The robustness column uses the provable Johnson regime: log₂(blowup)/2 per query, plus PoW.

| layer | profile (source) | blowup | queries | PoW | fold arity | last layer | Merkle cap in parent | conj. bits | Johnson |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| native (production) | `d2_native_b4_q54_p20_fold4` (`om31_security_candidate.zig`) | 4 | 54 | 20 | 16 (fold_step 4) | 2⁰ | 0 (full paths) | 128 | 74 |
| native (M6 / CPU default) | `conjectured128_b2_q108_p20_fold4` | 2 | 108 | 20 | 16 | 2⁰ | 0 | 128 | 74 |
| leaf outer proof | `m7_outer_gkr_k4_cap3` / `m6_…k4_cap3` = r1 (`circuit_cpu/om31/protocol.zig`) | 2 | 108 | 20 | 16 | 2⁰ | 3 | 128 | 74 |
| fold outer proof | same r1 | 2 | 108 | 20 | 16 | 2⁰ | 3 | 128 | 74 |
| root | the top fold, exported (no separate root STARK) | 2 | 108 | 20 | 16 | 2⁰ | — | 128 | 74 |
| shelved outer | `m3_b4_q51_p26` / `m3_b8_q34_p26` | 4 / 8 | 51 / 34 | 26 | 16 | 2⁰ | 0 | 128 | 77 |

- Lifting: every PCS uses the lifted VCS. All columns are lifted to the tree height, and the trees are FIXED, MAIN, INTER and COMPOSITION, plus the FRI layer trees.
- Field: OM31 (2²⁴⁸). The algebraic terms sit near 2⁻¹⁹⁰ or below, so the query term binds at 128.
- Hard limits:
  - PoW ≤ 32 (`search.cu`, OM31 shape);
  - verifier cap_log ≤ 5 (`om31_native/proof.zig`);
  - log blowup 1..16 (`FriConfig`).

## 2. What each parameter costs [M → D]

**Native GPU-s vs blowup** [M, `nsys-proof-kind.json`; NVTX state machine in `scripts/rv64_m9/nsys_proof_kind.py`, read-only on the pod sqlite]:
- M6 → D2: 5.29 → 6.06 GPU-s (26235156) and 7.69 → 8.77 (24628607), both pairs. LDE eval rose ×1.9 and DEEP ×1.5; composition and GKR stayed flat.
- Post-M8 fullstack on 24628607, native 3.17 GPU-s per request: the blowup-proportional share is 0.25–0.39 at b4 [D].

**Recursion node GPU-s at log blowup 1** [M, M8 fullstack, 5.28 GPU-s per request]:
- Blowup-proportional phases (openings, DEEP, TC LDE + Merkle, FIXED): 38.5%. The composition-phase LDE adds up to 17% more (φ_R 0.385–0.55).
- Raw-row-bound witness (MAIN assignment + INTER witness): 31.8%.

**Leaf rows vs native queries** [M rows, D fit]:
- 28 matched leaves (M6 q108/b2 vs D2 q54/b4, same blocks and nodes) fit F + q·r per component, with the depth term set by the code (one compression, 80 G rows, per Merkle node per tree).
- At D2 the fixed share is: Blake-G 25% (segment leaves) / 18% (truth leaves); qm31_ops 53% / 29%; m31→u32 46%.
- Per query: about 45 K Blake-G rows (568 compressions), of which about 70% hash column leaves and 30% walk paths.
- The fit reproduces both recorded profiles exactly. Its cell formula reproduces the receipt (1,096,894,720 cells on node 0).

**Fold rows vs child queries** [M, recsize]: 5.5% fixed, the rest ∝ child queries.

**Padding**: cells are powers of two per component.
- Today's segment leaves sit at Blake 2²² (80% full) and qm31 2²³ (66%). Folds sit at Blake 2²³ (93%).
- Without k-leaf fan-in, query cuts below about −36% do not halve any component. The model therefore reports *padded* (exact pow2) and *packed* (fan-in keeps fill constant) factors. The #1–#9 set includes fan-in, so it uses packed.

**PoW** [M dev-5090, `pow-bench-dev5090.jsonl`, `src/backends/cuda/native/pow/bench/m9_pow_bench.cu`]: see TL;DR item 4.

## 3. Search at ≥ 128 conjectured bits on every layer [D/E]

Grid:
- native log blowup 1–4;
- outer log blowup 1–3;
- PoW ∈ {20, 24, 26, 28, 32}, with queries at the minimum that keeps 128 bits;
- leaf cap {0, 6}, fold cap {3, 7}.

It minimises p50 kernel GPU-s after #1–#9 (16.12 central). Top central: native b4 q52 p24, leaf and fold b2 q104 p24, leaf cap 6, fold cap 7, at ×0.960 uncalibrated. The cap-only set is ×0.970.

| set | native / leaf / fold factor (packed, central) | p50 after #1–#9 (pess / central / opt) | root proof |
|---|---|---|---|
| A_caps5 (leaf cap 5, fold cap 5) | 1 / 0.954 / 0.942 | ×0.975 / 0.977 / 0.978 | 706 kB |
| **A_caps67** (leaf 6, fold 7) | 1 / 0.950 / 0.905 | ×0.969 / 0.970 / 0.972 | 706 kB |
| **B_caps67_pow24** | 1 (+0.28 ms PoW per proof) / 0.927 / 0.877 | ×0.970 / 0.960 / 0.962 | 683 kB |
| native b8 q36 p20 | 1.31 / 0.786 / 1 | ×1.12 / 1.09 / 1.07 | — |
| native b4 q48 p32 | 1 / 0.926 / 1 (+PoW) | ×5.5 / 1.59 / 1.69 | — |
| revert D2 (b2 q108) | 0.845 / 1.641 / 1 | ×1.13 / 1.14 / 1.14 | — |
| outer b4 q51 p26 (all) | 1 / 1.321 / 0.725 | ×1.14 / 1.08 / 1.05 | 390 kB |
| outer b4, folds only | 1 / 1 / 1.172 | ×1.04 / 1.02 / 1.02 | 390 kB |

- FRI folding arity 16 is already optimal [D]. Per query, arity 8 costs 116 and arity 32 costs 110–126 compressions, against 108 for arity 16 (path + leaf).
- A last-layer degree of 2^b saves at most one shallow FRI tree per query: about 1% of leaf Blake rows [D].
- Sensitivity:
  - n_trees 8–12, a fold fixed share of 3–10% and native trace log 21–23 move the factors by < 0.003, because cap savings are structural.
  - The real uncertainty is the effective tree count. The census calibrates it: model 124 K rows saved vs 86.8 K measured at leaf cap 3 on the mini fixture, so savings are scaled ×0.70 (0.6–0.9) for leaves and ×0.85 (0.7–1.0) for folds in `plan_model` [E].

## 4. Effect in the plan model (lever `PARAMS` = A_caps67, `PARAMS_POW` = B; calibrated) [E]

| | p50 wall | p95 wall | basket | K p50 |
|---|---:|---:|---:|---:|
| 2×5090 #1–#9 (rev 4) | 11.04 s (−43.8%) | 18.84 s | 166.6 s (−43.2%) | 16.12 |
| + PARAMS | 10.78 (−45.2%) | 18.42 | 162.7 (−44.6%) | 15.76 |
| + PARAMS_POW | **10.66 (−45.8%)** | **18.23** | **161.0 (−45.2%)** | 15.59 |
| 4×5090 #1–#10 | 7.01 (−64.3%) | 11.40 | 106.8 (−63.6%) | 16.12 |
| + PARAMS_POW | 6.74 (−65.7%) | 11.00 | 102.9 (−65.0%) | 15.59 |

No 2-GPU set reaches 60% (pess / central / opt: 40 / 44 / 55%).

## 5. Soundness: what changes the proof

- **Caps (set A)** change no child proof.
  - The parent circuit guesses the 2^c cap nodes of each child tree and hashes them to the committed root in-circuit (`merkle.verifyCap`, 2^c − 1 compressions). It then checks every path only up to the cap.
  - A forged cap needs a Blake2s collision or second preimage, so the error terms are those of the full-path verifier (`rv64-m6-diet-wire.md` §5).
  - The leaf and fold circuits change, so do their VKs and the outer profile domain. A receiver without the policy computes another circuit and rejects (fails closed).
- **PoW 24 / q52 (native) and q104 (outer) (set B)** change the proofs.
  - They stay at 128 conjectured bits (2·52 + 24, 1·104 + 24); the Johnson-regime bits are 76 vs 74 today.
  - They need new native and outer profiles with their own domain strings, identity hashes, receivers and tamper corpora (the D2 / m3 pattern), plus the engineered grind kernel. Its exact minimal-nonce semantics match on 28/28 grinds; the full grind corpus is still to run.
- **Rejected:** higher blowup anywhere (cost), PoW ≥ 28 (cost), outer q96 p32 (cost).

## 6. Prototype and measurement

- `STWO_RV64_M9_PCS_PARAMS` (`src/integrations/riscv_cpu/rv64_recursion/m9_pcs_params.zig`, 3 tests) parses and validates `native|leaf|fold=b<B>q<Q>p<P>`, `leaf_cap` and `fold_cap`. It enforces ≥ 128 conjectured bits, PoW ≤ 32 and the cap guards.
  - Only `leaf_cap` is wired (`leaf_graph.zig` cpuMode). Unset means cap 0, byte-identical.
- `CpuInput.cap_log` (default 0) and `m9_leaf_cap_census_test.zig` (in `test-d2-circuit-census`, 4/4 pass):
  - leaf cap 3 on the D2 mini fixture: cells 554,830,848 → 545,262,592, Blake-G rows 1,339,760 → 1,252,960; circuit valid [M CPU].
  - **Leaf cap 5 fails today.** The host cap derivation (`fromNativeCappedImpl`, written for outer proofs) does not reproduce the root of the native FIXED tree (height 18, 140 mixed-size preprocessed columns) → ShapeMismatch [M]. The parser therefore caps `leaf_cap` at 3.
- Build fix: `test-d2-circuit-census` did not compile on integrate, because `leaf_graph` reaches `outer_wrap`, which lazily imports `stwo_circuit_cpu_integration`. The step now wires circuit_cpu with a shared `stwo_proof_wire`.
- GPU: the dev-5090 PoW bench above. A recursion-node GPU-s A/B with caps needs the capped circuits wired into GPU leaf/fold classes, which is integration work. Cells → GPU-s uses the fewer-leaves calibration (0.262 ns/cell) [D].

## 7. Integration steps after GPU-native lands

1. Land `m9_pow_bench` evidence and swap `search.cu` to check-every-64. It is byte-identical (same minimal nonce): run the PoW corpus on both GPUs. That alone saves about 0.27 ms per proof.
2. Fix the native host cap: a lifted-leaf-aware `fromNativeCappedImpl` for trees shorter than the lifting height. Raise the leaf cap to 6 and the verifier guard to 7.
3. New outer profile `m9_outer_…_k4_cap7_leafcap6_r1_b2_q108_p20_fold4_v1`: fold cap 7 (`foldMerkleCapLog`), leaf cap 6, a new domain, fresh receivers, tamper corpus (wrong cap node, cap/root mismatch, cap from a different tree). Re-census real leaves (`RECURSION_NODE_SHAPE`) and fold classes, then a 3+3 A/B. Replace `pp_packed` / `pp_padded` with measured factors.
4. Optionally set B: native profile `d2b_native_b4_q52_p24_fold4` and the outer q104 p24, with new identity domains. Gated on step 1 and a GPU-s A/B.
5. Merge order: `codex/rv64-m9-plan` first. This branch adds `plan_model.py` verbatim from plan r4 (`5702d49e7`), then one commit with the `PARAMS` lever and the `d2_nat` / `d2_leaf` correction. Rebase that commit onto the plan branch.
