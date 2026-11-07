# RV64 M9 stream m9-outer-gkr: outer LogUp-GKR in recursion nodes (DW-R1), re-derived on today's trees

*2026-11-07, branch `codex/rv64-m9-outer-gkr` (cut from `codex/rv64-m7-integrate` @ 786429aca). CPU only: no GPU was used.
Labels: **[M]** measured, **[D]** arithmetic on measured numbers or counted from the code, **[E]** estimate.
Receipts: `vectors/reports/rv64-m9-prep/m9-outer-gkr/`. Flag: `STWO_RV64_M9_OUTER_GKR` (default off; read only by the new CPU tool).*

## 0. Verdict

The plan (rev 3, §4.1 row 8; `plan_model.py` `ogkr_alone` = (0.65, 0.57, 0.50)) multiplies **recursion GPU-s** by ×0.57.
That number is the M5 **committed-cell** factor (24628607, M4-era tree, `rv64-m5-outer-gkr.md` §6). Re-derived on today's trees:

1. **The cell factor holds:** ×0.562 / ×0.566 / ×0.568 on 24628607 / 26235168 / 26235159 (post-M8 tree), and ×0.575 / ×0.617 / ×0.630 on the k-leaf fan-in tree [D].
2. **The GPU-s factor does not.** Recursion kernel GPU-s goes **×1.07 central** on the post-M8 tree and ×1.07–1.15 on the fan-in tree (pess ×1.50–1.60, opt ×0.90–0.98) [D/E]. As built, **outer GKR is a net loss of GPU-s**, like Poseidon2 and canonical leaves in wave 1.
   - Why: M8 made committed cells cheap. The bench15 fit is r_k = 0.26 ns per committed cell [D]. M5 used 0.47 ns (0.235 per LDE cell at b2, M4.0). The GPU GKR prover did not get cheaper: 0.575 ns/fact on materialised inputs [M, M5 fused route]. With projection from MAIN it is 0.82 ns/fact [D, + native-stage projection spans], and 1.58 ns/fact all-in on the native projected route [M].
   - Break-even is **0.55–0.68 ns/fact** (0.46–0.57 once streaming commit lands) [D]. Every GKR component loses at the central rate. Per-component break-evens are blake_g_gate 0.72, xor12 0.64, triple_xor 0.57, m31_to_u32 0.34 ns/fact [D].
3. **The node wall improves a little,** ×0.89 (post-M8 tree) and ×0.95–0.96 (fan-in tree) [E]. The reason is that the per-cell wall rate (0.455 ns) is higher than the kernel rate. This is far from ×0.57.
4. **Two blockers come before any speed claim:**
   - **Memory.** GKR workspace is 64.3 B/fact [M]: 16.6 GB at a 2^23-blake fold. The M7 production fold already failed admission, needing 15.74 GB free [M].
   - **Power-of-two crossing.** Adding verifier rows to folds of fan-in leaves pushes blake_g_gate from 2^23 to 2^24. That happens in 3 of 9 folds on 26235168 and 6 of 12 on 26235159 [D/E]. Those folds get cells ×0.906 and a **30.6 GB** GKR workspace, which does not fit the 28 GiB gate.
5. **Recommendation for the plan:**
   - Set `ogkr_alone` = **(1.15, 1.07, 0.90)** as built.
   - Add an *engineered* variant only behind a measured GKR kernel at ≤ 0.3 ns/fact with fused projection. That variant gives ×0.78–0.84 [E] (p50 −3.1 GPU-s instead of −6.0).
   - In the §4.3 search, no 2-GPU set reaches 60% with outer GKR as built. The search must be rerun with these factors.

## 1. What moves to the GKR

The node AIR is the outer circuit verifier: 11 components (`profile.zig`).

| component | classic OM31 INTER cols | lookups/row | to GKR? | hybrid INTER |
|---|---:|---:|---|---:|
| blake_g_gate | 104 | 26 (lanes 16+8+2) | yes | 16 (Eq + cyclic prefix) |
| triple_xor | 48 | 12 (8+4) | yes | 16 |
| m_31_to_u_32 | 24 | 5 (4+1) | yes (cell rule; **loses on time**, break-even 0.34 ns/fact) | 16 |
| verify_bitwise_xor_12 (table) | 64 | 16 | yes | 16 |
| eq, qm31_ops, xor8/4/7/9, range_check_16 | 8–16 | 1–3 | no (≤ 16 binding cols) | unchanged |

- The relations that move are the gate relation (`378353459`), the XOR relations (8/7/9/12-bit ids in `tuples.zig`) and the m31→u32 range relation. Each lookup becomes one fraction of a lane-major GKR instance (index = lane·2^row + row).
- Closure is checked per shared relation: classic claimed sums + Σ GKR roots + public bus = 0. The classic consumers of a shared relation (qm31_ops, eq) stay on LogUp columns.
- Committed INTER per node falls from 304 to 128 base columns (`hybrid_air.zig`).
- The M5 hybrid rule ("GKR if classic width > 16") is a **cell** rule. On today's kernels the rule has to be a **time** rule: GKR only where measured ns/fact < the component's break-even (§3).

## 2. In-circuit verifier cost per child [D, from the circuit code]

`m9_node.verifierCost` counts the outer-GKR gadget (`circuit.zig verify + requireClosure + requireTerminal`) on a shape-exact fabricated section. The test "shape-only verifier cost equals the honest section's gate counts" pins that it is identical to an honest section (v1 and v2, two shapes). At L = 27 it reproduces the M5 GPU-section counts **exactly** (`verifier-cost.json`).

| child class (row logs eq,qm31,triple,m31,blake) | L | facts | G-gate | qm31_ops | m31→u32 | triple_xor | eq | section B |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| D2 CPU leaf 18,23,19,20,22 (v2) | 26 | 137.4 M | 183,840 | 209,107 | 19,192 | 18,384 | 1,516 | 65,588 |
| 2^23 fold 16,23,20,21,23 (v2) | 27 | 257.9 M | 195,200 | 223,667 | 20,360 | 19,520 | 1,627 | 69,812 |
| crossing fold 16,23,20,21,24 (v2) | 28 | 476.1 M | 205,280 | 234,978 | 21,368 | 20,528 | 1,742 | 73,652 |
| M5 leaf-cpu-24628607 (v1) | 27 | 257.9 M | 195,200 [= M5 M] | 223,203 [= M] | 20,360 [= M] | 19,520 [= M] | 1,581 [= M] | 69,812 |

- At hybrid widths, one child costs the parent **+19–24 M cells**.
- Verifying the child's 176 fewer INTER columns saves **9.1 M cells**:
  - leaf-hash compressions: 108 queries × 11 × 80 G-rows [D];
  - mixing the OODS samples [E];
  - DEEP terms: 2 qm31 rows per column per query [E].
- The net is **+10–15 M cells per child**, about 1.2–1.4% of a 1.03 G-cell hybrid fold.
- v2 (the DW-R1 row-point guard) costs about +440 qm31 rows over v1.

## 3. Prover GPU-s per node [D/E from our kernel timings]

| quantity | value | label |
|---|---|---|
| facts per node | Σ_GKR lookups · 2^row (D2 leaf 137.4 M; 2^23 fold 257.9 M; fan-in crossing fold 476.1 M) | D |
| GKR rate: materialised inputs, fused fold + next-sum | 0.575 ns/fact (148.2 ms / 257.9 M) | M (M5) |
| + lazy projection from MAIN | +0.244 ns/fact (native-stage projection spans, 4 natives) → **0.82 central** | D |
| all-in projected route | 1.58 ns/fact (native GPU_GKR stage wall / facts) | M |
| engineered target | 0.25 ns/fact (~1.5× an HBM floor of ~4 passes × 64 B/fact at 1.5 TB/s) | E |
| GKR workspace | 64.3 B/fact (16.57 GB at 257.9 M facts); 58.3 B/fact partial-frontier | M |
| committed-cell kernel rate | r_k = 0.262 ns/cell (bench15 fit); 19% of recursion is witness/`chain_run`, which scales with gate rows, not INTER | D |

Per node, central (24628607, post-M8 tree, `factor.json`):

| node | cells classic → hybrid | kernel GPU-s classic → hybrid (of which GKR) |
|---|---:|---:|
| D2 CPU leaf | 1.097 → 0.652 G | 0.287 → 0.305 (0.112) |
| short CPU leaf | 0.610 → 0.358 G | 0.160 → 0.172 (0.065) |
| 2^23 fold | 1.866 → 1.027 G | 0.488 → 0.528 (0.211) |

Per-component break-even (r_k·(1−0.19) per removed column ÷ facts per row) [D]:

| component | break-even ns/fact |
|---|---:|
| blake_g_gate | 0.717 |
| xor12 table | 0.636 |
| triple_xor | 0.565 |
| m31_to_u32 | 0.339 |

## 4. Soundness

- **Challenges.** OM31, with strict draws: a draw is rejected, never redrawn, if any raw word is ≥ 2p (`rv64-m5-outer-gkr.md` §3). With QM31 challenges the same facts fail at 124 bits (pinned in the M5 test). **OM31 is mandatory.**
- **Union bound per request** with the actual node count and the largest L [D, `factor.json soundness`]. The dominant term is the tuple-compression term i·a·2^L, which committed LogUp also has. Required: 151.

  | block | post-M8 tree | fan-in tree |
  |---|---|---|
  | 24628607 | 19 nodes, L ≤ 27: 209 bits | 12 nodes: 209 bits |
  | 26235168 | 62 nodes: 207 bits | 33 nodes: 207 bits |
  | 26235159 | 97 nodes: 206 bits | 48 nodes: 206 bits |

  The fan-in crossing folds have L = 28 and cost about 1 bit.
- **Binding.** v2 (DW-R1 closed): an anchored Eq recurrence and a cyclic prefix with target = Σ ρ_g(claim_n + γ·claim_d). The terminal claims are fixed before the late γ and ρ draws. The auxiliaries come only from the verified GKR point (`rv64-m7-outer-gkr.md`). The prototype runs exactly this on real-roster sections.
- **Characteristic bound.** `sourceUseMass` (all positive uses, classic + GKR + public). Even the 2^24-blake crossing fold has mass about 22·2^24 + … ≈ 2^28.6 < p [D].
- **Still owed** (unchanged from M7): the late-binding theorem review against `binding_theorem_required`, a fresh receiver on a full Ethereum request, and the production tamper corpus.

## 5. Proof-format change

- Each node proof gains one GKR section: v2 wire `[magic, version=2, class, n, L] salt roots` + per-layer rounds (4 coefficients) + masks. That is **57.5–73.7 kB** for L = 24–28 [D], and the identity domain is `…/lane-major/v2`.
- Each proof opens 176 fewer INTER columns at 108 queries, saving **−76.0 kB** [D]. Net root proof: **−6 to −10 kB**. Child proofs are consumed in circuit.
- Class identity: the M5 classes are comptime constants. M9 run-time classes (`m9_node.classFor`) take their id from the node row logs (`0x9xxxxxxx`). In production the receiver must derive the class from the node statement or VK, never from the proof (`section.decode` pins `expected`). The class-stable outer shapes of plan §5 row 2c would bound the class count.
- Optional v3: derive c0 from the claim (−25% of round bytes, M5 open item 5).

## 6. Prototype (CPU, real leaf class shape)

New files only:
- `src/integrations/riscv_cpu/outer_gkr/m9_node.zig`
- `m9_node_test.zig`
- `rv64_m9_outer_gkr_tool_main.zig`
- `rv64_m9_outer_gkr_test_root.zig`
- `scripts/rv64_m9/outer_gkr_factor.py`
- its test

There are also two additive build lines (a step and a tool) and an unchanged copy of `scripts/rv64_m9_leaf_fanin_model.py` from `codex/rv64-m9-fewer-leaves` @ a056cee67.

**The node relation from the original tuple authority.** MAIN and preprocessed rows of the four GKR components go through `tuples.rowFor` and `om31.witness.Elements.combine` (Σαⁱtᵢ − z) into lane-major fractions of the **real D2 CPU leaf roster**: 8 instances, lane groups 16+8+2 / 8+4 / 4+1 / 16.

**`runNode`** runs the full chain:
1. `proveCpu` (strict draws, re-salt on rejection);
2. encode, then fresh decode against the receiver-pinned class;
3. native verify;
4. closure (a wrong external sum is rejected);
5. terminal check against the input MLEs;
6. late v2 binding columns for all 4 components (a wrong target is rejected);
7. in-circuit verifier valid; a tampered closure is unsatisfiable.

A separate test checks that every sampled proof-body word tamper is rejected natively, and that a subset is rejected in circuit.

| rows (real − shift) | fractions | L | prove | native verify | binding | circuit | RSS | all checks |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| −8 | 0.54 M | 18 | 0.08 s | 0.03 s | 0.04 s | 0.01 s | 56 MB | pass |
| −6 | 2.1 M | 20 | 0.30 s | 0.10 s | 0.18 s | 0.02 s | 0.22 GB | pass |
| −4 | 8.6 M | 22 | 1.17 s | 0.40 s | 0.78 s | 0.02 s | 0.86 GB | pass |
| −3 (1/8 of the real leaf) | 17.2 M | 23 | 2.37 s | 0.82 s | 1.58 s | 0.02 s | 1.7 GB | pass |

The full-size leaf (137 M fractions) does not fit the 6 GB CPU guard. Its verifier cost is counted at full shape (§2).

**Tests [M]:**
- Zig 6/6: `zig build test-riscv64-m9-outer-gkr`;
- Python 3/3: `scripts/tests/test_rv64_m9_outer_gkr_factor.py`, which includes reproducing `factor.json` from the committed gate cache;
- source hashes in `tests.json`.

## 7. Re-derived factor (recursion kernel GPU-s, hybrid ÷ classic) [D/E]

The trees and per-node raw rows come from the fan-in model (exact on 24628607/26235156 against `RECURSION_NODE_SHAPE` [D]). Gate counts are from §2.

Cases:
- **pess:** 1.58 ns/fact, witness share 0.30, no DEEP saving;
- **central:** 0.82 ns/fact, 0.19, 2 rows/col/query;
- **opt:** 0.575 ns/fact, 0.10, 4 rows/col/query;
- **eng:** central with 0.25 ns/fact.

| block | tree | nodes | cells | pess | **central** | opt | eng | central after streaming | R central GPU-s | node wall Σ |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|---:|
| 24628607 | post-M8 | 19 | ×0.562 | ×1.52 | **×1.07** | ×0.90 | ×0.78 | ×1.15 | 5.66 → 6.08 | ×0.89 |
| 24628607 | fan-in | 12 | ×0.575 | ×1.50 | **×1.07** | ×0.91 | ×0.79 | ×1.15 | 4.66 → 4.99 | ×0.90 |
| 26235168 | post-M8 | 62 | ×0.566 | ×1.51 | **×1.07** | ×0.91 | ×0.78 | ×1.15 | 19.8 → 21.2 | ×0.89 |
| 26235168 | fan-in | 33 | ×0.617 | ×1.58 | **×1.13** | ×0.96 | ×0.83 | ×1.21 | 15.0 → 17.0 | ×0.95 |
| 26235159 | post-M8 | 97 | ×0.568 | ×1.51 | **×1.07** | ×0.91 | ×0.78 | ×1.15 | 31.2 → 33.4 | ×0.89 |
| 26235159 | fan-in | 48 | ×0.630 | ×1.60 | **×1.15** | ×0.98 | ×0.84 | ×1.23 | 23.6 → 27.1 | ×0.96 |
| basket (15 blocks) | post-M8 | | | ×1.51 | **×1.07** | ×0.91 | ×0.78 | ×1.15 | 231 → 248 | |
| basket (15 blocks) | fan-in | | | ×1.58 | **×1.13** | ×0.97 | ×0.83 | ×1.22 | 179 → 203 | |

What the table shows:
- Leaves and post-M8 folds behave alike (×1.06–1.08 central).
- In the fan-in tree, the crossing folds give a fold factor of ×1.33–1.41 central. A fold-arity guard (3 children when 4 would cross) or a planner that counts verifier rows removes this.
- **The plan's ×0.57 is wrong for GPU-s** at every case except a hypothetical sub-0.1 ns/fact prover. At p50 (post-M8 recursion 14.0 GPU-s) the lever is **+1.0 GPU-s** as built (central), −1.4 at opt and −3.1 engineered, against the plan's −6.0. At p95 it is +1.6 / −2.3 / −5.1 against −10.0.

## 8. What would make it pay

1. **A GKR kernel at ≤ 0.3 ns/fact** with the projection fused into the first product-tree level and the final-layer revisit (M7 `outer_gkr_projected.cu` callbacks). Measure first: a standalone 5090 microbenchmark of the fused projected traversal on one 2^23 fold class (≤ 5 min under the GPU lock). If it misses 0.45 ns/fact, kill the lever.
2. **A time-based hybrid rule.** GKR for blake_g_gate and the xor12 table only (break-even 0.72 / 0.64). triple_xor and m31_to_u32 stay classic unless the kernel beats 0.57 / 0.34.
3. **Memory.** Chunked/layered GKR or P1 (node ≤ 11 GB). Today 4/19 nodes of 24628607 and 23/97 of 26235159 exceed the 15.74 GB measured free [D]. The partial frontier (58.3 B/fact) clears all post-M8 nodes but leaves 3–6 fan-in nodes over.
4. **A fold-arity guard** in the planner for hybrid children: count verifier rows at the child's hybrid class.
5. **Interaction with other levers.** Streaming commit makes committed cells cheaper still (break-even falls by ×0.84). Poseidon2 leaves shrink blake_g_gate rows and with them the GKR's best component. Outer GKR and those levers compete for the same cells.

## 9. Integration steps after GPU-native lands

1. Rerun the plan search (`plan_model.py`) with `ogkr_alone` = (1.15, 1.07, 0.90). Add an `ogkr_engineered` = (0.90, 0.80, 0.78) variant gated on step 2.
2. GPU microbenchmark (standalone, lock ≤ 5 min, CUDA events): the fused projected GKR route at the D2 leaf class (137.4 M facts) and the 2^23 fold class (257.9 M). Gate: ≤ 0.45 ns/fact to continue, ≤ 0.3 to schedule.
3. If it passes:
   - port `m9_node.classFor` to the job classifier, so classes come from node shapes and are pinned in the VK;
   - add the time-based hybrid rule as a per-class roster;
   - add the arity guard to `leaf_fanin.zig`/`ready_dag`;
   - use chunked GKR (`gkr_chunk_contract.zig`) under global admission.
4. Wire the M7 resident hybrid route (`hybrid_device.zig`, `hybrid_receiver.zig`, child verifier) under `STWO_RV64_M9_OUTER_GKR=1` in a new job class, without touching `rv64/jobs/` defaults. Owed before promotion: a fresh receiver plus the tamper corpus on 24628607 and 26235168, and a 3+3 paired A/B.
5. Do not promote on cells. Promote only on paired request time.
