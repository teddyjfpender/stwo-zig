# RV64 M9: fewer, bigger recursion leaves (capacity-fit leaf fan-in)

Status: 2026-11-07. Branch `codex/rv64-m9-fewer-leaves`, cut from `codex/rv64-m7-integrate` @ 786429aca. This is CPU-side M9 prep that ran alongside the GPU-native landing. There is no GPU run, service, or proof.

Labels: **[M]** measured, **[D]** derived from measured, **[E]** estimate.

Deliverables:
- the model: `scripts/rv64_m9_leaf_fanin_model.py`, with tests in `scripts/tests/test_rv64_m9_leaf_fanin_model.py`;
- the planner: `src/integrations/riscv_cpu/rv64_recursion/om31_native/leaf_fanin.zig`, default off, flag `STWO_RV64_M9_LEAF_FANIN`;
- receipts in `vectors/reports/rv64-m9-prep/m9-fewer-leaves/`.

It answers 4-GPU doc §6.2 options (b)/(c)/(g) and engineering scope P4.

## 1. Result

**Recommendation:** one leaf verifies up to k adjacent native proofs of the *same class*. In practice that means CPU pairs and Keccak-class (t_a) truth triples. The cap is blake_g_gate ≤ 2^23 (today's fold envelope) and ≤ 2.2 G cells per node. Folds stay 4-ary and unchanged.

| block (gas) | plan | natives | leaves | folds | nodes | depth | cells G | rec. kernel GPU-s | after-native window, 2 GPU / 4 GPU s | streaming tail, 2 GPU / 4 GPU s | max node |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 24628607 (7.4 M, smallest ~4%) | today | 14 | 14 | 5 | 19 | 2 | **21.66** [D] | 5.66 | 5.47 / 3.19 (measured 5.69 on 2 GPU) | 2.19 / 1.88 | 1.87 G |
| | **fan-in** | 14 | **9** | 3 | **12** | 2 | **17.80** (−18%) | 4.66 | 4.49 / 3.09 | 2.20 / 2.09 | 2.11 G |
| 26235168 (29.1 M, ~p50) | today | 46 | 46 | 16 | 62 | 3 | 75.57 | 19.77 | 17.89 / 9.59 | 7.02 / 4.47 | 1.87 G |
| | **fan-in** | 46 | **24** | 9 | **33** | 3 | **57.50** (−24%) | 15.04 | 13.47 / 7.37 | 2.84 / 2.45 | 2.11 G |
| 26235159 (57.7 M, ~top 5%) | today | 72 | 72 | 25 | 97 | 4 | 119.21 | 31.18 | 27.46 / 14.41 | 7.58 / 4.50 | 1.87 G |
| | **fan-in** | 72 | **36** | 12 | **48** | 3 | **90.29** (−24%) | 23.62 | 21.31 / 11.27 | 2.51 / 2.81 | 2.11 G |

How to read the table:
- Cells and nodes are [D] where the receipts exist (24628607 and 26235156 reproduce exactly) and [E] elsewhere: the truth rosters are reconstructed, and so is the k-leaf additivity (§2).
- GPU-s and times are [E] on today's per-cell rates (§2.3). The relative cuts in cells and nodes do not depend on the kernel rates. Absolute seconds shrink with GPU-native.
- On all 15 basket blocks the fan-in plan cuts nodes by 29–51% and cells by 14–25% (`model.json`).
  - The largest five blocks: 71–97 nodes → 38–48.
  - Recursion after native is about 48% of the 24628607 warm request today (5.69 of 11.77 s, bench15 [M]), so −18% cells ≈ −1.0 GPU-s on that block.
- **Streaming tail.** Here natives finish uniformly across the native window and each leaf starts when its last native lands [E].
  - On 2 GPUs, today's plan cannot keep up with native arrival on big blocks, giving a 7.0–7.6 s tail. Fan-in brings that to 2.5–2.8 s.
  - On 4 GPUs the tail falls from 4.5 s to 2.5–2.8 s on the two large blocks.
  - On the small block it is flat to slightly worse (+0.2 s): a pair leaf waits for its second native. If that matters, set k = 1 for the last CPU group. This is a planner knob, not a format change.

### Options compared [E]

All columns are for 26235159.

| option | nodes | cells G | 4-GPU window s | max node | fits a 32 GB 5090 today? | verdict |
|---|---:|---:|---:|---:|---|---|
| today (one native per leaf, 4-ary) | 97 | 119.2 | 14.41 | 1.87 G | yes [M] | baseline |
| **(g′) wider folds, 8-ary** | 83 | 111.8 | 13.99 | 3.64 G (blake 2^24) | **no**: 36–43 GB | reject: −6% cells, 2× node, worse tail on small blocks |
| (c) truth batching only, today's envelope (all components ≤ 2^23) | 93 | 116.9 | 14.37 | 1.87 G | yes | −2%: the qm31_ops cap of 2^23 cannot even pair CPU proofs |
| truth batching only, blake ≤ 2^23 | 76 | 104.5 | 12.99 | 2.10 G | marginal (§3) | −12% |
| **k-leaf, same class (recommended)** | **48** | **90.3** | **11.27** | 2.11 G | marginal (§3); fits post-P1 | −24%, VK set bounded by classes × k |
| k-leaf, same kind (mixed truth families) | 44 | 87.5 | 11.06 | 2.11 G | marginal; fits post-P1 | −27%, but 10+ leaf classes that vary by block |
| k-leaf (same class) + 8-ary folds | 42 | 87.9 | 11.76 | 3.64 G | no | reject: −3% cells over k-leaf alone, 2× node |

Why wide folds lose:
- A fold's cost is linear in its children with zero intercept (§2.1). Widening arity only removes tree depth.
- A 4-ary fold of 2^23-log children already fills 93% of a 2^23 blake column (7.77 M of 8.39 M rows). A 5th child pads to 2^24.

Why k-leaves win: each grouped proof saves the ~0.40 G unpadded cells of verifying one recursion proof in a parent fold, plus its share of fixed tables and padding.

## 2. Cost model

### 2.1 Node cells are additive in children [D]

Every node records `RECURSION_NODE_SHAPE raw=[eq, qm31_ops, triple_xor, m31_to_u32, blake_g_gate]`. Source: `vectors/reports/rv64-m7-20261105/d2-composed/combined-d2-package/{24628607,26235156}-combined-d2-coalesce-v1/producer.stderr`.

- **A fold's raw rows are the sum of per-child rows that depend only on the child's largest padded log.** The intercept is zero.
  - fold4 / 4 = fold-root3 / 3 to 0.01%;
  - fold9 (two log-23 and two log-22 children) is predicted to 0.2%.

| child log | eq | qm31_ops | triple_xor | m31_to_u32 | blake_g_gate | unpadded cells |
|---:|---:|---:|---:|---:|---:|---:|
| 20 | 12,874 | 1,554,863 | 168,190 | 308,160 | 1,681,900 | 0.35 G |
| 22 | 14,145 | 1,674,037 | 186,346 | 344,464 | 1,863,460 | 0.38 G |
| 23 | 14,261 | 1,750,349 | 194,178 | 358,416 | 1,941,780 | 0.40 G |
| 24 [E] | 14,377 | 1,826,661 | 202,010 | 372,368 | 2,020,100 | 0.42 G |

- **Native verification rows per proof [M].** These come from the single-proof leaves.

| native | rows | padded cells as a lone leaf |
|---|---|---:|
| CPU segment (D2 b4 q54), max of 10 | 179,654 / 5,533,212 / 337,632 / 875,134 / 3,376,320 | 1.097 G |
| CPU tail segment | 139,759 / 3,236,107 / 201,144 / 551,210 / 2,011,440 | 0.610 G |
| t_a (3 per block) | 7,000 / 4,085,155 / 228,312 / 438,836 / 2,283,120 | 0.941 G |
| t_b, t_c, t_d | see `leaf_fanin.zig` `fixture` | 0.94–0.98 G |
| t_s | 4,234 / 790,279 / 80,000 / 150,016 / 800,000 | 0.310 G |

- **Padded cells** = Σ width·2^⌈log₂ raw⌉ + 87.6 M of fixed tables.
  - The widths are 12/28/73/31/167. They come from `component_list.zig` `component_facts`, via `scripts/rv64_m6_diet_receipt.py`.
  - The model reproduces `derived-recursive-cells.json` exactly: 21,658,004,224 on 24628607, and 26235156 to 49 k cells.
  - blake_g_gate is 77% of a node's cells. **Padding waste is 19–26% of all recursion cells today** [D].
- **k-leaf rows are the sum of their natives' rows** [E]. This is the same additivity the folds show. The in-circuit combine adds O(10²) constraints, which is negligible.

### 2.2 Basket shapes

- **CPU segments** [M]: `rv64-m3-20261104/summary.json`.
- **Truth leaves:**
  - The 6 blocks that prove under the coalesced D2 profile have 7 family proofs, which is exact on 24628607 and 26235156. The roster is t_a×3, t_b, t_c, t_d, t_s.
  - For the 9 blocks that profile refuses (bench15), round-3 p-truth-split adds max(0, M3 truths − 10) split t_a-class proofs [E].

### 2.3 Time and kernel rates [D, fitted on the 6 bench15 blocks]

- **Node wall:** 0.455 ns/cell, with t0 = 0.
  - It reproduces recursion-after-native to within −12% to +8%: 4.85 vs 4.84 s, 5.47 vs 5.69 s, and 10.89 vs 10.06 s on 24697070.
  - The simulation uses list scheduling, one node per GPU, and `ready_dag` priority.
- **Kernel time:** kernel GPU-s = 0.118·Minstr + **0.262 ns/cell**·recursion cells. M6 measured 0.29 ns/cell.
- **Per node:**

| node | cells | kernel GPU-s | wall |
|---|---:|---:|---:|
| CPU leaf | 1.10 G | 0.29 | 0.50 s |
| fold | 1.87 G | 0.49 | 0.85 s |
| CPU-pair leaf | 2.11 G | 0.55 | 0.96 s |

## 3. Memory on a 32 GB RTX 5090 [E]

- **Gate:** 28 GiB = 30.06 GB, the whole-process gate (`GPU_OUTER device_limit_bytes` [M]).
- **Today's footprint:** a fold node (1.87 G cells) peaks at about 22 GB live (scope §1 [D]). The job path declares 22.6 GB for a leaf and 26.6 GB for a fold [M, `rv64-m8-20261106/wire-outer-p2/nodes-24628607.json`].

| node | cells | today, ∝ 11.8 B/cell | today, job-path linear fit (16.9 GB + 5.2 B/cell) | + 2nd staged native (1.9 GB) | post-P1 (≤ 11 GB per fold) |
|---|---:|---:|---:|---:|---:|
| fold (unchanged) | 1.87 G | 22.0 | 26.6 | — | 11.0 |
| CPU-pair / t_a-triple leaf | 2.11 G | 24.8 | 27.9 | ≤ 29.8 | 12.4 |
| 8-ary fold | 3.64 G | 43.0 | 35.8 | — | 21.5 |

- **k-leaves fit today's gate with 0.3–5 GB of headroom, one lane per GPU.** This is marginal and must be measured before default-on (§6, step 3).
- **After P1** (≤ 11 GB per node), a pair leaf is 12.4 GB, so 2 lanes per GPU fit.
- The blake ≤ 2^23 cap is what keeps the leaf inside today's largest column length (2^23 rows × b2). The node grows only in the cheap qm31/eq columns.
- 8-ary folds do not fit until P1.

## 4. Soundness and transcript

1. **Each native proof is verified in full inside the k-leaf.**
   - Each runs its own native Fiat–Shamir channel, seeded by its own public statement exactly as today.
   - No challenge is shared across the k proofs. This is unlike option (b2), shared FRI, which would need a group barrier and a joint challenge and is explicitly *not* done here.
   - So each native verification keeps today's soundness error.
2. **The union bound shrinks.**
   - The block's error is bounded by the sum over every verified proof: natives plus recursive proofs.
   - Natives are unchanged. Recursive proofs drop from 97 to 48 on 26235159, and the tree depth from 4 to 3.
   - So the total soundness error strictly decreases, at conjectured-128 per proof.
3. **The statement is today's fold combine.**
   - A k-leaf's public output is `node_summary_v3.combine` of its k native summaries, enforced in-circuit:
     - lo/hi adjacency;
     - m/s digest chaining;
     - counter and step chaining;
     - bus sums;
     - mass sums with the existing `< P` limb bounds;
     - kappa count = k;
     - depth = 1.
   - The root's depth bound gets looser, not tighter.
   - `combineSpans` is the planner-side precondition.
4. **Class binding.**
   - The leaf circuit class is `StatementShape.classDigest` = Blake2s("rv64-m9-leaf-fanin/class/v1", version, k, ordered child class tags). It is position-independent, so one VK serves every pair of CPU segments.
   - It must be a T_rec / vk_table member (set-v2 VKs).
   - Same-class grouping bounds the new classes to (native classes) × (k − 1). That is 3 new leaf VKs on the basket: cpu×2, t_a×2, t_a×3.
5. **The receiver derives the same plan, and the prover cannot choose its grouping.**
   - The planner's inputs are the public inventory's native class tags plus per-class row *constants*, never the proof bytes.
   - The policy words (`Policy.words()`: "M9LF", version, k, grouping, caps, arity) join the topology fingerprint, exactly as `STWO_RV64_FOLD_ARITY` does.
   - Producer and receiver must read the same env, or a receiver mismatch fails closed.
6. **No silent padding.** A planned node outside the policy envelope is `LeafFaninNodeOverCapacity` at plan time. The producer must also fail, not re-pad, if a node's actual rows exceed its class shape, because the VK set is fixed.

## 5. Prototype

`leaf_fanin.zig` (std only; tests: `zig test leaf_fanin.zig`, 7 new plus 13 from `ready_dag`, all pass [M]):

- **`parsePolicy` / `policyFromEnv`:**
  - `STWO_RV64_M9_LEAF_FANIN` = unset/0/1 means off, 2..4 is k;
  - `STWO_RV64_M9_LEAF_FANIN_POLICY` = `same` (the default) or `kind`;
  - anything else is `InvalidLeafFanin`.
- **`groupNatives`:** a contiguous DP minimising padded leaf cells plus the verification cost of the group's proof in its parent. Ties go to the smaller group.
- **`FaninPlan.init`:** the groups, then the *unchanged* `ready_dag.Plan.initArity` over the groups.
  - It records rows per node and checks the envelope fail-closed.
  - `nativeRange(node)` maps any node back to native ordinals.
- **`StatementShape`** and **`combineSpans`:** the statement shape and the adjacency precondition (§4).
- **Tests on all 15 basket shapes:**
  - With the flag off, the plan has **byte-identical node identities** to `initArity(n, 4)`.
  - The cost function reproduces the M7 receipts' cells.
  - The fan-in plan is covering, ordered and homogeneous, every node is inside the envelope (blake ≤ 2^23, ≤ 2.2 G cells), and it has strictly fewer cells and nodes. The counts equal the Python mirror's.
  - Policy parsing and the class digest bind k and order.
  - The over-envelope path fails closed.

## 6. Integration after GPU-native lands

1. **Wire the plan** (`execution_wrap.zig`):
   - Read `leaf_fanin.policyFromEnv()` next to `foldArity()`.
   - Build `Native` items from the inventory (CPU setups, then truths), using per-class row constants.
   - Replace `Dag.Plan.initArity(n, arity)` (lines 359, 381, 722, 743) with `FaninPlan.init(...).dag`.
   - Make a leaf worker take `nativeRange(id)`, i.e. k native proofs, instead of one.
   - When the flag is off, the existing call is unchanged: the off path is identity-tested.
2. **Build the k-leaf circuit** (new file):
   - Instantiate the existing native verifier sub-circuit k times, each on its own channel.
   - Then run `node_summary_v3.combine` over the k native summaries, and expose the result as the leaf output.
   - Register the 3 new classes in `vk_table`/T_rec, keyed by `classDigest`.
   - Add `Policy.words()` to `topology_fingerprint.zig`.
3. **Measure memory** (the only GPU step, standalone):
   - Prove one CPU-pair leaf and one t_a-triple leaf on 26235156 inventory.
   - Record `GPU_DEVICE_PEAK` and the job-arena peak.
   - Gate: ≤ 28 GiB with one lane today, ≤ 13 GB after P1.
   - Also check the extrapolated log-24 child cost: a fold over 4 pair leaves must stay ≤ 8.39 M blake rows; the model says 8.08 M.
4. **Receiver:**
   - Make `root_derive.zig` and `root_verify.zig` derive the same `FaninPlan` from the policy words.
   - Add fresh-receiver accepts, plus negative corpus cases:
     - wrong k;
     - swapped child classes;
     - non-adjacent natives;
     - a policy word mismatch.
5. **Measure** with paired A/B on 24628607 and 26235156 (cells exact against the model), then one large block once p-truth-split lands.
   - Expected: −18% recursion cells on 24628607 and −24% on large blocks.
   - Default-on only after a fresh receiver, the corpus, and a measured request-time win.
6. **Interplay:**
   - **Poseidon2 leaves (P2):** these shrink per-native rows about ×0.19. Swap the class row constants and the same DP packs more natives per node. The planner is hash-agnostic.
   - **2^23 CPU rungs (P4):** these halve CPU natives. Grouping and bigger rungs compose: fewer, bigger natives still pair under the blake cap only if their rows fit, and the planner decides from the constants.
   - **D2 truth coalescing:** orthogonal. Grouping acts on whatever native roster the profile produces.
