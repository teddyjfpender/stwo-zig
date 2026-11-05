# M6 recursion cell diet in the prover (stream diet-wire)

*2026-11-05, branch `codex/rv64-m6-diet-wire` (from 95d40063d). Labels: **[M]** measured (receipt under
`vectors/reports/rv64-m6-20261105/diet-wire/`), **[D]** arithmetic on measured numbers, **[E]** model. Every timing is a
single observation on a loaded pod (1-min load 9–27 against a quiet bar of 8) unless stated; A/B pairs are interleaved
runs of one binary.*

## 1. What is switched on

**Named outer profile `m6_outer_diet_k3_r1_b2_q108_p20_fold4_v1`** (component `kary-v1`, k = 3), selected with
`STWO_RV64_OUTER_PROFILE` on the producer **and** the receiver, off by default.

| item | value |
|---|---|
| PCS | r1: blowup 2, 108 queries, 20-bit PoW, FRI fold 4 (conjectured 1·108 + 20 = 128 bits, unchanged) |
| domain (hashed into every outer authority identity, the wire header and every outer transcript) | `stwo/circuit/native-om31/m6-diet-k3-q108-p20-fold4/lens-v1` |
| fold arity | **3, a profile constant** (`Profile.requiredFoldArity`); `STWO_RV64_FOLD_ARITY` may only restate 3, any other value is a clean error on the producer and the receiver (`Om31ProfileFoldArityMismatch`, via `checkPolicyEnv`) |
| plan | `ready_dag.Plan.initArity(leaves, 3)`: streaming carry; the last fold of a level may take 2 children |
| shape | `exact` (no padding beyond each component's power of two) |
| fold message | v2 digest with version word `(3 << 8) \| 2`; `classKey` binds the arity (CV1) |
| T_rec outer_profile id | `@intFromEnum + 1` = 6 (existing ids unchanged, pinned by test) |

**Second named profile `m6_outer_diet_k4_cap3_r1_b2_q108_p20_fold4_v1`** (components `kary-v1` k = 4 and `merkle-cap-v1`
c = 3 on fold circuits; domain `stwo/circuit/native-om31/m6-diet-k4-cap3-q108-p20-fold4/lens-v1`; T_rec id 7): same PCS and
shape rules, arity 4 as a profile constant, fold child verifiers stop at an 8-node Merkle cap (§5). This is the stage that
pays: −26 % / −31 % committed recursion cells and −25..−34 % recursion GPU work on the dev blocks (§3b).

Soundness: nothing new. The k-ary fold is the fold v2 argument with k children (`rv64-m5-binding.md` §4, the k-ary lemma,
reviewed "no issue"); arity is a class constant and the receiver re-derives the plan from the leaf count and the profile.
A diet proof under an r1 receiver (or the reverse) fails at the first outer authority because the domain differs
(corpus DW07).

## 2. Why 3 and not 4 (the power-of-two cliff) [M]

26235156 under r1 with `STWO_RV64_FOLD_ARITY=4`: the first 4-ary fold needs **8,680,080 `blake_g_gate` rows = 2^23 + 3.5 %**,
so the component pads to 2^24 and the fold's composition domain to eval_log 25. The producer fails with
`CudaAllocationFailed` (arena overrun 11.24 GB on top of 15.7 GB live in a 27.3 GB carve). A 3-ary fold of three leaves
needs 6,510,080 rows (78 % of 2^23), so it keeps the leaf's padded shape and every node still fits the M5 arena.

To make 4-ary fit, a fold must lose about 300 k G rows (≈ 940 compressions per verified child out of ≈ 27 k). §5 is the
diet that does it (Merkle cap, built as the second named profile).

## 3. Measured effect [M] (receipts `*-k3-ab1*`, `*-k2-ab1*`; same M5 binaries, interleaved)

| | 26235156 k=2 | 26235156 k=3 | 24628607 k=2 | 24628607 k=3 |
|---|---:|---:|---:|---:|
| nodes (leaves + folds) | 21 (11+10) | **17 (11+6)** | 33 (17+16) | **26 (17+9)** |
| committed recursion cells [D] | 32.70 G | **26.75 G (×0.818)** | 51.62 G | **41.20 G (×0.798)** |
| fold cells [D] | 16.07 G | 10.12 G | 26.13 G | 15.71 G |
| recursion device-stage GPU-s | 19.79 | **16.53 (−16 %)** | 29.37 | **26.09 (−11 %)** |
| recursion stage wall | 15.46 s | 15.50 s | 21.55 s | 21.37 s |
| request wall | 31.65 s | 30.84 s | 44.08 s | 43.56 s |
| root proof | 748,536 B | 753,112 B | 706,424 B | 741,784 B (+5 %) |
| device peak (NVML, whole device) | 31.5 GB | 31.5 GB | 31.5 GB | 31.5 GB |
| fresh receiver | accepted | accepted | accepted | accepted |

The k=2 controls reproduce the M5 default root (24628607 root sha `2feed86a…` = M5 integrate a4).

**Reading.** Cells and GPU work fall by 11–20 %, the recursion wall does not move. The recursion is not GPU-bound in
M5: per-node host preparation (graph 0.2–1.0 s + host plan 0.7–1.9 s per node, `pipeline.json`) and the native pipeline
gate it; device-stage occupancy is 0.54–0.69. The cell diet turns into wall time only once hint-tape / enqueue / sched
remove the host gaps (their M6 levers). The root proof grows 0.6–5 % because the root verifies up to 3 children.

## 3b. The two named profiles on this tree's binaries [M] (receipts `*-k3-p1`, `*-k4c-p1`, `*-r1-p2`, `*-k4c-p2`, `*-p3`)

Driver and receiver built from this branch (6a6d95e9f); CUDA library = M5 `0caf0144` (CUDA sources unchanged by this
branch; this tree's nvcc link segfaulted once and was not retried). One-shot `rv64_m3_pod.py bench`, fresh cache-disabled
receiver per run. p2 ran with the negative corpus in parallel (1-min load 34–53): A/B within p2 is interleaved, absolute
times are not quotable.

| | 26235156 r1 (p2) | 26235156 k4-cap3 (p1 / p2) | 24628607 r1 (p2) | 24628607 k3 (p1) | 24628607 k4-cap3 (p1 / p2) |
|---|---:|---:|---:|---:|---:|
| nodes | 21 | **15** | 33 | 26 | **23** |
| committed recursion cells [D] | 32.70 G | **24.06 G (×0.736)** | 51.62 G | 41.20 G | **35.79 G (×0.693)** |
| fold cells [D] | 16.07 G | 7.43 G | 26.13 G | 15.71 G | 10.31 G |
| device-stage GPU-s | 21.22 | 13.95 / 15.86 | 32.11 | 24.74 | **21.59 / 22.04** |
| recursion stage | 17.40 s | 12.76 / 15.10 s | 26.21 s | 20.58 s | 20.21 / 21.20 s |
| root proof | 748,536 B | 750,136 B | 706,424 B | 743,768 B | 708,696 B |
| fresh full-tree receiver | accepted, 48.5 s | accepted, 34.7 / 43.8 s | accepted, 69.7 s | accepted, 54.0 s | accepted, 50.3 / 52.7 s |
| device peak (NVML) | 31.5 GB | 31.5 GB | 31.5 GB | 31.5 GB | 31.5 GB |

The 4-ary fold of four leaves needs **7,767,120 G rows** (k-ary r1 without the cap: 8,680,080), the [D] estimate of §5
was 7.77 M. Every fold keeps the leaf shape (eval_log 24), so the device peak is unchanged.

Gate evidence [M]:
- negative corpus v3 (`--format m3`, full-tree receiver, fresh process per case): k4-cap3 **42/42** on both dev blocks,
  k3 42/42 (26235156; 24628607 in the receipts), 0 unexpected accepts, 0 crashes. V01/V02 were made k-ary aware (they
  named binary fold files; binary trees pick the same files as before).
- cross-profile (DW07, `cross.sh`): a k4-cap3 proof under r1 / k3 receivers and a k3 proof under the k4-cap3 receiver →
  `MissingRecursiveNodeProof` (plan differs); an r1+arity-3 proof under the k3 receiver and a k3 proof under r1+arity-3
  → `Om31CircuitWireProfile` (same plan, domain differs); `STWO_RV64_FOLD_ARITY=2` under k4-cap3 →
  `Om31ProfileFoldArityMismatch` (clean exit 1); the control accepts.
- root-only (`derive-vk-tables` / `verify-root-candidate`, fold-v3 files): **fails on k-ary trees** with
  `VkDeriveLeafCoverage`: `root_verify.zig` `recordLeaf/recordFold/foldClassKey/foldDigest` and the sink are binary
  (`[2]Bridge.Child`) and the k-ary verify path does not feed the sink. The full-tree receiver (today's `--audit`
  equivalent) accepts. Owner: fold-v3.

### Why the wall does not move yet (timeline of 24628607 k4-cap3 p1, `pipeline.json` stamps) [M]

- Every node spends 1.3–3.3 s in host preparation (graph build + host plan) and 0.3–1.3 s on the device. The recursion
  driver keeps at most `STWO_RV64_RECURSION_PREP_AHEAD` (default 3 × lanes = 6) nodes in preparation with 8 host workers,
  so leaf 15 is only taken at 10.4 s although every native proof is ready at 0.
- Leaves finish at 12.7–13.9 s in every configuration; the fold tail after the last leaf is 7.3–7.7 s for binary,
  3-ary and 4-ary alike: three sequential folds × (≈ 2 s host + 0.7 s device).
- Σ host prep / host parallelism ≈ the DAG wall; Σ device / 2 lanes = 10.8 s (k4-cap3) vs 15.1 s (r1). The diet saves
  device time that is not on the critical path today. With host prep off the critical path (hint-tape, sched), the
  device bound alone predicts ≈ −4 s on 24628607 for k4-cap3 vs r1 [E].

## 4. What the M7 levers need (measured blockers)

| lever | status today [M] | what unlocks it |
|---|---|---|
| 4-ary folds | **fits with merkle-cap-v1** (7.77 M G rows); without the cap OOM (2^23 + 3.5 % → 2^24) | done (§3b) |
| `m3_b4_q51_p26` outer profile (k = 3) | OOM on the first leaf: interaction tree, 304 columns, LDE at blowup 4 requests 5.93 G words (23.7 GB), `GPU_TRACE_ALLOCATION_FAILURE tree=2` | outer GKR: the four GKR-bound components drop 240 of 304 interaction columns and add 64 binding columns → 128 columns, ≈ 2.5 G words (10 GB) [D] |
| outer GKR | not wireable this session (§6) | |
| fused Blake one-instance | not started (needs a 12th outer component + 2 tables) | sequenced after outer GKR (blake-gadget review: ships with GKR) |

## 5. Merkle cap in the in-circuit fold verifier (`merkle-cap-v1`, profile `m6_outer_diet_k4_cap3_r1_b2_q108_p20_fold4_v1`)

The in-circuit verifier (`native_verifier/merkle.zig decommitTrees`, `om31_native/fri.zig`) re-expands a full
authentication path per query (no multiproof dedup). A **cap at level c** (the 2^c nodes c levels below the root) costs
2^c − 1 node hashes per tree and saves c node hashes per query per tree:

- Per verified outer child [D]: 4 trace trees (height 24) + 6 FRI layer trees (path 20, 16, 12, 8, 4, 1), 108 queries.
  c = 3 saves 27 compressions per query − 63 per child ≈ **2.85 k compressions ≈ 228 k G rows per child (≈ 10.5 %)**.
  A 4-ary fold then needs ≈ 7.77 M G rows < 2^23 [D].
- The cap nodes are new guessed wires. In trace-only graphs every guess is a `seed` origin with its value
  (`builder/context.zig guessAs`), so the GPU assignment takes them without a new kernel; the host derives them from the
  captured child proof (positions + full paths).
- Completeness bound: cap node j is derivable when some query lies under j or under j's sibling (computed node or
  sibling word). P[some level-c pair has no query] = 2^(c−1)(1 − 2^−(c−1))^108: c = 3 → 1.4·10^−13 per tree (fine),
  c = 4 → 4.4·10^−6 per tree ≈ 10^−3 per request (not acceptable without a producer-exported cap).
- Soundness: unchanged binding (root = H(cap), each path ends at cap[top c bits]); a fold-circuit change only, so it is
  a new fold VK set (named version). It does not change committed cells of any node that stays at its power of two:
  its only value is to enable 4-ary (−4.7 G cells on 24628607 vs k = 3 [E]).
- Built: `native_verifier/merkle.zig` (`selectHash`, `capRoot`, `verifyCap`, `verifyPathToCap`, `decommitTreesCapped`,
  host `hostCap`, which re-hashes the derived cap to the committed root and refuses an uncovered or inconsistent cap),
  `om31_native/proof.zig fromNativeCapped` (trace trees from the captured leaf rows, FRI layer trees from the coset group
  roots exactly as `fri.zig` hashes them), `mod.zig` / `fri.zig` capped decommitment, `om31_outer.zig` selects it from
  `Profile.foldMerkleCapLog()` (3 for the k4-cap3 profile, 0 for every other profile, so leaves and all pre-M6 folds keep
  full paths). Tests: gadget accept/reject (cap node, sibling, top bit) and host derivation (merkle.zig); real OM31 proof
  capped at c = 1 / 2 accepted, cap-node / truncated-sibling / FRI-cap tampering unsatisfiable with unchanged topology
  (om31_native/test.zig).

## 6. Outer GKR: what blocks the wiring (design finding)

`outer_gkr/binding.zig` specifies E (eq column) and Pre (weighted prefix), but `rv64-m5-outer-gkr.md` §5 constrains only
Pre. **E has no AIR constraint in the outer design.** The native stack already solved this: `services/gkr_local/binding.zig`
uses three constraints per instance — Eq boundary at the first two rows against succinct `eq0/eq1`, the recurrence
`eq = eq_next2 · carry` with a **succinct carry polynomial** that the verifier derives from its own folded point, and the
cyclic prefix `pre − pre_prev − eq·projection + target_per_row`. The outer wiring should reuse exactly that construction
(one review instead of two). What it needs in the outer stack, none of which exists:

1. a *succinct column* operation in the outer eval program (`circuit_cpu/om31/program*.zig`): `first`, `second`, `carry`
   are per-row functions of the GKR point, evaluated by the prover per row and by the verifier at the OODS point, never
   committed; the CPU evaluator, the GPU composition codegen (`composition_codegen.zig`) and the in-circuit OODS
   evaluator (`om31_outer.zig evalComposition`, `ForLane`) all need it;
2. per GKR-bound component: drop the classic LogUp part of its captured program, add the 3-constraint binding part over
   the lookup lanes (`binding.zig ProjectionFor` order = the component's lookup order), 16 interaction base columns;
3. the outer prover's interaction phase (enqueue-owned `outer_source_interaction.zig`): GKR after MAIN commit with
   `section.deviceSeed`, then rho/gamma, then E/Pre on device; fused projection (MAIN → fractions inside the first GKR
   layer) to stay under the arena (26.9 GB unfused);
4. transcript order in the CPU receiver and in the in-circuit child verifier (`om31_native/mod.zig verify`):
   `section.verify` / `circuit.verify` between MAIN and INTER, closure with the classic claims, `requireTerminal` against
   the binding columns' OODS values;
5. wire: the section after the interaction claims (class-constant length).

Estimate [E]: 2–3 sessions for one engineer; the plan's kill rule (M7: "slips by more than 2 sessions → ship without outer
GKR") starts counting from M5.

## 7. Native-GKR leaf hook (NF5)

Depends on native-format `v2-gkr` landing; the leaf would verify the native GKR section with `outer_gkr/circuit.zig` and
check the binding boundary against native OODS. Not started; native-format's NF5 is the contract.
