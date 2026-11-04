# Stream diet, iteration 1: M7 cell-diet prototypes, measured cell counts (24628607)

CPU-side prototypes only. Nothing here is wired into the prover, the verifier, the circuit builder or the registry.
No proof bytes change, and no timing is claimed. The cell counts are what M7 needs to turn its factors into **[M]**/**[D]**.

Labels: **[M]** measured by a test/run in this commit; **[D]** arithmetic on measured inputs, with the formula in
`scripts/diet/diet_census.py`; **[E]** estimate under a named assumption.

| file | what |
|---|---|
| `src/frontends/circuit/diet/fused_blake2s.zig` | fused Blake2s compression AIR: fill, evaluator, tables, 5 tests |
| `src/integrations/riscv_cpu/logup_gkr/outer_gkr_diet_test.zig` | batched outer LogUp-GKR: prove, native verify, in-circuit verify, cost law, binding cost |
| `scripts/diet/diet_census.py` | per-node / per-tree cell model (reads widths from `component_list.zig`, row logs from census-v2) |
| `outer-gkr-run1.jsonl`, `outer-gkr-run2.jsonl` | raw `OUTER_GKR_*` lines from two pod runs (`test-riscv64-outer-gkr-diet`, ReleaseFast); every count is identical across the runs |
| `outer-gkr-run2-build.log` | run 2: the step passes (2/2). Run 1 produced the same numbers, but its exactness assertion was too strict for packed qm31 rows, and it pulled in a pre-existing failing `mle_point` test, so the step is now filtered to the diet tests |
| `24628607-cell-census-q108.json`, `-q51.json` | full census output: per node, per lever, tree totals; q = queries of the verified child (r1 108, m3 51) |
| `fused-blake2s-test.log` | pod run of the fused AIR tests |

Inputs: census-v2 row logs of all 33 nodes of 24628607 (17 leaves, 16 folds) **[M]**
(`vectors/reports/rv64-m3-20261104/topo/census-v2.json`). The census reproduces the plan's 1,174.4 M cells for the CPU0
leaf exactly, and its 74.3% G-gate share.

## 1. Fused Blake2s compression AIR **[M]**

**Design.**
- One row per compression; all 10 rounds sit in the row.
- Words are byte columns. XOR is a lookup into a 2^16-row byte table, which doubles as the byte range check.
- `rotr16` and `rotr8` are free byte permutations. `rotr12` and `rotr7` use table variants that return the XOR
  result already split at bit 4 or bit 7, so they cost no extra lookups.
- Additions have **no carry cells**. Each half's carry `(sum − result)/2^16` is a linear expression, constrained to
  {0,1} (degree 2) or {0,1,2} (degree 3).
- Intermediate state never leaves the row, so there is no Gate-relation traffic for intermediates. Only `h` (8 words) and
  `m` (16) are used, and the 8 output words are yielded.

**Tests** (`zig test src/frontends/circuit/diet/fused_blake2s.zig`, pod log `fused-blake2s-test.log`, 5/5 pass):
- **Completeness:** chained fused rows reproduce `std.crypto.hash.blake2.Blake2s256` on 20 message lengths
  (0–300 bytes, 1–5 blocks). Every row satisfies all constraints and all table lookups.
- **Shape:** 3,328 main columns, 1,376 lookups and 640 constraints per row, maximum degree 3.
- **Single cells:** every single-cell change of an honest row (4 deltas × 3,328 cells) is rejected. Most changes break a
  local constraint or table. The rest are message-limb changes that keep the carries in range; those are caught by the
  Gate tuple, which is how today's G gate binds `f0`/`f1` too.
- **Wrong digest:** a wrong digest with a valid byte encoding is rejected.

**Per compression**, today vs fused. The k>1 rows are the analytic multi-row layout [D]; each extra row repeats the
message limbs and carries the state and `h`:

| layout | rows / compression | committed main+inter cells | main | inter | preprocessed | columns per row (main+inter) |
|---|---:|---:|---:|---:|---:|---:|
| today: 80 `blake_g_gate` + 8 `triple_xor` | 88 | **8,672** | 4,320 | 4,352 | 920 | 104 / 44 |
| fused k=1 (implemented) | 1 | **6,080 (×0.701)** | 3,328 | 2,752 | 45 | 6,080 |
| fused k=2 [D] | 2 | 6,528 | 3,584 | 2,944 | | 3,264 |
| fused k=5 [D] | 5 | 7,680 | | | | 1,536 |
| fused k=10, the "round-level rows" [D] | 10 | 9,600 (×1.107, **worse**) | | | | 960 |

Round-level rows lose: once rows are narrow, carrying the state and repeating the message dominates. The win comes from
keeping intermediate state inside the row.

Lookups per compression drop from 2,176 to 1,376, so the LogUp `M/|F|` error term shrinks.

## 2. Outer LogUp-GKR **[M]**

**What was run.** One batched LogUp-GKR covers the 11 outer components of the CPU0 leaf: one instance per component,
with `n = row_log + ceil(log2(lookups per row))`. The batch has L=28 layers, Σn=217 and 378 sumcheck rounds.
- It is proved with `engine.lookups.gkr_prover` and verified natively.
- It is replayed on circuit wires through the shared verifier authority (`verifier_kernel`, with the Blake channel gadget
  in-circuit). The circuit is valid.

**Cost law.** The test was measured at 7 shapes, with per-instance variables scaled down by shift 16…10.
- An affine law in (rounds, instance-layers, layers) was fitted on the first 5 shapes and checked on 2 held-out shapes.
- It is **exact** for Blake G gates, m31→u32, triple-XOR and eq rows.
- Packed qm31 rows are within 0.12%.

The Blake cost is exactly **240·(R+S+L) G gates**, i.e. 3·(S+R+L) compressions. That confirms the earlier
source-derived law (`rv64-gkr-production-recursion-cost.md`).

| per verified child proof, production shape | G gates | qm31 rows | m31→u32 | triple-XOR | eq | cells |
|---|---:|---:|---:|---:|---:|---:|
| GKR verifier (fit at L28/S217/R378) | 149,520 (1,869 compressions) | 54,798 | 11,256 | 14,952 | 428 | **17.49 M** |
| terminal binding arithmetic, 11 instances at production row logs, measured directly | 0 | 76,408 | 0 | 0 | 4,420 | **1.56 M** |

That is about **1.7% of one leaf** (19.0 M of 1,174 M), far below the R7 kill line of 25%. Native terminal-claim
evaluation and the circuit transcript match.

**Binding columns.** The prover side replaces classic interaction columns with 2 secure binding columns: the eq column
and the weighted prefix.
- **8 per log class** (optimistic): one shared column pair per distinct row log.
- **8 per component**: one pair per component.
- **12 per component**: separate N and D prefixes.

## 3. Cells per node, today vs each lever (24628607)

Means over the 17 leaves and the 16 folds.
- Today and all GKR rows are [M]×[D].
- Fused rows use the measured row shape × [D] compressions per node: `point = 0.713·2^logG/80`, the plan's 5.98/8.39
  fill [D].
- Brackets give the interval implied by the measured G and `triple_xor` row logs **[M-bounded]**.
- Fused instances are padded with at most 3 power-of-two pieces.

| node | today | fused k=1 | fused k=2 | GKR, 8 per log class | GKR, 8 per component | GKR, 12 per component | fused k=1 + GKR |
|---|---:|---:|---:|---:|---:|---:|---:|
| leaf (mean) | 1,010 M | 536 M **×0.53** [479–627] | 564 M ×0.56 | 611 M **×0.60** | 645 M ×0.64 | 716 M ×0.71 | 360 M **×0.36** |
| fold (mean) | 954 M | 479 M **×0.50** [417–500] | 505 M ×0.53 | 572 M **×0.60** | 601 M ×0.63 | 664 M ×0.70 | 317 M **×0.33** |
| CPU0 leaf (node 0) | 1,174 M | 659 M ×0.56 | 693 M | 680 M ×0.58 | 758 M ×0.65 | 844 M | 446 M **×0.38** |

### Parents pay for width

A parent hashes every opened column of every child at each query. That costs `q × Δcolumns / 16` compressions, plus
DEEP rows, which are [E] at 2 qm31 rows per column per query.

This is what the plan's per-node factors leave out, and it is why the fused compression row is not free:
- At k=1 the child is 6,189 columns wide, against 311 today.
- That adds 369 M cells per verified child at q108, and 174 M at q51.

Tree totals over all 33 nodes, with 32 child verifications [D]:

| lever | own cells | + parent verification | **tree factor q108 (r1)** | **tree factor q51 (m3)** |
|---|---:|---:|---:|---:|
| today | 32.44 G | | 1.00 | 1.00 |
| fused k=1 | 16.78 G | +8.53 G (q108) / +4.03 G (q51) | 0.78 | 0.64 |
| **fused k=2** | 17.66 G | +4.75 G / +2.24 G | **0.69** | **0.61** |
| fused k=5 | 20.23 G | +2.40 G / +1.14 G | 0.70 | 0.66 |
| fused k=10 (round rows) | 24.09 G | +1.68 G / +0.80 G | 0.79 | 0.77 |
| GKR, 8 per log class | 19.55 G | +0.42 G / +0.52 G | **0.62** | **0.62** |
| GKR, 8 per component | 20.57 G | +0.42 G / +0.52 G | 0.65 | 0.65 |
| **fused k=1 + GKR** (GKR removes the fused row's 2,752 interaction columns) | 11.19 G | +2.98 G / +1.56 G | **0.44** | **0.39** |

### The plan's M7 factors, checked

| plan lever | plan [E] | this iteration |
|---|---|---|
| outer LogUp-GKR | ×0.55 | **×0.58–0.65 per leaf** (own cells, binding at 8 per class to 8 per component) [D from M]; **×0.62–0.65 tree** including the measured in-circuit verifier |
| fused Blake2s, no padding | ×0.7 | **×0.53–0.56 per leaf** own [D from M], but **×0.61–0.69 tree** after parent width (best layout k=2 at q108, k=2 at q51) |
| combined | ×0.38 | **×0.36–0.38 per leaf** own; **×0.39 (q51) – 0.44 (q108) tree** |

The tree-level combined factor is roughly the plan's ×0.38 only when the outer profile is m3 q51 and GKR removes the fused
row's interaction width.

**Recommendation for M7:**
- Build fused **k=1 under GKR**.
- Without GKR, build **k=2** (2 rows of 5 rounds per compression).
- Do not build round-level rows.

## 4. Soundness and binding notes, for review by stream profiles

### Fused AIR

- **Bytes.** Every byte cell, whether an add result, an XOR output, an `h` byte or an output byte, is an argument of a byte
  XOR table whose rows only contain bytes. Split outputs are bounded by their table: `lo < 2^s`, `hi < 2^(8−s)`.
- **Additions.** All operand limbs are below 2^16. They are either byte combinations or Gate-relation u16 limbs, the same
  trust as today's G gate. All sums are below 3·2^16+2, far under p.
  - So the field identity `Σ op_h + e_in − r_h = 2^16·e_h` with `e_h ∈ {0..n−1}` holds over the integers.
  - Hence `r = Σ op mod 2^32`.
  - The carries are linear expressions, not cells, so they add no prover freedom.
- **XOR and rotation.** These follow from the table semantics plus a linear byte permutation or recomposition.
- **Wiring.**
  - `h` and `m` are uses, and the outputs are yields with preprocessed multiplicities, exactly as today.
  - `t0` (v12) and the last-block flag (v14) are setup-fixed preprocessed values, as today's interned constants are.
  - No intermediate wire exists, so there are no new wiring obligations.
- **Profile.** This is an AIR change, not a hash change. A production version needs its own component ids and table ids
  under a named outer profile.

### Outer GKR

- **Sumcheck error.** Σ rounds·degree/|F| ≈ (378+217+28)·3/2^124, about 2^-113.
- **Binding.** The 8-column binding relies on a late random combination of N and D after commitment. That needs the
  review flagged in `rv64-gkr-production-recursion-cost.md`.
- **Unchanged.** The `M/|F|` LogUp term is unchanged versus classic LogUp.
- **Open issue.** The in-circuit channel's `drawSecureFelt` does not reject raw words ≥ 2p. This is a known open item in
  `rv64-gkr-circuit-cost-gate.md`, and it must be closed before production.

## 5. Not measured, and limitations

- **Compressions per node.** Real compression counts per node were not measured; the outer graph census logs no gate
  counts. The fused per-node numbers use the plan's 0.713 fill, with the measured-log interval shown.
- **Parent-side cost.** The parent-side width cost is a first-order model (columns/16 compressions per query, plus [E]
  DEEP rows). It is not a built parent circuit.
- **GKR prover.** The GKR prover's cost (time, memory) was not measured at production size; the largest proved instance is
  2^18 fractions.
- **Binding arithmetic.** It is measured per instance; the residual linear-form evaluation over OODS samples is not
  included.
- **No GPU work, no timings, no proof-format change.**
