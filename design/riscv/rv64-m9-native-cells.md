# RV64 M9 prep: native cells per instruction and columns (stream m9-native-cells)

Branch `codex/rv64-m9-native-cells`, cut from `origin/codex/rv64-m7-integrate`. M9 plan rev 4
(`design/riscv/rv64-m9-plan.md` on `codex/rv64-m9-plan`) is short of the >60 % 2×5090 cut by
**×0.67 on all remaining kernel GPU-s**. The owner asked for work reduction. This stream answers how much of that
×0.67 the **native** proofs can supply through fewer cells, columns or instructions.

Labels: **[M]** measured, **[D]** derived from measured values, **[E]** estimate. Receipts are in
`vectors/reports/rv64-m9-prep/m9-native-cells/`. No GPU was used: dev pods `a` and `b` had no `READY-DEV`, and the
main pod was only read.

## 0. Answer

1. **The native AIR is already lean, and the cells are concentrated.** On the 15-block basket [M], committed native
   cells are **160.4 per instruction (513 per gas)** today and **128.1 per instruction** after native GKR v1
   (review fix: v1 now gives every plan slot its pair, as `native_roster.cpu` does; it was 126.7).
   - Four items make up 79 % of today's cells:
     - CPU row: 33 %, 53.4 cells per instruction (37 MAIN + 16 binding columns);
     - Keccak truth: 28 %;
     - LS-D64 dword load/store: 15.5 %;
     - secp truths: 4.7 %.
   - Keccak-f costs about 26 k MAIN cells per permutation, which matches ZisK's `keccakf` template (§4.3).
2. **Prover-side cuts beyond NGKR are small, but they are real** [M declaration census / D GPU-s]:
   - one eq+prefix binding pair per row log (V2SHARE): cells ×0.959, native GPU-s ×0.979 (composition and the
     per-component projection kernels do not shrink; review fix, was ×0.970);
   - tighter padding (PAD): cells ×0.980;
   - a candidate 3-column narrower CPU row (CORE_NARROW, [E]): cells ×0.975.
   - Combined, they give **native GPU-s ×0.945** (pessimistic ×0.966, optimistic ×0.943) on top of NGKR.
   - LogUp batching at 3 fractions per column (LOGUP3) is only an *alternative* to NGKR, worth ×0.967. Most classic
     columns carry 2 queries, and 3 per column saves nothing at q = 2.
3. **The larger native lever is guest-side Zbb; the dispatch cut is small.**
   - Zbb is measured at instructions ×0.937 and native cells ×0.955 [M, ledger-scored basket].
   - The interpreter loop `dispatch_cgoto` spends **28.1 RV64 instructions per dispatched EVM opcode** (1.12–1.36
     instr/gas) [M], but that is the whole per-opcode cost with the handler bodies inlined. The removable overhead is
     the 6 dispatch + 1–2 stack-check + 2 gas instructions per op, and patch 0030 already took the gas branch out of
     the pure opcodes. A basic-block check saves 1.5 / 2.5 / 5 instructions per op: **instructions ×0.980 / 0.967 /
     0.934** [E] (review fix; the first cut was ×0.92 / 0.85 / 0.79 and removed handler work).
   - Both shrink the CPU segments, and with them the CPU recursion leaves and capture, not only native cells.
4. **Plan-model effect** (`scripts/rv64_m9/native_cells_plan.py`, central, on top of the rev-4 best 2-GPU set):

   | lever set (2×5090) | p50 | p95 | basket |
   |---|---:|---:|---:|
   | rev-4 best set | 11.04 s (−44 %) | 18.84 s (−43 %) | 167 s (−43 %) |
   | + NCELLS | 10.77 s (−45 %) | 18.31 s (−44 %) | 163 s (−45 %) |
   | + NCELLS + ZBB | 10.34 s (−47 %) | 17.59 s (−46 %) | 157 s (−47 %) |
   | + NCELLS + ZBB + DISPATCH [E] | 10.22 s (−48 %) | 17.16 s (−48 %) | 153 s (−48 %) |

   - Native work reduction (incl. the recursion leaves the guest levers remove) supplies about **×0.92 of the missing
     ×0.67** on kernel GPU-s: ×0.657 → ×0.603 [D/E] (review fix; was ×0.83, ×0.545).
   - That is about a fifth of the gap in log terms; most of it is Zbb and NGKR-basis cell cuts.
   - **60 % is not reached**: central −48 %, pessimistic −43 %, optimistic −54/−55 % (was −58/−59 %).
   - The rest has to come from recursion (proof-params, recursion-arch, segment-shape streams).

## 1. Data and method

**Census tool [M].** `rv64-m9-native-cells` is built standalone from
`src/integrations/riscv_cpu/build_m9_native_cells.zig`, so `build.zig` is not edited.
- It runs the production roster code on the declarations of real produced native proofs: `cpu_components.Plan`,
  `global_cpu.layout`, `truth_components` and `truth_v3_catalog`, the same code as `rv64-native-gkr-census`.
- It counts MAIN and INTER cells and columns per proof and per component under four variants: today, logup3, v1 and
  v2share.

**Inputs.**
- `bundle.json` of all 15 basket blocks: `/workspace/m3/runs/integrate/<block>-2gpu-*/…/proof/bundle.json`, from the
  M4 integrate runs on 2026-11-04. The M7/M8 CPU roster is unchanged.
- The current M8 default request of 24628607: `m8-census2/daemon-24628607-r2-c2-…`, with 7 CPU proofs and 7 coalesced
  truth proofs.

**Reconciliation [M].** On the current 24628607 run, the declared INTER of all 14 native proofs equals the measured
`GPU_TRACE_OWNERSHIP tree=2 coefficient_words` exactly (multiset equality).
- MAIN is 2.723 G and INTER is 1.909 G.
- The measured `GPU_PCS_NATIVE coefficient_cells` sum is 5.538 G. That figure is the M7 "5.45 G native cells"; the
  extra 0.906 G is FIXED plus the composition quotient.

**Instruction classes [M].** Class row shares come from the exact active rows of a freshly verified 4-packet prefix of
24628607 (`prefix4-active-rows-24628607.json`, from `ge-cache/decode/prefix4b`). Per 4,194,303 instructions:
- every instruction has a CPU row;
- 30.9 % are LS-D64 rows, 6.3 % LS32, 7.8 % ALU-function, 1.8 % bitwise, 1.3 % shift and 1.3 % MUL/DIV;
- RAM events are 37 % of instructions;
- the memory image adds 0.109 rows per instruction.

**Weighting.** The basket weight is the actual cells of each block, so the instruction mix and the precompile calls of
each block are both included.

## 2. Budget (15-block basket, 1,424 M instructions, 445 M gas) [M]

**Per instruction class:**

| class | share today | cells/instr today | cells/instr v1 | rows per instr |
|---|---:|---:|---:|---:|
| CPU row (every instruction) | 33.3 % | 53.42 | 53.42 | 1.000 |
| Keccak truth | 28.0 % | 44.87 | 26.05 | — |
| LS-D64 (aligned LD/SD) | 15.5 % | 24.83 | 19.23 | 0.309 |
| secp add/double (bridge + truth) | 4.7 % | 7.56 | 2.60 | 0.0006 |
| LS32 (sub-dword) | 3.9 % | 6.18 | 5.21 | 0.063 |
| ALU / compare / branch FUNCTION | 3.8 % | 6.18 | 6.18 | 0.078 |
| bulk memory + JUMPDEST | 2.0 % | 3.13 | 2.30 | 0.040 |
| memory image (initial/terminal) | 1.6 % | 2.56 | 2.56 | 0.109 |
| Keccak bridge + sponge | 1.4 % | 2.21 | 1.58 | 0.0035 |
| MUL / DIV | 1.4 % | 2.21 | 2.21 | 0.013 |
| shift, bitwise, JALR, control, range, sha, arith, curves | 4.9 % | 7.5 | 6.7 | — |
| **total** | | **160.4** | **128.1** | |

**Per component** (basket; MAIN / binding / classic, in cells per instruction):

| component | MAIN cols | MAIN | binding | classic |
|---|---:|---:|---:|---:|
| `core.cpu` | 37 | 37.29 | 16.13 | 0 |
| `truth.keccak` | 1,925 | 23.57 | 0 | 21.29 |
| `dword.0` | 39 | 10.77 | 4.42 | 4.42 |
| `core.ls` | 70 | 3.96 | 0.90 | 0.90 |
| `dword.1` | 39 | 2.86 | 1.17 | 1.17 |
| `core.alu` | 47 | 3.78 | 1.29 | 0 |
| `truth.add` | 1,869 | 0.97 | 0 | 2.66 |
| `truth.double` | 1,447 | 0.71 | 0 | 1.97 |

The full table is in `model.json` (`components_basket`).

- **Per block** (`model.json` `blocks`):
  - cells per instruction run from 147.7 (25229951) to 207.4 (26235156);
  - the truth share is 29–42 %;
  - CPU cells per instruction are 104–120.
- **Bits per gas.** 513 cells/gas × 31 bits = 15.9 k own-height bits/gas today, and 12.7 k after v1.

## 3. Native GPU-s by stage (24628607, M8 default kernels) [M/D]

The kernel names in `ab8-kernels.json` (opt-combined fullstack, CUPTI union) split as follows:

| stage | GPU-s |
|---|---:|
| native composition | 0.571 |
| witness | 0.451 |
| classic LogUp | 0.399 |
| local GKR | 0.532 |
| binding kernels | 0.132 |
| channel | 0.103 |
| PCS (native share of FFT/Merkle/DEEP) | 1.02–1.62 |

- The PCS share is the native total (plan split, 3.20 GPU-s) minus the native-only kernels, or a committed-cell split
  of the shared 4.82 GPU-s.
- A column lever pays through PCS and composition (∝ committed cells), witness (∝ MAIN) and the binding kernels.
  GKR traversal (∝ facts) does not move.
- `native_factor()` in `native_cells.py` applies this, with the v1 basis (no classic LogUp, GKR ×1.2) for levers on top
  of NGKR.

## 4. Levers

### 4.1 Prover-side (native GPU-s factor pess / central / opt)

**NGKR_V1** (plan lever NGKR).
- Cells: ×0.798 [M/D] (the plan's own factor is ×0.826). The tool's v1 now equals the M5 exact v1 roster
  (`rv64-m5-20261104/native-gkr/<block>-v1-shape.json`) proof for proof on 24628607 and 26235156, and the tool
  fails if its v1 pairs differ from `native_roster.cpu`/`truth` on any input.
- Native GPU-s: ×0.781 / 0.783 / 0.784.
- Proof change: a new stage-two GKR section and receiver. It is gated by the 151-bit check.

**V2SHARE** (on top of v1).
- Cells: ×0.959 [M].
- Native GPU-s: ×0.981 / 0.979 / 0.977 [D]. PCS and the prefix/eq kernels scale with the removed columns.
  Composition and `project_binding`/`finalize_binding` (0.047 of 0.137 binding GPU-s) do not: every component still
  projects its own ρ-weighted N + γ·D into the shared residual.
- Proof change: one eq+prefix pair per row log, with prefixes combined by a fresh ρ. Soundness: the shared row point
  lemma, plus k/|OM31| for the combination (§6).

**PAD** (on v1).
- Cells: ×0.980 [M waste / E recovery].
- Native GPU-s: ×0.985 / 0.984 / 0.984.
- The measured CPU padding waste is 4.9 % of CPU v1 cells. It is measured on one 4-packet prefix of 24628607 and
  extrapolated to the basket. The top items are `dword.1`, `sponge.perm`, `alu_tail`,
  `multiplication` and `initial/terminal`. Keccak waste is only 0.5 %.
- The lever recovers half of it with a second tail height.
- Proof change: shape/class only, no new argument.

**CORE_NARROW** (on v1).
- Cells: ×0.975 [E].
- Native GPU-s: ×0.982 / 0.981 / 0.981.
- CPU row 37 → 34 MAIN columns by deriving the three `enabled` flags. This is a candidate and its soundness is not
  verified: the AIR change needs the decode authority re-derived. Compact decode already took the row from 47 to 37 [M].

**LOGUP3** (alternative to NGKR).
- Cells: ×0.968 [D].
- Native GPU-s: ×0.966 / 0.967 / 0.967.
- Three fractions per classic column, with a degree-4 batch that fits the b4 composition. Keccak is already at 3 per
  column (pair27, degree-4 quotient). It gives nothing at q = 2, which covers RAM on LS and dword.

**Combined, on v1** (V2SHARE × PAD × CORE_NARROW): **×0.966 / ×0.945 / ×0.943**.
- The pessimistic case excludes CORE_NARROW.
- This is the plan-model variant NCELLS.

**Recursion leaf dividend** [E]. Fewer native columns also mean fewer columns opened in the leaf: about 53 k leaf cells
per column at D2. V2SHARE removes 109 k columns across the basket, about 1.5 recursion GPU-s over 15 blocks. That is
≤0.1 GPU-s per block, and it is **not** included in the plan variants.

### 4.2 Guest-side (guest-efficiency ledger)

**ZBB** [M]. The basket scored instr/gas goes from 3.130 to 2.934 (×0.937) and bits/gas from 33,695 to 32,187
(×0.955).
- The proven prefix and fresh verify exist (`zbb-prefix-24628607-v2.json`).
- Left to do: driver and class work to make `ethereum_services_v3_zbb` the default.
- Proof change: none beyond the already-admitted BINARY component.

**DISPATCH** [M cost, E cut].
- `dispatch_cgoto` costs 1.12–1.36 instr/gas: 17.7 M dispatched ops on the 15 blocks (0.040 ops/gas) at 28.1
  instructions each (`notes/client3-20261102.md`).
- The 28.1 is the **whole** per-opcode cost, with the handler bodies inlined: PUSH1 16, POP 10, SWAP1 25, ADD 36,
  MLOAD 86. The overhead inside it is 6 dispatch + 1–2 stack-check + 2 gas instructions per op (client3 §b), and
  patch 0030 already dropped the gas branch for pure opcodes (28.1 → 27.2).
- Basic-block gas and stack checks, as in evmone's advanced mode, remove about 1.5 / 2.5 / 5 instructions per op
  (pess: the stack checks; opt: plus a cheaper threaded dispatch) [E].
- Estimate on the post-Zbb count (DISPATCH is stacked on ZBB): instructions ×0.980 / 0.967 / 0.934, giving native
  GPU-s ×0.985 / 0.974 / 0.949 (v1-basis CPU share of native cells 0.77).
- Review fix: the first cut took 28 → 14–18 per op (×0.92 / 0.85 / 0.79). That removed handler work, which a
  dispatch change cannot do.
- No proof change. The EEST guards must keep passing.

The 256-bit service work (MUL, EXP) was already measured: its ceiling is below 0.3 % (client3 §a).

### 4.3 Evaluated and rejected (work-reduction candidates in the brief)

- **Narrower limbs.**
  - Words are 4 × u16 in M31, and two u16 limbs cannot share one M31 cell (2^32 > p).
  - A 21/21/22-bit split needs range proofs over 2^21–2^22 values. Those cost more lookup columns than they save.
- **Merged components.**
  - Folding LS-D64 into the CPU row adds about 20 columns to *every* CPU row, roughly 20 cells per instruction. It
    removes only 19.2 × (1 − 20/55) ≈ 7 cells per instruction of dword cells, which is a net loss.
  - The ledger's "−24 cells/instr" (M2) predates LS-D64 and is stale.
  - Merging the small tables (`and`/`range16`/`selection`/`shift_table` at log 16, `rom`, `jtab`) pays only through
    their binding pairs, and V2SHARE already counts those.
- **Cheaper memory argument.**
  - RAM is 2 queries per access, already 1 batched + 1 cumulative OM31 column.
  - Folding the batch into the running sum (as the CPU does for its U8 pair) saves 8 of 16 RAM columns in today's
    protocol.
  - NGKR v1 deletes those columns anyway, so after NGKR there is no committed RAM column left to cut.
- **Smaller lookup tables.** All range/and/shift tables together are 0.27 + 1.6 cells per instruction, and the Keccak
  chi table is 1 MAIN + 16 binding columns at log 21. That is <1.5 % in total.
- **Dropping preprocessed columns.** FIXED is setup-resident. A request pays only DEEP and query openings over it,
  well under 1 % of native GPU-s.
- **Keccak truth.**
  - The AIR has 1,925 MAIN columns × 13.5 rows per permutation (pair27) ≈ 26 k MAIN cells per permutation.
  - ZisK's `precompiles/keccakf/pil/keccakf.pil` keeps a bit-sliced 1,600 + 320-cell state for 13.5 groups per
    permutation (two ops per 27-group slot) ≈ 25.9 k [D].
  - There is no cheap cut. Keccak is 20 % of v1 cells, and a second 2× needs a new AIR (ledger track 6, weeks).

## 5. Prototype: shared binding pairs as a column-count change on the real planner [M]

`SharedBindingPlan` (`services/native_gkr/m9_cells_main.zig`) re-plans a production `cpu_components.Plan`.
- Every binding slot of a row log is assigned to one group, and the binding INTER becomes 16 columns per distinct log.
- Every plan slot is a v1 component (`native_roster.cpu` gives each slot `inter_offset = 16 * index`), so global-only
  slots such as `core.initial`/`core.terminal` are grouped too.
- The unit test (`zig build --build-file build_m9_native_cells.zig test-m9-native-cells`; one new test, 36/36 with
  the imported modules' tests) checks:
  - the grouping;
  - the column count;
  - the cell count;
  - that a global-only slot gets its own group;
  - the 3-per-column width at q = 13 and q = 2.
- Parity: on every input the tool checks its v1 pairs against `native_roster.cpu`/`truth` (component count and
  16 × 2^row_log cells) and fails otherwise. All 16 bundles pass.

**Run on all 15 basket blocks plus the current 24628607** (`blocks.json`):
- v2share/v1 cells are **×0.949–0.962**: 24628607 goes from 3.606 to 3.435 G, 26235168 from 14.284 to 13.712 G and
  26235159 from 25.056 to 24.052 G.
- Per CPU proof, the 21–41 v1 components collapse onto 10–16 distinct logs.
- The `core.cpu` pair at log 22 is unique per proof, so it stays. It is 436 M of the 793 M CPU binding cells on 24628607,
  which is why the saving is 4 % and not the ≈0.4 G that rv64-native-gkr.md §7 guessed.

This is a declaration-level measurement: the native AIR change and a proof run are the integration work in §7. The
`rv64-native-gkr-census` today-cells and the tool's `today` agree for every proof (same Plan code), and the current
run reconciles with the measured tree=2 words.

## 6. What changes the proof (D2 security target)

- **NGKR v1, V2SHARE, LOGUP3 and CORE_NARROW change the native proof**: the AIR, the transcript and the leaf
  verifier.
  - V2SHARE draws ρ after every instance's claim is fixed, then binds Σ_c ρ^c·(N_c + η·D_c) with one shared eq and one
    prefix per row log.
  - The extra soundness error is ≤ (k − 1)/|OM31| ≤ 2^-242 per log for k ≤ 41 components, negligible against the
    151-bit native-GKR gate (`v2.zig` REQUIRED_BITS). The production pair already sums its instances with an
    independent `rho[instance]` per instance (`binding.zig boundaryFor`), so V2SHARE only moves that sum from
    "instances of one component" to "instances of all components of one row log". With independent ρ the bound is
    1/|OM31| per log.
  - Integration risk: if a proof's instances exceed the CUDA `batch_max_oracles` cap and the stage-two batch is split,
    same-log components in different batches no longer share a row point and cannot share a pair.
  - It relies on all same-log components being in one stage-two batch, with row bits as the last coordinates
    (rv64-native-gkr.md §3.2 lemma). Today that holds only under v1/v2's one batch per proof.
  - `binding.zig` forbids cross-instance *cancellation*: each instance keeps its own target. ρ-weighting keeps the
    targets separate.
- **LOGUP3** raises the classic batch constraint from degree 3 to 4. That stays inside the b4 composition bound, as
  Keccak does already.
- **PAD** changes shapes and classes (VK and leaf rosters), not the argument.
- **CORE_NARROW** needs the `enabled` and decode authority re-derived and the negative corpus extended. Treat it as a
  candidate.
- **ZBB and DISPATCH** are guest changes. The statement is the same (EVM output). ZBB uses an already-admitted
  component. DISPATCH must pass EEST and guards G1–G6.

## 7. Integration after GPU-native lands (default-off flags)

1. **NGKR first.** It is the plan's lever. V2SHARE and CORE_NARROW are defined on its basis, and NCELLS is inert
   without it.
2. **V2SHARE, flag `STWO_RV64_M9_SHARED_BINDING`:**
   - port `SharedBindingPlan` into `gkr_local/cpu_components.Plan` (binding index = log group) and into the roles' INTER
     offsets;
   - emit one binding residual per log group that sums the ρ-weighted projections of its components;
   - make the receiver and leaf verifier read one eq/prefix pair per log;
   - extend the NG corpus (swap/zero one component's target);
   - gate: declared INTER == tree=2 words, fresh receiver, byte parity of untouched proofs, and native GPU-s at or below
     ×0.975 on 24628607 [E].
3. **PAD, flag `STWO_RV64_M9_TAIL2`:** a second tail height for `dword`, `sponge.perm`, `alu`, `bulk.set`/`ucopy`,
   `multiplication` and `jalr`. Re-run the planner on the 15 bundles; the target is waste ≤2.5 % of CPU v1 cells.
4. **ZBB:** make `ethereum_services_v3_zbb` the default after the driver and class work, then run the full 15-block
   native census and bench15.
5. **DISPATCH:** an evmone basic-block-check client branch on the guest-efficiency ledger, with exact outputs on all 15
   blocks and EEST. Measure instr/gas, then re-run `native_cells_plan.py` with the measured factor.
6. **CORE_NARROW:** only after a soundness write-up of the derived `enabled` flags.
7. Then re-run `python3 -I scripts/rv64_m9/native_cells.py census` on fresh bundles and `native_cells_plan.py`, and
   replace these [E] factors with [M].

## Files

- `src/integrations/riscv_cpu/build_m9_native_cells.zig`, `rv64_m9_native_cells_main.zig`,
  `word16_global_execution/services/native_gkr/m9_cells_main.zig`: the tool and the prototype (new files only).
- `scripts/rv64_m9/native_cells.py` (`census`, `model`), `scripts/rv64_m9/native_cells_plan.py` (plan variants), and
  `scripts/rv64_m9/plan_model.py` (verbatim rev-4 copy from `codex/rv64-m9-plan`).
- `vectors/reports/rv64-m9-prep/m9-native-cells/`: `blocks.json`, `model.json`, `plan-variants.json`,
  `prefix4-active-rows-24628607.json`, `README.md`.

## 8. Adversarial review corrections (2026-11-07)

The review re-ran the tool on the 16 pod bundles (read-only copies), re-ran the model and plan scripts, and
re-checked the reconciliation against `producer.stderr`. The declaration census and the tree=2 reconciliation
reproduce exactly [M]. Fixed:

1. **v1 missed one binding pair per global-only CPU slot.** The tool gave a v1 pair only to slots with a local
   binding today. `native_roster.cpu` gives every plan slot one, `core.initial`/`core.terminal` included.
   - Before the fix, 24628607 cpu-0 was 16.78 M cells under the M5 exact roster (`24628607-v1-shape.json`).
   - Fixed in the tool and the test. The tool now checks itself against the receiver roster at run time.
   - Effect: v1 128.1 cells/instr (was 126.7), NGKR cells ×0.798 (was ×0.790), V2SHARE cells ×0.959.
2. **V2SHARE GPU-s overclaimed.** Composition and the per-component projection kernels were scaled with committed
   cells. Native GPU-s ×0.979 (was ×0.970).
3. **DISPATCH overclaimed about ×4–5.** The 28.1 instructions per op include the handler bodies. Instructions ×0.967
   central (was ×0.85). The plan's p50 cut with every lever is −48 % (was −52 %).
4. **Stacked guest levers used today's CPU share (0.67).** On the NGKR basis it is 0.77, which `native_cells_plan.py`
   now uses.
5. Wording: one new unit test (36/36 counts the imported modules' tests); the Keccak padding label said 29 rows per
   pair where the code (correctly) uses 27.

Corrected headline: NCELLS native GPU-s ×0.945 central; the best set + NCELLS + ZBB + DISPATCH gives kernel GPU-s
×0.603 (central) of the post-M8 baseline, and walls of −48 % central, −43 % pessimistic and −54/−55 % optimistic
[D/E]. Native work reduction closes about a fifth of the gap to −60 % in log terms, not half.
