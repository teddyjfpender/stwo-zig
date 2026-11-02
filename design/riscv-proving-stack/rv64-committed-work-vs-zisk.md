# RV64 Word16 vs ZisK: committed work per Ethereum block

Status: observation and estimate, 2026-11-01. No proving was run; every number
comes from existing receipts, proof files or public source. Receipt:
`vectors/reports/rv64-ethereum-20261101/committed-work-comparison-v1.json`.
Harness: `scripts/rv64_committed_work_report.py` (run with `python3 -I`).

## Headline (committed witness bits at the LDE, fixed trees excluded)

| | ours (block 24,628,607) | ZisK (block 25,701,329) |
|---|---|---|
| field / cell | M31, 31 bit | Goldilocks, 64 bit |
| blowup | 2 (log 1) | 2 |
| gas used | 7,372,614 | 59,982,888 |
| instructions / steps | 104,253,913 RV64 retirements | ~242.6 M steps (16.5 G / 68; inferred) |
| main (stage 1) | 634.3 Gbit | 3,859.6 Gbit |
| interaction (stage 2) | 538.2 Gbit | 1,698.5 Gbit |
| composition / quotient | 52.9 Gbit | 150.7 Gbit |
| **total per block** | **1,225.5 Gbit** | **5,708.8 Gbit** |
| per instruction or step: main / inter / quot | 6,084 / 5,163 / 508 | 15,906 / 7,000 / 621 |
| **per instruction or step: total** | **11,755 bit** | **23,527 bit** |
| per gas: main / inter / quot | 86,034 / 73,005 / 7,178 | 64,345 / 28,316 / 2,513 |
| **per gas: total** | **166,218 bit** | **95,174 bit** |

Ratios, ZisK over ours: 2.00x per instruction or step, 0.57x per gas, 4.66x per
block.

Ours with fixed trees included: 1,313.8 Gbit LDE (fixed is 88.3 Gbit). In the
trace domain it is 21.19 G cells: 20,336,488,256 trace cells (the qualified
figure) plus 853.6 M composition cells.

## Read this before using the numbers

1. **Different blocks.** ZisK's block uses 8.1x the gas, and its per-gas
   advantage partly reflects its mix: 47% of its area is the Keccak precompile.
   Per-instruction and per-gas point in opposite directions. The honest
   statement is: per retired instruction we commit about half the bits; per
   gas we commit about 1.75x more on a light, non-keccak-dominated block.
   Matching the block is the next step: run ZisK area on 24,628,607, or our
   prover on 25,701,329.
2. **Different security.** Ours is q70 + 26 PoW at blowup 2, nominally 96-bit
   and conjectured, and not qualified for 128-bit
   (`rv64-word16-execution-20261101/security-policy-v1.json`). ZisK targets
   128-bit in the proven regime, using a setup-time query solver, BLAKE3 and
   24 grinding bits. Committed cells do not depend on the query count, but
   reaching equal security would change our blowup and/or queries. A larger
   blowup scales the LDE columns of this table directly.
3. **Commitment bits are not the whole cost.** This excludes FFT/LDE,
   constraint evaluation, the DEEP/FRI quotient, PoW (ours: 30 x 2^26 ≈ 2.0 G
   expected hashes), openings, witness generation, and all recursion and
   aggregation. Hash work is reported separately for ours: 5.73 G Blake2s
   compressions per block, about 55 per instruction.
4. **Units differ.** An RV64 retirement and a ZisK step are not the same unit.
   ZisK steps are transpiled ops, and precompile work sits outside the step
   count; ours handles keccak and secp through truth proofs, which are counted
   in our totals.

## Part A: ours, what is measured and how

Inputs: the LS32 qualified complete-block run
`/tmp/rv64-ls32-qualified-complete-v1`. Its `cost.json` is byte-identical to
the committed `vectors/reports/rv64-ls32-qualified-20261101/complete-cost.json`.
The run has 25 CPU and 5 truth proofs, plus `roster.json`, `report.json`,
`bundle.json`, 30 stage profiles, and 30 `STWOPRW1` proof files.

- **Trace cells (measured).** `cost.json` columns and native cells per tree
  (fixed / main / interaction) come from `telemetry.zig:measure`, which sums
  `2^log` per base column. Interaction QM31 columns are already split into 4
  coordinates. The script checks that interaction widths are multiples of 4,
  and that the proof wire's per-tree column counts equal the cost.json widths
  for all 30 proofs. Total: 20,336,488,256 cells (the qualified figure).
- **Composition (measured plus derived).** The proof's fourth tree has 8
  columns for CPU proofs (split 1) and 16 for truth proofs (split 2). Each
  column has 2^D rows, with D = 1 + fold_step·inner_layers + log_last_layer
  from the proof. The script checks that D equals the largest trace log.
- **PCS / FRI (measured from proof headers).** pow 26, log_blowup 1, last
  layer 0, 70 queries, fold 1, no lifting override. FRI commits D layers per
  proof (the first layer on the circle domain 2^(D+1), then line layers):
  22 / 18 / 17 / 12 layers depending on height.
- **Openings (measured).** 73,140 sampled QM31 OODS values, 3,968,580
  queried M31 values, 126,416 PCS hash witnesses, 31,604 FRI witness QM31,
  231,235 FRI hash witnesses. Proof bytes: 29,481,608.
- **Merkle hashing (derived).** This uses the counter-qualified prefixed
  Blake2s ledger (`services/hash_accounting_test.zig`, and the receipt
  `rv64-word16-execution-20261031/mixed-height-hash-accounting-v1.json`; the
  script reproduces its three trees exactly as a self-test). Leaf
  compressions are Σ_g (⌈cum/16⌉ − ⌈prev/16⌉)·2^(log_g+1), plus 2^(max+1)
  finals, with columns sorted by ascending height. Parents are 2^(max+1) − 1.
  CPU histograms come from `roster.json` and are exact; the roster is
  cross-checked against cost.json per tree. Truth proofs have no histogram:
  their non-final leaf work is the all-at-max upper bound scaled by
  native/lifted density, and both values are reported (the upper bound is +1.6% on
  truth non-final leaves, +0.1% of all block compressions). FRI layers use the same hasher with one QM31 per leaf, since
  fold 1 means no packing (assumed: same `B.MerkleTree(H)` as the PCS).
- **Validation.** On the complete-block run directory: exact cell match, 30
  proofs parsed to end-of-buffer, 30 stage profiles. In receipt-only mode on
  `complete-cost.json`: same trace cells, with composition assumed at 8
  columns (−0.9% composition). On the prefix run
  `/private/tmp/stwo-rv64-perf-runs/perf2-baseline-prefix4` (schema 5, 4 CPU +
  3 truth, 16,777,212 instructions): 11,798 LDE bit per instruction including
  fixed, against 12,602 for the complete block, which carries more keccak and
  secp truth work.

## Part B: ZisK, what is derived and what is inferred

Sources, read only: zisk @64a1f166, pil2-proofman (setup and std), and
ziskethone @1c3e8d1 `docs/perf-notes.md`.

- **What "area" is (derived).** `core/src/zisk_ops_costs.rs:10-14` says "Area
  is the total number of columns of the air (SUMMARY Total in
  build/setup.log)", and each op costs ⌈Total / ops-per-row⌉. In the proofman
  setup (`pil/info.rs`), Total = stage-1 + stage-2 + quotient base columns,
  with fixed excluded. MAIN_COST = ⌈245/4⌉ = 62 at this commit
  (`emulator/src/emu_costs.rs:34`); the notes used an older 68. Block area is
  therefore committed trace-domain Goldilocks base cells for stage 1, stage 2
  and quotient, without padding to 2^N instance rows and without fixed or
  blowup. So 44.6 G area ≈ 44.6 G committed cells ≈ 2.85 Tbit in the trace
  domain, or 5.71 Tbit at blowup 2.
- **Quotient (derived).** Blowup 2 caps the constraint degree at 3, so Q is 2
  cubic-extension columns = 6 base columns. This is confirmed for Keccakf by
  `precompiles/keccakf/pil/NUMBERS.md` (615 = 467 + 142 + 6) and assumed for
  the other AIRs; stage-2 + Q is invariant to that choice.
- **Stage 2 (derived rule, inferred per-AIR counts).** From `std_sum.pil`
  with max degree 3: one gsum extension column, plus about ⌈(T−1)/2⌉ `im`
  extension columns for T bus terms, plus any compiler imPols. Per-AIR
  stage-2 is taken as Total − stage-1 − 6, not recounted.
- **Per-AIR ratios (derived).**

  | AIR | stage 1 | stage 2 | Q | Total |
  |---|---|---|---|---|
  | Main | 152 | 87 | 6 | 245 |
  | Keccakf | 467 | 142 | 6 | 615 |

  The MEMORY mix (75% Mem / 25% MemAlign family) and the OPCODES mix
  (Binary / BinaryAdd / BinaryExtension / Arith) are **inferred weights**.
- **Block split (inferred).** MAIN 16.5 G, keccak 20.8 G, MEMORY 4.2 G and
  OPCODES 3.5 G give stage-1 / stage-2 / quotient fractions of
  67.6% / 29.8% / 2.6%. These are applied to the stated 44.6 G total (the
  parts sum to 45.0 G). Fixed is about 0.33 G cells, committed at setup.
- **Steps (inferred).** 16.5 G / 68 = 242.6 M steps. The same notes also
  give 234.8 M self steps for evmone, so the steps figure carries ±3%.
- **Gas.** 59,982,888 from etherscan (not in any repo).
- **Not modelled for ZisK.** Hash counts, openings, query count (solved at
  setup), and the BASE rom/table instances (about 0.285 G cells).

## Next measurements that would tighten this

- Run ZisK's emulator area on block 24,628,607, or our harness on a
  25,701,329 run. That removes the block mismatch, which is the largest
  confounder.
- Fix the security profile on both sides (128-bit, same regime) and redo the
  LDE column, the queries and the hash counts.
- Record per-height histograms for truth proofs in `cost.json`, so truth hash
  counts become exact.
