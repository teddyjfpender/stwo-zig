# recsize: M3 recursion version (outer profile m3_b4_q51_p26_fold4 + 4-ary folds)

Source: branch `codex/rv64-m3-recsize`. Host: pod (CPU only, no GPU job run). Test: `zig build test-riscv64-om31-m3-fold -Doptimize=ReleaseFast`
(log: `m3fold-test.log`, parsed: `m3-fold-census.json`). r1 binary control: `test-riscv64-om31-outer` (log `r1-outer-test.log`).

## Fold verifier circuit per node, MEASURED (same synthetic children, child component logs up to 2^20)

| outer profile | arity | vars | padded vars | assignment tasks | levels | Blake G gates | vs r1 binary (vars / tasks) |
|---|---:|---:|---:|---:|---:|---:|---|
| r1 b2/q108/p20 | 2 | 19,127,398 | 22,544,384 | 9,374,531 | 9,025 | 3,769,440 | 1.00 / 1.00 |
| r1 b2/q108/p20 | 4 | 38,252,931 | 45,088,768 | 18,749,526 | 9,025 | 7,538,800 | 2.00 / 2.00 |
| **m3 b4/q51/p26** | 2 | 9,583,278 | 11,272,192 | 4,687,249 | 9,025 | 1,880,960 | **0.50 / 0.50** |
| **m3 b4/q51/p26** | 4 | 19,164,689 | 22,544,384 | 9,374,962 | 9,025 | 3,761,840 | 1.00 / 1.00 |
| m3 b8/q34/p26 | 2 | 6,749,742 | 11,010,048 | 4,512,109 | 9,025 | 1,320,320 | 0.35 / 0.48 |
| m3 b8/q34/p26 | 4 | 13,497,603 | 22,020,096 | 9,024,684 | 9,025 | 2,640,560 | 0.71 / 0.96 |

Per verified child, the m3 b4 fold costs 0.50x r1 in variables, tasks and Blake gates. The 9,025 dependency levels do not
change: children are verified in parallel inside one fold, and the level count is set by one child's verifier
(the transcript chain), not by the number of queries. At b8, padding to a power of two removes most of the extra
saving in padded rows, so b4 is the default m3 profile.

## Whole tree for block 24628607 (17 leaves), DERIVED from the measured per-fold counts

| | r1 | m3 (b4, arity 4) |
|---|---:|---:|
| fold nodes | 16 | 6 (5 x 4-ary + 1 x binary root) |
| fold depth | 5 | 3 |
| child verifications | 32 | 22 |
| fold variables in total | 306.0M | 105.4M (**0.34x**) |

Leaf circuits verify the native q108 proofs, so they are unchanged by this version. Each leaf's own outer proof now
commits at blowup 4, about 2x the LDE/Merkle work per committed cell, measured nowhere yet [E].

## m3 4-ary root, MEASURED (CPU outer prover, synthetic children)
- Fresh receiver (its own trace-only fold graph, PP and authority) accepts: `fresh_receiver_accepted=true`.
- Output tamper rejected; r1 receiver rejects the m3 wire (profile header) and the m3 config; PoW-nonce flip rejected.
- Wrong arity of the same children gives a different digest; a tampered child output makes the 4-ary fold graph unsatisfiable.
- Root wire 389,980 B (r1 binary root of the control test: 705,624 B). CPU prove 401 s, receiver 6.5 s. These are CPU
  backend times and are not representative of the GPU route.

## Not measured
- No GPU recursion run at m3. The infra READY/RECIPE was not published during this window. GPU b4 outer commits (non-`separate`
  composition n2b path, device memory at 2x LDE) are unqualified.
- No real-block recursion wall at m3. No real leaf/fold circuits from block 24628607 were built under m3.
