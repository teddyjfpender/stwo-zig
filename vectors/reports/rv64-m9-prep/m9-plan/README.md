# m9-plan receipt: gas-weighted targets and the >60% cut budget

Design doc: `design/riscv-proving-stack/rv64-m9-plan.md`. Model: `scripts/rv64_m9/plan_model.py`. Tests: `scripts/tests/test_rv64_m9_plan_model.py`.
No GPU was used. Every number in `model.json` is [D] (fits and arithmetic on receipts) or [E] (scenario model); the inputs
are [M] receipts named in the script.

## Regenerate

```
python3 -I scripts/rv64_m9/plan_model.py --gas-sample <gas_sample.json> --json vectors/reports/rv64-m9-prep/m9-plan/model.json
```

## The raw gas sample (out of git)

- File: `gas_sample.json`, 2,901 rows `[number, gasUsed, gasLimit, txs, ts]`. 2,897 distinct blocks 26,019,159–26,236,159,
  dated 2026-09-20 to 2026-10-20. sha256 `52578c5a916ade03414e899517ae21b0d52c26e0e52b2135fc2e567f30f05544`.
- Kept outside the repo (session scratchpad), as receipt policy requires for raw artifacts. The script embeds its percentiles
  (p5…p99), so it runs without the file; the mainnet-weighted distribution and basket weights in `model.json` need it.

## Contents of `model.json`

- `fits`: bench15-1 kernel GPU-s and warm proving fits, instructions per gas, native GPU-s per M instruction, capture fit.
- `basket`: basket vs mainnet shares above 40 M gas.
- `mainnet`: modelled wall-time distribution over the sample (baseline, all 2-GPU levers, 4 GPUs), basket mainnet weights
  and percentiles.
- `levers`: per block (p50, p95, 26235168, 26235159, 24628607): shape, post-M8 baseline, production baseline, and each lever
  alone and cumulative, for pessimistic, central and optimistic scenarios.
- `basket_totals`: the 15-block total per cumulative step.
- `combos`: minimal 2-GPU lever sets reaching ≥60% on p50, p95 and the basket at once.
- `best_2gpu`: the best 2-GPU lever set per scenario and its minimum cut over p50/p95/basket.

## Review revision (2026-11-07)

`model.json` was regenerated after the adversarial review (design doc §8): per-node recursion fit (`fits.recursion_gpu_s_per_node`),
leaf-only D2 / native-GKR factors, K607 with T2 off (8.333), last-segment Stage 1 at the seal, and three [E] integration costs
(`truth_b16`, `occ_23`, `canon_pad`). Headline: central M9-only −56% (basket); with GPU capture −63%; pessimistic has no 2-GPU set.

## Stream revision r3 (2026-11-07)

`model.json` regenerated with the reviewed prep-stream results (design doc §3): k-leaf fan-in ratios and tree shapes per basket
block (`FANIN_SAME`, codex/rv64-m9-fewer-leaves a056cee67), Poseidon2 scenarios as built / 2-to-1 + x0.6 / engineered
(codex/rv64-m9-poseidon2-leaves 37e581cfc), canonical-leaf held-out tax x1.55 and fold-class misses (codex/rv64-m9-canon-leaf
64a2cb991), packed-ingress exposure 0.46, residual x0.03, decode 0.004 GPU-s per leaf (codex/rv64-m9-packed-ingress 805d1a105).
`truth_b16` and `occ_23` are removed; P2, D2REV and CANON are off the landing order (`levers.*.single` only) but in the search.
Headline: best central 2-GPU set −58% (p50 −59.4, p95 −58.1, basket −58.8); no 2-GPU set reaches 60% centrally; 4 GPUs −73 to −75%.

## Stream revision r4 (2026-11-07, wave 2)

`model.json` regenerated with the reviewed wave-2 streams (design doc §3.2): outer GKR as built `ogkr_alone` (1.28, 1.07, 0.90)
and `ogkr_fanin` (1.35, 1.13, 0.95) off the order, engineered `OGKR_ENG` (0.90, 0.81, 0.78) as #8 (codex/rv64-m9-outer-gkr
a45530dc7); `stream` (0.975, 0.955, 0.90) (codex/rv64-m9-stream-commit 42ce18195); `wit` (0.80, 0.70, 0.55), class hits only in
production (codex/rv64-m9-witness-rowpar 4459242f1); `GPUCAP` bounded by the per-block seeded first pass with services fixed
(`FIRST_PASS`, copied from m9-gpu-replay/first_pass_basket.json) and `REPLAY` (prototype alone, net of tape read-back)
(codex/rv64-m9-gpu-replay 7d9850bab). Headline: no 2-GPU set reaches 60% in any scenario (best central −43%: p50 −43.8,
p95 −42.7, basket −43.2); 4 GPUs with #1–#10 −64.3 / −65.3 / −63.6%, −59.6% on the basket without OGKR_ENG.
