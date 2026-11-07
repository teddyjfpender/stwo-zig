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
