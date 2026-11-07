# rv64-m9-prep / m9-segment-shape receipts

- `model.json`: output of `python3 -I scripts/rv64_m9/segment_shape_model.py --gas-sample gas_sample.json --json model.json`,
  with schema `rv64-m9-segment-shape/v1`. Labels: [M] measured, [D] derived, [E] estimate. It contains:
  - `fits`: per-segment native job ms vs cells, the bench15 kernel fits, and the 15-block recursion and native wall fits;
  - `per_segment`: the GPU-s of one full 2^22 segment, split into native, leaf and fold share;
  - `shapes`: recursion cell ratio, leaves, folds, depth and native factor at 2^22, 2^23 and 2^24, with no fan-in,
    truth-only fan-in or full fan-in, under pess/central/opt. It covers the 15 basket blocks and the synthetic p50/p95;
  - `memory`: per-job peaks and the per-GPU arena left, today and post-P1;
  - `tail`: the near-empty last segment, and `near_empty_last_segment_share`;
  - `plan`: wall and kernel GPU-s from `plan_model.py` for baseline, `SEG23`, `SEG24`, `LEAVES` and the rev-4 best sets
    with and without `SEG23`, plus the best-set search including `SEG23`.
- Gas sample: `gas_sample.json` (2,901 rows, 2,897 unique blocks; it stays out of git), sha256
  `52578c5a916ade03414e899517ae21b0d52c26e0e52b2135fc2e567f30f05544`.
- Tests [M, CPU]:
  - `python3 -I scripts/tests/test_rv64_m9_segment_shape_model.py`: 10/10 OK (3 added by the 2026-11-07 review);
  - `python3 -I scripts/tests/test_rv64_m9_plan_model.py`: the rev-4 tests, 16/16 OK with the new levers present.
- No GPU was used. Neither dev pod had `/workspace/m3/READY-DEV` on 2026-11-07, and the main 2x5090 belongs to
  GPU-native. No raw artifacts were produced.

Design and numbers: `design/riscv-proving-stack/rv64-m9-segment-shape.md` (review findings and corrected headline: §8).
The receipt was regenerated after the review fixes (central SEG23 kernel ×0.877 after rev-4, p50 9.79 s).
