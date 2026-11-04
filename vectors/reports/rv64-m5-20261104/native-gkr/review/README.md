# native-gkr v1 adversarial review (head 48f38757b, 2026-11-04)

Pod, ReleaseSafe, CPU only (no GPU). Synthetic fractions on the real v1 rosters (census of the dev blocks), as in `../realshape/`.

- `test-15.log`: `zig build test-riscv64-native-gkr`, 15/15 tests (the suite guard now requires 15). Adds adversarial A1 and A3-A6 (design note §9).
- `shape-156.json`, `shape-607.json`: v1 shapes re-derived with the strict relation mapping (A2). Identical to `../<block>-v1-shape.json`.
- 26235156 completeness, fresh-process receiver (`156-<proof>.{prove,verify}.{json,time}`): truth-1, truth-3, truth-5, truth-6 and
  cpu-1 (59 instances, 122.7 M fractions) all accepted. cpu-1: CPU reference prove 73.1 s (11.4 GiB peak RSS), verify 88.4 s with the
  binding recompute (4.5 GiB), pod load 10-19. Single observation.
- Tier R corpus, one fresh receiver process per case: truth-6 every word 4,753/4,753, truth-5 every word 3,393/3,393.
  cpu-1 sampled 25/25 (`corpus-156-cpu-1.json`, includes cross-proof substitution of truth-3).
