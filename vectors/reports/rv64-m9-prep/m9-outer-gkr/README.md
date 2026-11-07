# rv64-m9-prep / m9-outer-gkr receipts

The design and verdict are in `design/riscv-proving-stack/rv64-m9-outer-gkr.md`. CPU only: no GPU or pod was used, and no raw artifacts were produced.

- `factor.json` [D/E]: the re-derived outer-GKR factor on the three focus blocks (24628607, 26235168, 26235159). It covers both trees (post-M8 baseline and k-leaf fan-in) and five cases, with per-node rows, cells, GKR facts, GPU-s, workspace, the soundness ledger and proof bytes. Produce it with `python3 scripts/rv64_m9/outer_gkr_factor.py --out .../factor.json`, using `gates.json` or `--tool`.
- `factor-basket.json` [D/E]: the same model for all 15 basket blocks, with basket totals (node lists only for the focus blocks).
- `gates.json` [D]: in-circuit outer-GKR verifier gate counts per child class, keyed by padded row logs. Each count comes from `rv64-m9-outer-gkr-tool cost-raw` (the circuit code on a shape-exact section).
- `verifier-cost.json` [D vs M]: a shape-only cost cross-check against the M5 GPU-section counts. It matches exactly for leaf-cpu-24628607 and fold-24628607 at L = 27. The file also holds the real D2 CPU leaf class at v1 and v2.
- `node-rounds.json` [M, CPU]: the end-to-end node round on the real D2 CPU leaf roster at row logs −8, −6, −4 and −3. The −3 round has 17.2 M fractions, 1/8 of the real leaf. Every check passes.
- `review.json` [D/E]: the adversarial review (`scripts/rv64_m9/outer_gkr_review.py`). It holds the r_k fit error and leave-one-out band, the factor and break-even across that band, the free-GKR floor, the binding-pass sensitivity and the 2-GPU makespan at GKR wall 0.82 and 1.58 ns/fact. See design §10.
- `tests.json` [M]: Zig 6/6 and Python 3/3, with source SHA-256s.

Headline (central): cells ×0.56–0.63, but recursion kernel GPU-s ×1.07–1.15 [D/E]. **As built, outer GKR does not save GPU-s.** The review (§10) finds the loss within the r_k fit error: ×1.04–1.17 LOO, break-even at r_k +1σ. The critical-path wall is ×0.89–1.19, and ×0.57 is unreachable even with a free GKR (floor ×0.65). Break-even is 0.55–0.68 ns/fact, against a measured 0.575 (materialised) or 0.82 (with projection) ns/fact.
