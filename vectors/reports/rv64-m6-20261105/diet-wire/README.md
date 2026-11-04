# diet-wire receipts (M6, 2026-11-05)

Stream diet-wire, branch `codex/rv64-m6-diet-wire`. Argument and full tables: `design/riscv-proving-stack/rv64-m6-diet-wire.md`.
All timings are single observations on a shared, loaded pod (1-min load 8–53; the protocol's quiet bar is 8): A/B pairs are
interleaved runs, absolute seconds are not quotable. `committed_cells` = measured per-node row logs × component widths [D].

| file | what |
|---|---|
| `*-k2-ab1.json`, `*-k3-ab1.json` | M5 integrate binaries, r1 with `STWO_RV64_FOLD_ARITY=2/3` (k2 = M5 default root) |
| `26235156-k4-r1-oom.log` | 4-ary r1 fold: blake_g_gate 8,680,080 rows → 2^24, `CudaAllocationFailed` |
| `26235156-k3-q51-oom.log` | `m3_b4_q51_p26` (k = 3): interaction LDE 5.93 G words, `GPU_TRACE_ALLOCATION_FAILURE tree=2` |
| `*-k3-p1.json` | named profile `m6_outer_diet_k3_r1_b2_q108_p20_fold4_v1` (this branch's driver/receiver) |
| `*-k4c-p1/p2/p3.json` | named profile `m6_outer_diet_k4_cap3_r1_b2_q108_p20_fold4_v1` (4-ary + Merkle cap 3 in folds) |
| `*-r1-p2/p3.json` | r1 control on the same binaries, interleaved |
| `*-corpus.json` | profiles' negative corpus v3, full-tree receiver, fresh process per case: 42/42 on every run |
| `26235156-cross-profile-rejects.log` | DW07 + arity-override cases: all rejected, control accepted |
| `k4c-p1-rootonly-blocked.log` | root-only `derive-vk-tables`: `VkDeriveLeafCoverage` on k-ary trees (fold-v3 owns root_verify) |
| `*.sh`, `req.py` | the pod scripts that produced these |

Headline [M] (24628607, r1 → k4-cap3, three interleaved pairs): nodes 33 → 23, committed recursion cells 51.6 → 35.8 G [D],
recursion device-stage 29.4–32.1 → 21.6–22.2 GPU-s, recursion stage wall 21.4–26.2 → 20.2–21.8 s (within load noise:
recursion is host-gated today), full-tree receiver 66–82 → 50–61 s, root proof 706,424 → 708,696 B, device peak 31.5 GB both.

## Final gate pair at branch head 5d0bf8660 (`*-p5.json`, driver a82188a3, receiver 070ee066, load 13-21) [M]

| block | profile | nodes | cells [D] | recursion | device-stage GPU-s | root | receiver | device peak |
|---|---|---:|---:|---:|---:|---:|---|---:|
| 26235156 | r1 (default, root = M5 default b424203b) | 21 | 32.70 G | 14.86 s | 19.14 | 748,536 | accepted 42.8 s | 31.5 GB |
| 26235156 | k4-cap3 | 15 | 24.06 G | 13.32 s | 14.82 | 750,136 | accepted 35.3 s | 31.5 GB |
| 24628607 | r1 (default, root = M5 default 2feed86a) | 33 | 51.62 G | 20.40 s | 27.89 | 706,424 | accepted 63.5 s | 31.5 GB |
| 24628607 | k4-cap3 | 23 | 35.79 G | 20.15 s | 21.64 | 708,696 | accepted 52.3 s | 31.5 GB |
