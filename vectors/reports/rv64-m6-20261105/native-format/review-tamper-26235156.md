# Adversarial review of rv64-m6-native/v2 (v2-strict), 26235156 [M]

Review of `codex/rv64-m6-native-format` @ 902284701 (receiver b4 `001bf1d9`, built from 715aa3f9e; later commits change only
tests, docs, scripts and vectors). Fresh, separate, cache-disabled, GPU-disabled receivers with
`STWO_RV64_NATIVE_VERSION=m6-native-v2-strict`. Base: the accepted pair `/workspace/m3/runs/m6-native-format/26235156-2gpu-v2s-r5`
(the donor is `24628607-2gpu-v2s-r6`). Script `scripts/rv64_m6_native_v2_tamper.py`. Pod load 17-23, single observations.

- **15/15 as expected. No unexpected accepts, no crashes.** The table is in `design/riscv-proving-stack/rv64-m6-native-v2.md` sec. 6.
- The deep rejections:
  - an admissible rung relabel (NVT02b, rung 1 -> 2, with present-empty curve bridges) -> `GlobalGkrManifestExecution`;
  - activating a present-empty instance (NVT05) -> `InvalidSumcheck`;
  - non-zero claims on present-empty instances (NVT06/07) -> `OodsNotMatching`;
  - a same-class cross-block segment replay (NVT09/09b) -> span/geometry admission;
  - same-class segment and truth swaps (NVT10/11) -> adjacency / physical root.
- Completeness: a fresh v2 receiver accepted 24628607 (setup 10.76 s, native verify 1.62 s, recursion verify 61.6 s, load ~20).
  NVT00 accepted 26235156 (49.1 s wall).
- Open: v2-strict is not total (no `cpu_single` rungs; the `cpu_last` rungs carry only cpu_log 20-22). See note sec. 6, finding 2.
