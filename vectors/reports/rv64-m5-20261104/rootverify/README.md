# M5 rootverify receipts (2026-11-04)

Receiver `48ba61f968bf…` (this branch). Proofs come from the M4 integrate binaries (format unchanged), proved once per
dev block into `/workspace/m3/runs/m5-rootverify/*-m4base`. Every run is a single observation at pod load 13–40, which is
**not quiet**, so none of these rows enters the best-so-far table. Note: `design/riscv-proving-stack/rv64-m5-rootverify.md`.

| block | M4 receiver, full tree [M] | `--audit` [M] | **root-only verify per block** [M] | root proof verify | derive once [M] | corpus |
|---|---:|---:|---:|---:|---:|---|
| 26235156 | 43.2 s | 46.0 s | **10.1 / 10.1 s** | 12 ms | 39.2 s | 51/51 |
| 24628607 | 63.7 s | 57.8 s | **14.6 / 14.9 s** | 12 ms | 52.4 s | 51/51 |

- **Root-only vs today's full tree:** ×4.3 on 26235156 and ×4.4 on 24628607 [D].
- **Gate ≤ 1.5 s: not met.** On 607, 13.2 s of the 14.6 s is native setup (native keys 8.2 s, native FIXED authority
  5.0 s), which today's receiver-side admission still needs. M5 removes it: T_nat entries plus in-circuit admission.
- **`--audit` agrees** with root-only on both blocks: same root digest, same root authority.

Files:
- `<block>-rootonly.json`: receipt, with the root-only runs and their breakdown, audit, baseline, derive and corpus summary.
- `<block>-rootonly-corpus.json`: corpus receipt.
- `vk-table-dev-blocks.json`: the receiver table, profile `rv64-m4-fold-v2-compat/v0`, 27 leaf and 11 fold classes,
  40 KB. It is bound to receiver sha `48ba61f9…`.
