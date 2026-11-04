# M5 rootverify receipts (2026-11-04)

Receiver `f5f7ec5e5ff2…` (this branch, round 2; round 1 `48ba61f9…` gave the same picture at higher load). Proofs come from the M4 integrate binaries (format unchanged), proved once per
dev block into `/workspace/m3/runs/m5-rootverify/*-m4base`. Every run is a single observation at pod load 13–40, which is
**not quiet**, so none of these rows enters the best-so-far table. Note: `design/riscv-proving-stack/rv64-m5-rootverify.md`.

| block | M4 receiver, full tree [M] | `--audit` [M] | **root-only verify per block** [M] | root proof verify | derive once [M] | corpus |
|---|---:|---:|---:|---:|---:|---|
| 26235156 | 43.2 s | 41.3 s | **10.6 / 10.0 s** | 12 ms | 41.1 s | 51/51 rootverify, 40/40 profiles v3 m5-root |
| 24628607 | 63.7 s | 55.4 s | **14.4 / 14.0 s** | 12 ms | 52.7 s | 51/51 rootverify, 40/40 profiles v3 m5-root |

- **Root-only vs today's full tree:** ×4.1–4.3 on 26235156 and ×4.4–4.5 on 24628607 [D].
- **Gate ≤ 1.5 s: not met.** On 607, 13.2 s of the 14.6 s is native setup (native keys 8.2 s, native FIXED authority
  5.0 s), which today's receiver-side admission still needs. M5 removes it: T_nat entries plus in-circuit admission.
- **`--audit` agrees** with root-only on both blocks: same root digest, same root authority.

Files:
- `<block>-rootonly.json`: receipt, with the root-only runs and their breakdown, audit, baseline, derive and corpus summary.
- `<block>-rootonly-corpus.json`: corpus receipt (`scripts/rv64_m5_rootverify_corpus.py`, includes the RV table/profile cases).
- `<block>-profiles-corpus-v3-m5root.json`: profiles' corpus v3 (`origin/codex/rv64-m5-profiles` @ `59d251205`) run with
  `--format m5-root` against this receiver. Its C00 control compares the root-only statement (output, root digest, root
  authority, manifest, profiles) with the **M4 full-tree receiver's** statement: they are equal on both blocks.
- A stale table (derived by round-1 receiver `48ba61f9`) offered to round-2 `f5f7ec5e` is refused: `VkTableNotDerivedByThisReceiver`.
- `vk-table-dev-blocks.json`: the receiver table, profile `rv64-m4-fold-v2-compat/v0`, 27 leaf and 11 fold classes,
  40 KB. It is bound to receiver sha `f5f7ec5e…`.

Reproduce on the pod (CPU only): `repro/round2.sh`. It runs the stale-table check, then `repro/rv_go.sh all` (derive ×3,
root-only ×2 per block, `--audit` per block), then both corpora per block. `repro/rv_receipt.py` assembles the receipts.
