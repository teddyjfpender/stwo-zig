# rootverify adversarial review 1 (2026-11-04, of d562c78f9)

All runs: pod, CPU only, no GPU lock. Proofs unchanged (M4 binaries, `/workspace/m3/runs/m5-rootverify/*-m4base`). Single observations at load 16-28 (above the quiet bar of 8).

- `adv-f5f7ec5e.log` [M], against the ORIGINAL receiver f5f7ec5e: A1-stale is refused (VkTableNotDerivedByThisReceiver). **A1-relabel is accepted**: the same stale table with only `header.receiver_sha256` edited, and no reseal. **A3-sibling is accepted**: a table in the producer run tree next to `proof/`.
- Fix commit 508d339be built receiver 6c98e28d…: `pipe.log`. Unit tests pass (`test-riscv64-m5-rootverify`, 2/2 steps). Derive on both blocks plus merge succeeds, and the self-check passes. Root-only is accepted unpinned and pinned (`verify*.json`; 26235156 9.46 / 9.52 s, 24628607 13.93 / 13.56 s). A1-relabel of the v0 table is now refused (`VkTableRootMismatch`).
- Corpus `*-rootonly-corpus-review.json`: **59/59 on both blocks** (the 51 previous cases plus RV16-RV23). 42/42 must-reject cases are rejected, with no crashes and no unexpected accepts. RV19/RV20/RV23 (re-sealed tamper/relabel with the pin) are refused with `VkTableRootPinMismatch`. RV21/RV22 (unpinned re-sealed relabel, producer-tree table) are accepted with the control statement. That acceptance is the documented self-declared behaviour.
- `vk-table-dev-blocks-root-v1.json`: the table bound to receiver 6c98e28d. Its pin is `30dd14175aefc31614e7dce6a7a77915257cc6984d5fd17a31bfc9390cbd2556`.
- Repro: `repro/adv.sh`, `repro/pipe.sh`.
