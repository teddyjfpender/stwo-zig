# rv64-m9-prep / canon-leaf receipts

Stream m9-canon-leaf (branch codex/rv64-m9-canon-leaf). Design: design/riscv-proving-stack/rv64-m9-canon-leaf.md.

| file | label | what |
|---|---|---|
| segment-shapes-15.json | M | the 579 leaf declarations (347 CPU, 232 truth) of the 15 accepted M3 2-GPU basket bundles, copied read-only from the pod (`/workspace/m3/runs/integrate/<block>-2gpu-scale/.../proof/bundle.json`; 25229951 from `-2gpu-diag-idle0`) |
| catalog-r4.json | D | `scripts/rv64_m9_canon_leaf_catalog.py --rungs 4`: exact classes, frozen v1 strict misses, R=1..8 sweep incl. leave-one-block-out, different-blocks service simulation, per-block taxes |
| catalog-r8.json | D | same with `--rungs 8` (recommended R) |

Commands (CPU only; no GPU was used by this stream):

    python3 -I scripts/rv64_m9_canon_leaf_catalog.py --shapes vectors/reports/rv64-m9-prep/canon-leaf/segment-shapes-15.json \
        --widths vectors/reports/rv64-m5-20261104/canon-native/widths-gkr-v3.json \
        --out vectors/reports/rv64-m9-prep/canon-leaf/catalog-r4.json --rungs 4 \
        --zig src/integrations/riscv_cpu/rv64_recursion/canon_leaf_catalog.zig
    ~/Coding/ge-ops/bin/memguard run --gb 6 -- zig build test-riscv64-m9-canon-leaf -Doptimize=ReleaseSafe

Test run [M] (2026-11-07, macOS host, zig 0.15.2, ReleaseSafe): `Build Summary: 2/2 steps succeeded`, suite minimum 6 tests,
each of the 6 test names selected individually with `-Driscv-test-filter` (a non-matching filter fails the guard), stderr line
`RV64_M9_CANON_LEAF leaves=579 exact_classes=389 catalog=72 used=53 misses=0`.
