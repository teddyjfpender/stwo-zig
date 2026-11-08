# m9-native-cells receipts (2026-11-07)

Design note: `design/riscv-proving-stack/rv64-m9-native-cells.md`. Labels: [M] measured, [D] derived, [E] estimate.

| file | what | label |
|---|---|---|
| `blocks.json` | per block (15 basket + current 24628607): per native proof MAIN / INTER cells and columns for today, logup3, v1, v2share; per component aggregates; keccak padding | M (declaration census of produced proofs) |
| `prefix4-active-rows-24628607.json` | exact active rows per CPU component of a freshly verified 4-packet prefix of 24628607 (class mix, padding) | M |
| `model.json` | basket budget per component and instruction class, padding, lever table with native GPU-s factors, guest factors | M / D / E |
| `plan-variants.json` | plan_model rev 4 + NCELLS / ZBB / DISPATCH: p50 / p95 / basket walls and cuts, pess / central / opt | D / E |

Reproduce:

```
# tool (new build file; no build.zig edit), ~130 MB cache
cd src/integrations/riscv_cpu
zig build --build-file build_m9_native_cells.zig m9-native-cells test-m9-native-cells -Doptimize=ReleaseSafe --prefix OUT
# inputs: pod bundles (read-only)
#   /workspace/m3/runs/integrate/<block>-2gpu-{scale,cold1,diag-*}/case/batch/trial-0/<block>/proof/bundle.json
#   /workspace/m3/runs/m8-census2/daemon-24628607-r2-c2-24628607-00-baseline/spool/out/0000-24628607/24628607/proof/bundle.json
for f in bundles/**/bundle.json; do OUT/bin/rv64-m9-native-cells $f 18 > cells/<tag>-<block>.json; done
python3 -I scripts/rv64_m9/native_cells.py census --cells-dir cells
python3 -I scripts/rv64_m9/native_cells.py model --json vectors/reports/rv64-m9-prep/m9-native-cells/model.json
python3 -I scripts/rv64_m9/native_cells_plan.py --json vectors/reports/rv64-m9-prep/m9-native-cells/plan-variants.json
```

Reconciliation [M]: for the current 24628607 request, declared INTER of the 14 native proofs equals the measured
`GPU_TRACE_OWNERSHIP tree=2 coefficient_words` of `m8-census2/.../producer.stderr` exactly. The raw tool outputs (6.7 MB)
are not in git.

Review (2026-11-07, design note §8): receipts regenerated after two fixes. (1) v1/v2share now give every plan slot
a binding pair, as `native_roster.cpu` does (the tool checks this at run time; v1 equals the M5 exact
`<block>-v1-shape.json` proof for proof on 24628607 and 26235156). (2) The V2SHARE GPU-s, DISPATCH and stacked
CPU-share factors were corrected in `native_cells.py`. Bundle copies were named `scale-<block>.json`,
`diag-idle0-25229951.json` and `m8-census2-24628607.json`; the census picks by those tags.
