# Canonical typed RISC-V public surface qualification

The consolidated typed/native RISC-V and detached recursion route passes on the
source recorded in `qualified-source-snapshot.json`, including the shared
polynomial compiler, build-factory extraction and reviewed package declarations.

- CPU/Metal/AOT complete four-segment proofs: 384 acceptance/rejection checks,
  all 21 artifacts identical to the canonical baseline.
- Same-source/binary 1/2/4/8 continuation: 1,110 checks, 78 baseline-identical
  artifacts, authenticated continuation and standalone roots.
- Fresh root-only measurements for all eight backend/rung pairs verify without
  native inputs or execution replay. The eight-segment root is 2,297,319 bytes.
- Native table and typed leaf/parent Metal interaction dispatches remain required.
- All 103 focused package/build/ownership checks passed before the source freeze.
- Clean temporary-index patch replay reproduces all 6,189 source hashes without
  modifying the user index. All 114 archived pinned inputs match current files.

`summary.json`, per-backend product reports and ladder summaries retain exact
results. `source.patch.gz` applies to the base HEAD in `source-replay.json`.
The pinned-input archive is inherited from the preceding checkpoint and rechecked
byte-for-byte; inspect `pinned-inputs-recheck.json` before extraction.

The first orchestration completed both products, then stopped before any ladder
case because its temporary launcher referenced the previous output directory.
Only that external path was corrected. The continuation resumed with the already
qualified binaries; no source changed and neither complete product was rebuilt.
Both initial and resumed logs are retained.

Run from the qualified source with Zig 0.15.2:

```sh
python3 scripts/riscv_recursive_product.py --backend cpu --output /tmp/typed-cpu-new
python3 scripts/riscv_recursive_product.py --backend metal --output /tmp/typed-metal-new
```

The Metal command requires the physical-Mac Xcode Metal toolchain. This remains
a development q193, hybrid-Metal profile. Production security and strict GPU
coverage are not claimed. Timing/RSS observations are retained in
`ladder-measurements.json`; they are not a speed improvement claim.

The typed/native recursion implementation milestone is qualified. The original
broader baseline goal remains open: repository source-size findings and Linux
artifact-store qualification are unresolved. An isolated publication identity
regression and candidate fix are recorded in
`../artifact-publication-reproduction-v1`; the candidate is not part of this
qualified source. Report documentation and the goal/guide updates were written
after the source freeze.
