# Typed RISC-V and detached recursion cleanup qualified

The frozen source passed the canonical CPU/Metal/AOT complete-proof command and
useful 16-address 1/2/4/8 continuation ladder. This checkpoint includes the
artifact-store atomic publication fix, shared recursion/interaction ownership
cleanups, typed session retirement cleanup and retirement of four unused
binary-parent experiment exports.

- CPU and Metal four-segment products: 384 acceptance/rejection checks and all
  21 compared artifacts identical to the pinned baseline.
- CPU and Metal 1/2/4/8 continuation: 1,110 checks and 78 baseline-identical
  artifacts; includes authenticated continuation and statement substitutions.
- Eight fresh root-only processes verify without native inputs or execution replay.
- Metal native table, typed leaf and typed parent dispatch requirements pass.
- Before freeze: 66 ownership/isolation/package checks passed; integration build
  graph constructed. The affected execution-session gate passed 31 tests.
- Source stayed unchanged through all builds, proofs and root measurements.
  Patch replay reproduces 6,201 source files without modifying the user index.
- All 114 pinned inputs and archived input contents were checked byte-for-byte.

The eight-segment root is 2,297,319 bytes. Root verification was approximately
70 ms and fresh-process peak RSS was 15,450,112 bytes on both backends.
Production took 153.14 seconds on CPU and 115.28 seconds on Metal in these
individual observations. These are checkpoint measurements, not a speed claim.
See `ladder-measurements.json` for every rung and verification economics.

`summary.json`, backend summaries and `ladder-summary.json` record the results.
`qualified-source-snapshot.json`, `source-replay.json` and `source.patch.gz`
identify the qualified source; `source-changes.json` compares the preceding
checkpoint. The archived scripts retain orchestration and evidence collection.
All qualification processes exited successfully; no source rebuild was restarted.

Reproduce the complete products from qualified source using Zig 0.15.2 and new
output directories:

```sh
python3 scripts/riscv_recursive_product.py --backend cpu --output /tmp/typed-cpu-new
python3 scripts/riscv_recursive_product.py --backend metal --output /tmp/typed-metal-new
```

This qualifies the canonical typed/native recursion cleanup milestone. The
original broader baseline goal remains open: 106 source-size findings and Linux
runtime qualification of the artifact-store publication repair. The admitted
q193 profile is developmental and Metal execution is hybrid; production security
and strict GPU execution are not claimed. Documentation updates linking this
checkpoint follow the source freeze and do not change its implementation.
