# Resident OM31 composition finalization

The device composition accumulator has eight coordinate-major M31 columns.
The native PCS commits composition coefficients in recursive chunk-major,
coordinate-minor order. The qualified finalization operation interpolates the
accumulator in place and writes that exact order directly to a disjoint slab,
with no intermediate readback or allocation.

The implementation reuses the existing staged/fused B2N transforms, extending
their compile-time coordinate count from four to eight. Existing four-coordinate
entry points and output ordering remain unchanged. Depth one produces sixteen
base columns; depth two produces thirty-two. Both retain exactly the input's
total number of base cells. Fused final intervals write the compact permutation
directly instead of copying an intermediate coefficient matrix.

`stwo_rv64_composition_finalize_on` checks the selected context and lane, every
allocation range, twiddle extent and disjointness before enqueue. Input ownership
remains live through stream completion; the input is consumed numerically, not
freed. Typed `resident.Commands.finalizeComposition` checks generation and
capacity, records the actual dispatch count and poisons a failed job. The real
C-ABI seam compiles in the host suite.

The native Zig oracle evaluates random canonical coefficient polynomials with
the native circle implementation. GPU interpolation/splitting must reproduce
those original coefficients in native chunk order. Fourteen cases cover four
and eight coordinates, depths one/two and logs 3, 5, 13 and 17 (the invalid
log-3/depth-2 combination is omitted). This exercises both staged and fused
paths. Native-context alias and foreign-owner mutations reject before launch.
Normal, memcheck, racecheck, initcheck and synccheck pass on RTX 5090. The host
suite passes 75 tests, including capacity, custody and partial-failure handling.

Reproduce the oracle with:

```
zig build --build-file src/integrations/riscv_cuda/build.zig \
  rv64-composition-split-fixtures -Doptimize=ReleaseSafe -- /tmp/split-fixtures
```

`scripts/rv64_cuda_composition_finalize_qualify.py` builds the exact native
sources and runs all five gates. Logs and pinned source/fixture hashes are in
`vectors/reports/rv64-cuda-composition-finalize-20261103/`.

This closes the interpolation/split numerical seam. It is not an accepting
Stark or Ethereum proof, and no block-time or production-size throughput claim
is established by these fixtures. Production scheduling must still retain the
source accumulator, coefficient slab and twiddles within its VRAM budget and
bind the resulting composition commitment to the physical worker transcript.
