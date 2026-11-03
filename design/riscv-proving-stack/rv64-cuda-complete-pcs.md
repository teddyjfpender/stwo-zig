# Complete native PCS proof on the resident GPU

A complete OM31 PCS proof now passes the unmodified native receiver, with
serialized proof contents byte-identical to the native CPU reference. This
connects the previously separate commitment, OODS/DEEP, FRI and trace-opening
gates. It is not yet an AIR/Stark proof or an Ethereum execution proof.

The qualified construction has one tree, six base-field columns at three
coefficient heights, three point/height groups, maximum degree log 9, evaluation
log 11, blowup log 2, 256 queries, no grinding and fold step 4. It uses the same
OM31/raw-mod channel and prefixed Blake2s commitments as the native RV64 lane.
This is a functional fixture, not an Ethereum or throughput benchmark.

The GPU receives compact coefficient and immutable geometry ingress. It then
performs source-column LDE, the trace commitment, root mixing, OODS parameter
draw, circle point derivation and coefficient sampling, sample-value mixing,
DEEP challenge draw, compact coefficient aggregation and LDE, quotient
evaluation, every FRI commitment/fold and the terminal check. It mixes the
zero-grinding nonce, draws raw queries, and gathers FRI and trace openings.
There is no intermediate numerical H2D/D2H transfer. After joined completion,
only compact proof material and verdict/channel records are downloaded; no
complete column or Merkle tree is read back.

The native receiver assembles the downloaded words into the actual
`CommitmentSchemeProof`, independently reconstructs its commitment and point
transcript, then invokes the existing complete PCS verifier. Its proof JSON
hash matches the independently produced native reference. Physical mutations
of sampled values, trace values, a FRI commitment, terminal coefficients,
the nonce and the trace commitment are rejected by that verifier. This is
stronger than comparing intermediate numerical arrays alone.

Two protocol details matter at this seam. Sample normalization uses the
global evaluation log minus the column evaluation log, and DEEP denominator
lines retain the original, unfolded sample point. DEEP random powers are
assigned in ascending native tree/column/sample order. That order differs from
the reverse random-coefficient fold used for AIR composition. The explicit
term exponents and native reference enforce the distinction.

## Evidence and remaining integration

The normal run and memcheck/racecheck/initcheck/synccheck all pass on the RTX
5090. Every run is followed by a fresh native Linux receiver accepting the
complete proof and rejecting all six physical mutations. Compact captures are
byte-identical across all five gates. An independent native macOS receiver also
accepts the captured proof. Receipts, source/object/executable hashes and logs
are in `vectors/reports/rv64-cuda-pcs-pipeline-20261103/`.

```
zig build --build-file src/integrations/riscv_cuda/build.zig \
  rv64-pcs-fixtures -Doptimize=ReleaseSafe -- export /tmp/rv64-pcs-fixtures
zig build --build-file src/integrations/riscv_cuda/build.zig \
  rv64-pcs-fixtures -Doptimize=ReleaseSafe -- verify \
  /tmp/rv64-pcs-fixtures/case-0.bin /tmp/rv64-pcs-readback/case-0.bin
```

`scripts/rv64_cuda_pcs_pipeline_qualify.py` links the qualified dependency
objects, runs the resident pipeline and all four sanitizer/receiver gates.
The older primitive-only `pcs_smoke.cu` remains intact; the complete path is in
`pcs_pipeline_smoke.cu`.

The current orchestration is a qualified proof harness, not a production
execution dispatcher. The real RV64 proof uses multiple trees, heterogeneous
opening masks and periodicity samples; these require receiver-derived planning,
sample-order permutation and bounded residency. Joined-domain composition,
actual CPU/truth witness integration and manifest/statement/physical-root
acceptance are still required before the Ethereum receiver can accept a GPU
bundle. GPU block timings, recursion and ZisK-equivalent performance remain
unqualified. Neither this fixture nor the q256 parameter choice supplies a
whole-protocol security certificate.
