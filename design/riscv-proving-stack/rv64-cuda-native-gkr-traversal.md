# Resident native OM31 GKR traversal

The RTX5090 now runs a complete mixed-height native LogUp-GKR child, from the
fraction trees through every outer layer and sumcheck, without numerical CPU
feedback. `rv64/gkr.zig` owns deterministic workspace geometry and reuses the
existing mixed-batch enqueue implementation. `native/rv64/gkr_loop.cu` owns the
parent transcript and binds each sumcheck's imported seed, alpha, input claims
and initial heights back to that parent. Individual output pairs and masks are
absorbed separately, exactly as in the native protocol.

The typed route reserves one generation-checked arena and all external input
ranges before its first mutation. Trees, reusable fold banks, Eq storage,
reduction scratch, records and masks have deterministic disjoint regions. The
byte cap covers requested workspace payload; input fractions, MAIN/PCS buffers,
allocator retention and process RSS are separate. This first implementation
retains dense fraction trees; checkpointing/source replay still matters for the
largest production geometries. Public geometry alone controls launches. No
challenge, polynomial or marginal is read back to decide subsequent work.

After joined completion, `Header.validate` checks transcript status, chain,
cursor, draw counter and terminal phase. Proof assembly and fresh native
verification remain mandatory. An unbound GKR child does not authenticate its
input matrices and cannot accept an execution.

Qualification: eight fixtures exported by the actual native OM31 prover and
fresh verifier, including mixed heights, base/secure numerators, zero numerators
and64 instances. GPU roots, records, masks, intermediate checkpoints and terminal
input marginals match, with native input-MLE closure. Nine parent/frame/field
mutations are rejected. All four Compute Sanitizer tools pass. The extended
private batch-state layout also preserves all15 earlier numerical fixtures and
five injected-failure cases. Host ReleaseSafe/ReleaseFast each pass45 tests and
compile the real-context C ABI seam. Receipts:
`vectors/reports/rv64-cuda-gkr-traversal-20261102/`.

The cold exporter is `zig build rv64-gkr-fixtures --build-file
src/integrations/riscv_cuda/build.zig -Doptimize=ReleaseSafe -- OUT`. Build the
hardware harness from `tests/cuda/rv64/gkr_loop_smoke.cu`, native `context.cu`,
`rv64/gkr.cu`, `rv64/batch.cu` and `rv64/gkr_loop.cu`, using the existing CUDA
include path and sm_120 flags. Its argument is OUT; run it under memcheck,
racecheck, synccheck and initcheck with `--error-exitcode 99`.

Next integration gates are source-authenticated device projection, joined AIR
composition including public Eq auxiliaries, and the OM31 PCS/OODS/DEEP/FRI and
opening/proof-assembly controller. Full GPU Ethereum proof acceptance,
performance and current-profile recursion remain unqualified.
