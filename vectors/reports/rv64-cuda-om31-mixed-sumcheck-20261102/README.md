# Native mixed-height OM31 sumcheck on RTX 5090

One GPU transcript now mixes differently sized LogUp oracles, including constant
oracles that activate late. Interpolation is performed once on the weighted
active sum, with the native inactive half-claim constant added afterwards.
Per-oracle Eq corrections and the native `2^unused_variables` claim scaling are
preserved. The [design note](../../../design/riscv-proving-stack/rv64-cuda-mixed-sumcheck.md)
explains the equivalence and its boundary.

The actual Zig native prover supplies 15 fixtures. A fresh native sumcheck verifier
checks them, and the native gate evaluator plus Eq suffix checks every terminal
oracle mask. Device records match all coefficients, trimmed lengths, challenges,
masks, final mixed claims and final channel checkpoints exactly. The fixtures
include 64-oracle batches, a 16-variable oracle, zero/unit RLC weights, all-constant
batches, base/secure numerators and cancellation to empty round polynomials.

Five device mutations separately reject changed oracle heights, a pole, a
noncanonical input claim, an invalid checkpoint counter and an out-of-order round.
Errors remain sticky and every later record is cleared and tagged invalid.
All four Compute Sanitizer tools pass. The existing single-oracle pipeline also
passes all eight strategies in both numerator modes at logs 12/16 after the shared
interpolation refactor; its log 8 memcheck passes. Those recorded timings are
regression observations, not a controlled performance comparison.

The typed Zig wrapper checks the complete job before the first enqueue, including
late aliases, retired generations, bank geometry and constant-oracle workspaces.
It handles zero-round batches without reading an Eq, point or record workspace.
Safe and Fast integration each pass 42 tests; the real-context/real-C-ABI seam
compiles. Terminal status/cursor/count checks are mandatory before publication.
No round polynomial, claim or challenge is read back during the job.

Reproduce native fixtures:

```
zig build rv64-batch-fixtures --build-file src/integrations/riscv_cuda/build.zig -Doptimize=ReleaseSafe -- /tmp/rv64-batch-fixtures
```

Compile `rv64/batch.cu` and `tests/cuda/rv64/batch_smoke.cu` offline with CUDA 12.8,
SM120, the native include directory, and the existing GKR/context objects. Pass
the fixture directory to the smoke and repeat under all four sanitizers with
error-exitcode99. Raw outputs are in `batch/`; `artifacts.json` pins all 15 fixture
files without committing numerical matrices. The shared fixture-IO extraction
also preserves every earlier composition fixture and generated-source hash.

This is a complete mixed sumcheck inside one GKR layer. The parent GKR layer
loop, source projections, physical bindings, truth/PCS integration and proof
assembly remain necessary. No complete GKR child or Ethereum GPU proof is claimed,
no block-level speedup is established, and production readiness remains false.
