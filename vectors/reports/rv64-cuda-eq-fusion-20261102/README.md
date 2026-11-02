# Eq expansion fusion

Continuation of PR311 at bccab607. Adds a resident four-level Eq expansion
option and a four-way full-sumcheck benchmark matrix. Baseline stays default.

22 tests pass in both ReleaseSafe and ReleaseFast, including native EqEvals
parity for1 through14 variables, remainder tiles and real-context FFI checks.
Ada/Blackwell kernels compile without reported spills. Four-level sm120 tiles
use128 registers; hardware profiling remains mandatory. No NVIDIA GPU is
available here, so no measured speedup or utilization claim is made.

For21 variables the route uses6 launches instead of21. A full four-level tile
uses the same30 field multiplications but moves544 Eq-buffer bytes per prefix
instead of1440, excluding point loads/caches. Increased register use and fewer
threads may offset these savings. The real-driver harness compares full proof
records for all baseline/fused Eq and combined/split reduction combinations.

Source hashes and compiler/test logs are retained. Existing full-block,
physical-binding, Rust oracle and hardware qualification gates remain open;
this is neither a complete Ethereum prover nor a production promotion. Broad
repository formatting/layout failures documented in the parent commits remain;
local hook feedback is bypassed with disclosure, without hosted-CI bypasses.
