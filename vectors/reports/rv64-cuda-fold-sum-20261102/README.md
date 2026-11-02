# Fold / next-round sum fusion

Continuation of PR311 at43148eba. The optional fused path removes a full
read of every nonterminal folded table, plus one launch per nonterminal
round. Four output rows belong to one thread; retained register values feed
the next raw term, while disjoint bank stores support the following fold.
No extra workspace, hot transfer, allocation or synchronization is added.
The standalone initial sum and terminal fold remain explicit.

24 tests pass in each of ReleaseSafe and ReleaseFast. Complete numerical
records/state/terminal masks agree with the baseline and actual native prover
for14 cases /62 rounds per strategy, including base/secure inputs, zero
polynomials and minimum terminal/fused geometries. Padded SoA strides exercise
the exact tile helper. Real native-context FFI compiles in both modes.
A separate ASan/UBSan host replay passes22 cases (count4 through4096, both
numerator kinds). LeakSanitizer cannot inspect this runner's proc thread
state, so only leak detection was disabled on the passing replay.

CUDA13.4 compiles sm89/sm120; the fused first-stage kernel uses128 registers,
256 shared bytes, zero stack and no reported spills on both architectures.
The full six-strategy real-driver harness compiles/links for both targets;
execution exits77 because no NVIDIA device/driver is available. Added device
preflight-negative and poisoned fused-wave checks are compiled, not executed.

For count2^22 the source cost model removes20 launches and268,435,200 logical
fraction-table read bytes (256 MiB minus256 bytes). This is not a measured
speedup or utilization result. Fewer schedulable threads and register pressure
require real shape sweeps; fusion remains false by default. Independent Python
field checks pass4196 cases. Focused package checks and31 source-check unit
tests pass. Whole-source checks retain inherited findings outside touched
files; broad CI is not claimed green. Local hook feedback is bypassed for the
previously reproduced inherited failures; hosted checks have no bypass.

All source hashes bind this snapshot. Earlier report directories are historical
snapshots. GPU sanitizers/Nsight,2/4x4090/5090 sweeps, Rust oracle, authenticated
witness ingress, mixed GKR, PCS and complete-block acceptance remain pending.
This slice does not open any production/security gate.
