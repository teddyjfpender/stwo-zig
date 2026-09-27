# Persistent native BLAKE3 fixed commitment

The standalone parent Plan now builds and authenticates its preprocessed PCS
tree once, retains the complete LDE/coefficient/Merkle owner, and appends a lease
to each request through the canonical scheme/transcript API. Temporary projected
preprocessed columns are released after initialization. No fixed-column commit
remains in Plan.prove.

PCS trees support explicit promotion to shared immutable ownership and explicit
lease acquisition. Atomic reference counts keep the original owner alive until
the last lease is released. Final teardown uses the original allocator and
retains backend teardown tokens/backing allocations. Sampling discards only a
lease's coefficient descriptor; it cannot free the shared coefficient storage.
Nonshared trees retain their previous cleanup behavior.

This is a lifetime mechanism, not a blanket backend concurrency guarantee. The
source lease must be live while another is acquired; raw struct copies are
moves. Backend payload reads and final-release allocator use must independently
support the chosen threads. Concurrent Metal use has not been qualified.

## Validation

```sh
python3 scripts/zig_serial_build.py --cwd src/prover test-pcs-shared-commitment -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-riscv-segment-v2-native-proof -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment -Doptimize=ReleaseSafe --summary all
```

All terminal exit 0:

- Ownership: 3/3 tests (including root import), 785 ms / 2 MiB, compile 4 s / 354 MiB.
  Tests cover failed promotion, original-owner release before leases, coefficient
  cleanup, subsequent lease acquisition/decommitment, and distinct request
  allocator custody. Initial compile failed on a test-only constructor name;
  corrected to M31.fromCanonical before the passing run.
- Default native parity: 2/2 tests, 9 s / 1 GiB, compile 51 s / 3 GiB.
  This target excludes BLAKE3, so the separate BLAKE3 gate below is authoritative
  for the new parent behavior.
- Native BLAKE3 gate: 3/3 tests, 41 s / 2 GiB, compile 1 min / 5 GiB.
  Two sequential complete parent proofs reuse one plan; each traverses the
  bounded codec and independent verifier. The second artifact is verified after
  plan destruction. The plan arena allocation extent and fixed column/coefficient
  identities remain unchanged across proving. No allocator leaks reported.

Both canonical artifacts are 111,428 bytes. Diagnostic key remains
`f76d51b30dce850ad74060c42808bed2f4dd5bee6cc5705673f00b4754d3c976`.
Child q1/PoW0 and parent q8/PoW0 remain unchanged. No speed benchmark ran; test
elapsed time is not a before/after speed comparison (the gate now proves twice).

Next: bounded preparation/proving overlap and retained per-worker buffers,
then production-profile, binary/parent-of-parent and Metal qualification.
Statement-independent key integration and the production default switch remain
unfinished. Original fused PCS/DEEP and final-layout witness work remains in scope.

Logs, changed-source snapshots and relative SHA256SUMS accompany this report.
