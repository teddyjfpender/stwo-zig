# Current CPU and Metal native CSP suite

All 16 canonical cases pass on both backends: 320 measured verified samples,
32 additional warmups and fresh verification of each retained artifact. Both
invalid-signature checks pass. Every case has identical CPU/Metal proof, statement
and output hashes. ReleaseFast; 16 workers; one warmup and ten samples per case.

The reports use source snapshot `267d2200f6e4dbe8053f4e2181b5fc26d40d5066`.
The active working tree/index/ref was not committed or changed to create it.

Result classifications:
- cpu: `host-qualified-non-comparable`; power admissible: `True`.
- metal: `host-qualified-non-comparable`; power admissible: `True`.

These are local current-source measurements, not a paired speedup experiment.
Prove is the mean of execution + witness + proof generation; verification is
reported separately. Both use the unchanged CSP parameters: 70 FRI queries and
26 proof-of-work bits. Native RV32IM execution; no precompiles or recursion.

| Workload | Size | CPU prove s | Metal prove s | CPU verify ms | Metal verify ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| sha256 | 128 | 0.754 | 0.441 | 124.38 | 105.60 |
| sha256 | 256 | 0.670 | 0.411 | 128.12 | 96.77 |
| sha256 | 512 | 0.582 | 0.403 | 134.47 | 99.05 |
| sha256 | 1024 | 0.668 | 0.428 | 136.57 | 97.41 |
| sha256 | 2048 | 0.640 | 0.429 | 138.81 | 100.37 |
| keccak | 128 | 0.523 | 0.388 | 134.46 | 93.52 |
| keccak | 256 | 0.594 | 0.402 | 142.92 | 99.65 |
| keccak | 512 | 0.574 | 0.418 | 138.36 | 101.06 |
| keccak | 1024 | 0.614 | 0.427 | 143.95 | 99.18 |
| keccak | 2048 | 0.779 | 0.461 | 151.76 | 97.47 |
| poseidon2_m31 | 2 | 0.602 | 0.428 | 145.13 | 97.85 |
| poseidon2_m31 | 4 | 0.660 | 0.448 | 148.01 | 99.84 |
| poseidon2_m31 | 8 | 0.921 | 0.489 | 143.96 | 98.57 |
| poseidon2_m31 | 12 | 0.778 | 0.515 | 162.19 | 101.88 |
| poseidon2_m31 | 16 | 1.217 | 0.572 | 155.53 | 105.68 |
| ecdsa_secp256k1 | 32 | 3.737 | 1.937 | 205.28 | 152.21 |

Raw CPU/Metal JSON contains all timing samples, stage means, proof sizes, RSS,
binary/source identities, verifier receipts and GPU telemetry. Snapshot/build
commands and logs are retained. `previous-suite.md` contains historical values;
`precompile-investigation.md` explains why the fast provider proof is a different
workload/security boundary. No claimed precompile speedup is inferred here.

An initial dirty-provenance build was stopped. The first clean CPU measurement
completed its proofs but failed report serialization for an external binary path;
its diagnostic log is retained separately. The successful run reuses identical
binaries under the clean checkout’s ignored zig-out directory. The working-tree
report writer now supports external paths; that reporting-only fix is not part
of the measured snapshot.

Report-path fix validation: 89 benchmark/provenance/native-isolation tests pass;
`git diff --check` passes. No proving implementation changed in this investigation.
