# Base-field lookup visitation

The previous checkpoint made verified progress by connecting canonical native
parent interactions to authenticated Metal kernels. This experiment addresses a
shared CSP/parent preparation cost: registerRepeated materialized every event as
a secure-field Entry (including wide unused tuples and non-table events), then
converted selected table tuples back to base fields.

The authenticated runtime now visits selected base-field events directly, in the
same order and using the same evaluated expression DAG and signed roles.
The shared row-column counter path selects bitwise/range-8-8 events and scales
signed multiplicities in M31. Counter.registerBase uses the same checked table
index function as indexSecure; arity and zero-weight behavior remain unchanged.
There is no change to AIRs, proof parameters, transcript, or GPU shaders.
No workload dispatch or case-specific hash implementation was introduced.

Two focused ReleaseSafe framework tests pass. They compare full counter arrays
against the original secure-entry path on complete compression G/XOR/boundary
rows, repeated padding, signed cancellation, invalid tuple rejection, invalid
arity and zero-weight invalid tuples. Existing table interaction claim closure
and typed framework export checks also pass.

Canonical Metal parent qualification passes all seven selected/imported tests,
with unchanged 857591-byte artifact SHA-256
87eacb69ec7dcf9d5aad70f4f36ff5ac8839bf78366fb11e7ac20da38755ce7b.
Both levels retain 70 queries / 26 PoW bits; independent verification, replay,
rekey, fixed-plan reuse and ownership checks pass.

The first diagnostic main-setup observation falls from approximately 4.7 s to
1.56 s. Interleaved frozen-binary measurements are recorded separately; this
single stage observation is not an end-to-end speed claim.

## Next shared target identified

The preceding native-parent Metal profile attributes 3.999 s of its 5.248 s core
to sampled-value evaluation, versus 0.757 s for composition. Therefore adding all
seventeen missing native composition components is not the highest-return next
step. sampled_values.zig:evaluateBarycentricTreesWithBackend returns false when
quotientResidencyHandle is absent. Bounded streaming commitments are host-owned,
so the existing device barycentric kernels are bypassed. A bounded host-column
staging adapter, with exact point normalization and shared weight plans, is a
concrete next investigation. Do not retain the entire trace on device just to
recover dispatch; memory bounds and independently verified parity are mandatory.

This checkpoint does not complete full CSP baseline recovery, scheduling overlap,
deeper PCS/DEEP fusion, final-layout emission or the separately reviewed recursion
parameter experiment.

## Matched parent result

Frozen prior/candidate binaries, serial control/candidate/candidate/control order;
two complete canonical fixtures per arm. All four preserve identical proof bytes
and all verification/replay/rekey/ownership assertions.

| Metric | Prior | Base visitor |
| --- | ---: | ---: |
| Complete fixture wall median | 26.788347 s | 23.985443 s |
| Parent stage sum median | 14.163265 s | 11.003184 s |
| Main setup median | 4.705555 s | 1.575659 s |
| Peak resident set | 20,979,515,392 B | 20,884,406,272 B |
| Peak physical footprint | 27,381,756,360 B | 27,381,707,352 B |

Complete fixture time improves 10.5%; parent stages improve 22.3%; main setup is
3.0x faster. Physical peak is unchanged. The fixture includes child proof,
preparation, verification and teardown, excluding compilation. It does not measure
production tree throughput. Raw logs/results/summary and frozen source/binary/AOT
artifacts are retained here; measure-parent.py reproduces the comparison.

## Matched Metal CSP result

| Workload | Complete median (s), prior → candidate | Reduction | Candidate execution+witness+prove mean (s) |
| --- | ---: | ---: | ---: |
| ECDSA precompile / 32 | 0.685503 → 0.670229 | 2.2% | 0.526907 |
| SHA256 / 128 | 1.611874 → 1.524971 | 5.4% | 1.061632 |
| SHA256 / 2048 | 2.633728 → 2.533698 | 3.8% | 1.918155 |
| Keccak / 128 | 2.540282 → 2.416209 | 4.9% | 1.837668 |

Frozen prior/candidate ReleaseFast products, 16 workers, canonical 70 queries /
26 PoW bits, blowup 1, fold step 1 and last-layer degree 0. Six samples per arm,
in three-sample control/candidate/candidate/control blocks; zero warmups.
All 48 timed proofs and 16 fresh artifact verifications pass. Every case preserves
guest/input/output/config identity and exactly matches the prior proof bytes.
GPU interactions, composition and overlapped leaves remain enabled in both arms.

Physical peaks are essentially unchanged; exact process-lifetime peaks are in
csp-summary.json. The complete median includes admission, encoding and fresh
verification; the last column matches the historical timing scope. This subset
is not the final one-warmup/ten-sample CPU/Metal basket and does not supersede the
original Poseidon results. The broader baseline gap remains open.

Reproduce with measure-csp.py (frozen products) and summarize-csp.py. Focused
tests: scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu
test-blake3-framework -Doptimize=ReleaseSafe --summary all.
