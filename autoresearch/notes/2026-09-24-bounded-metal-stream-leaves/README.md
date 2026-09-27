# Bounded Metal streaming leaves — retained

Previous goal turn: progress. Eight GPU BLAKE3 composition components were qualified
with unchanged canonical proof hashes and measurable complete-transaction gains.
This turn investigates the remaining host streaming commitment path.

The authoritative column histogram from a canonical SHA256/2048 proof reaches
log 21, with 654 main and 608 interaction columns. Simply using the existing
full-domain staged GPU commitment would require two full-domain hash-state slabs.
That is incompatible with preserving the bounded streaming memory design.

The shared backend hook tiles the final leaf domain. It maps every
original lifted column index into the exact local tile, packs up to 256 small columns into a fixed-capacity
staging window, and reuses two compact BLAKE3 state slabs within a 64 MiB scratch budget.
It calls existing authenticated kernels, with no shader or protocol change. The
resulting leaf hashes enter the shared parent-layer builder. This first experiment
still synchronizes each bounded kernel group; parent hashing remains on CPU,
and Merkle trees remain host-owned. It does not establish persistent device residency.

The frozen comparison candidate uses `STWO_ZIG_METAL_STREAM_LEAVES=1` to opt in.
After qualification, the retained product enables the route by default and adds a
real streaming-leaf dispatch counter. `STWO_ZIG_CPU_STREAM_LEAVES=1` restores host
leaf generation for subsequent matched controls. Canonical 70 queries / 26 PoW bits
and the precompile guest remain unchanged.


The initial full proof was rejected with `UntrustedExecutionKey`: the first tile
mapping incorrectly used ordinary index shifting. The actual lifted-circle map
preserves parity. The corrected implementation preserves both parity lanes and
passes the host Merkle oracle for every layer, using 33, 273 and 1030 columns with
heterogeneous heights and a deliberately tiny 4 KiB scratch budget to force tiles.
All 23 focused ReleaseSafe checks pass. The failure is retained under
`rejected-initial-mapping`; the invalid candidate was rejected.

The initial dispatch ledger also exposed thousands of tiny sixteen-column calls
for ECDSA's narrow components. Packing small domains into the same bounded window
reduces that overhead while keeping the kernel buffer ABI unchanged. The native
compact primitive now accepts up to 256 column descriptors; its existing shader
already loops over the dynamic count. Bounds, overlap and state checks are retained.


## Qualification

- The corrected and packed implementation passes 23 focused ReleaseSafe checks,
  including parity-preserving tile indices, actual GPU/host equality for every
  Merkle layer across heterogeneous domains and BLAKE3 chunk boundaries, and
  telemetry counter separation.
- Shared CPU streaming/retained-column ownership passes 17 ReleaseSafe checks,
  covering full proof verification and failed ownership transfers.
- The ReleaseFast Metal product builds and its 199-export AOT inventory is accepted.
- One corrected ECDSA smoke proof matches the retained proof bytes and freshly verifies.
- All 48 timed comparison proofs and 16 retained fresh verifications pass with the
  earlier full-suite proof hashes. Both arms retain GPU interactions and composition.
- The final default product additionally passes all 16 positive CSP cases, one proof
  plus fresh verification each, with identical retained proof hashes. This is a
  correctness gate, not a new full-suite timing study. The separate invalid-signature
  workload was not rerun in this change.

## Matched Metal timings

Six samples per arm, three samples per block, zero warmups, 16 workers,
control/candidate/candidate/control order. Complete-transaction medians include
admission, execution, witness, proving, encoding and fresh verification.

| Workload | Complete time (s) | Main commitment (s) | Interaction commitment (s) |
| --- | ---: | ---: | ---: |
| ecdsa_secp256k1-32 | 0.746314 → 0.747673 | 0.088342 → 0.101383 | 0.091969 → 0.116923 |
| sha256-128 | 1.770857 → 1.696814 | 0.154752 → 0.126226 | 0.163059 → 0.135292 |
| sha256-2048 | 2.917031 → 2.790789 | 0.300801 → 0.252144 | 0.325606 → 0.275855 |
| keccak-128 | 2.834862 → 2.694932 | 0.295735 → 0.249275 | 0.324114 → 0.258945 |

The larger cases improve 4.2%, 4.3% and 4.9% respectively. ECDSA complete time is
flat. Its main and interaction commitments become slower in isolation; other stages
offset this in complete time. On the original execution+witness+proving metric,
ECDSA's mean changes from 0.588385 to 0.605793 s in this comparison. Do not present
this as an ECDSA speedup. Candidate means for that narrower metric are listed below.

- ecdsa_secp256k1-32: 0.605793 s.
- sha256-128: 1.232298 s.
- sha256-2048: 2.165601 s.
- keccak-128: 2.117864 s.

Peak process footprint is effectively unchanged at approximately 1.74, 4.53, 8.04
and 7.79 GiB across the four workloads. Scratch is bounded per commitment by 64 MiB;
actual measured shapes use 36–52 MiB. This is not a claim of a global concurrent
memory cap or persistent allocation reuse across proofs.

## Scope and remaining work

Leaf hashing now runs on Metal through the generic streaming PCS hook; CPU backends
and unsupported hash families retain their original path. Parents still use shared
CPU construction, and the Merkle tree remains host-owned. Composition therefore
continues to use its previously qualified bounded staging. Per-group waits and
host copies remain; reusable command/buffer slots and end-to-end residency need more
work. Witness preparation is still a substantial measured cost. Full historical CSP
recovery, native recursion latency, overlap, broader PCS/DEEP fusion and the separately
reviewed parameter experiment remain unfinished. No 10× or cross-prover superiority
claim is supported by this checkpoint.

`candidate-source` and `candidate-products` identify the timed opt-in implementation;
`retained-source` and `retained-products` add default selection and dispatch accounting.
Raw commands, profiles, reports, proof artifacts and verification receipts are retained.
`qualify-basket.py` checks the retained default route; `measure.py` reproduces the frozen
comparison. The initial failed mapping is kept as a rejected diagnostic, not mixed into
measurements. No benchmark ran concurrently with a build or another proof process.
