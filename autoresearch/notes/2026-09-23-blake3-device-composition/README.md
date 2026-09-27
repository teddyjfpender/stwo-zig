# Authenticated BLAKE3 composition on Metal

This follows the ZisK problem mapping for compiled AIR execution. It retains
canonical 70-query/26-bit-PoW proofs and the prior GPU interaction implementation.
Eight composition kernels are generated from the same typed AIR exports as the
host evaluator. The core AOT inventory now has 199 native exports. Exact generated
identity, placement-bound program validation and invocation checks remain required.
Unsupported programs keep host evaluation. Exported jobs are owned once.

The first diagnostic exposed a second integration gap: streaming PCS commitments
adopt host Merkle trees and expose null residency handles. Merely admitting kernels
therefore did not move composition to the device. The initial unchanged proof is
retained under `initial-smoke`; it is not GPU composition qualification.

The candidate now keeps resident-only base/lookup components on the host if their
input trees are unavailable. Framework composition stages only its requested columns,
one evaluation-domain group at a time through the bounded scratch owner. Exact-domain
columns copy their authenticated committed evaluations without retained coefficients
or a redundant FFT. Wider-domain groups still require the retained polynomials and
actual evaluation transform. Runtime binding accepts proof-owned scratch without
requiring a Merkle tree handle, and still checks buffer ownership, addresses and spans.

The control environment is `STWO_RISCV_CPU_HASH_COMPOSITION=1`. Both arms retain GPU
hash interactions. `smoke.py` requires eight composition dispatches, enables host/device
parity and checks the retained full-suite proof hash plus fresh verification. The
matched measurement uses 16 workers, zero warmups, three samples per block in
control/candidate/candidate/control order, four workloads. The completed results follow below.

This does not qualify the full CSP basket, native parent performance or superiority
over ZisK. Streaming GPU commitment, full residency, broader fusion and overlap remain
separate unfinished architecture work.

## Qualification and results

- Maintained recursive/BLAKE3 AOT catalog comparison and Metal product build pass.
- Native metallib admission: 199 exact exports, no function constants, exact AOT/JIT inventory.
- Six shader-authority checks pass.
- All 21 focused composition tests pass in ReleaseSafe, including exact-domain
  coefficient-free staging, duplicate references, pointer mutation rejection,
  wider-domain coefficient requirements, owner cleanup and strict policy checks.
- The diagnostic complete ECDSA proof dispatches all eight kernels and passes
  host/device composition parity, unchanged proof SHA256 and fresh verification.
- All 48 timed proofs and 16 retained fresh verifications pass, preserving earlier
  full-suite proof hashes. All candidate blocks dispatch eight composition kernels;
  controls dispatch none. Both arms retain GPU hash interaction generation.

Six measured samples per arm; complete transaction medians include admission,
execution, witness, proving, encoding and fresh verification. Memory is the maximum
process-lifetime physical footprint across each arm's two blocks, not a per-proof
allocation counter. The parity diagnostic is excluded from all timings below.

| Workload | Complete time (s) | Composition (s) | Peak process footprint (GiB) |
| --- | ---: | ---: | ---: |
| ecdsa_secp256k1-32 | 0.974180 → 0.735410 | 0.303651 → 0.065190 | 1.52 → 1.74 |
| sha256-128 | 1.905213 → 1.768019 | 0.272147 → 0.132722 | 4.31 → 4.53 |
| sha256-2048 | 3.254150 → 2.907799 | 0.603590 → 0.255626 | 7.82 → 8.04 |
| keccak-128 | 3.170560 → 2.850824 | 0.573330 → 0.259414 | 7.57 → 7.79 |

ECDSA improves about 24.5% end to end; the larger cases improve 7.2–10.6%.
Composition falls 4.66× for ECDSA and roughly 2.1–2.4× for the larger cases.
Bounded staging adds about 0.22 GiB to measured process peak, so this is a speed
improvement with a memory cost, not a memory reduction.

For the original baseline's narrower execution+witness+proving metric, candidate
means (six samples, not the historical ten-sample full-suite protocol) are:

- ecdsa_secp256k1-32: 0.577753 s.
- sha256-128: 1.306173 s.
- sha256-2048: 2.280783 s.
- keccak-128: 2.254966 s.

The ECDSA checkpoint is below its historical Poseidon time; the larger SHA/Keccak
workloads remain far behind. This four-case comparison does not supersede the full
historical CSP basket. No CPU speedup or parent/tree recursion timing is claimed.

## Next architecture target

Streaming PCS currently performs incremental leaf hashing with the host committer
and adopts a host Merkle tree (`src/prover/pcs/tree_builders.zig`). This explains the
null resident handles that had disabled composition. A bounded GPU streaming
commitment path could remove host hashing and preserve useful device ownership;
it must preserve height-sorted leaves, tail handling, proof bytes and memory bounds.
Profile witness preparation and commitment costs together before choosing the next
implementation. Parent fixed-column/residency integration, persistent scheduling,
PCS/DEEP fusion and preparation/proving overlap remain required by the broader goal.

`control-source` captures this turn's input; `candidate-source` captures the change
and focused tests. The frozen product/AOT bundle, exact commands, raw reports,
profiles, artifacts and fresh verifier receipts are retained. Added safety tests
and formatting followed the timed product build and do not change executable logic.
