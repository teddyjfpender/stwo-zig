# Shared BLAKE3 G width reduction

Status: retained shared layout; Metal CSP and canonical CPU parent checks pass.

The previous goal turn made progress by qualifying bounded Metal staging overlap.
The remaining large CSP gap calls for reducing the shared trace work, not another
isolated copy optimization. The ordinary commitment and native parent rosters both
use this G component.

| Per G | Control | Candidate |
| --- | ---: | ---: |
| Main columns | 124 | 112 |
| Direct constraints | 80 | 56 |
| Arithmetic lookup requests | 56 | 52 |
| Call relation events | 66 | 62 |
| Interaction base-field columns | 132 | 124 |
| Maximum constraint degree | 2 | 2 |

Six additions now use two 16-bit limbs, retaining byte-bounded inputs and outputs
and boolean carries. Both sides of each integer sum remain below 2^17, below M31,
so the field equation cannot conceal a modular alias. This removes twelve carry
columns and twenty-four equations. The four lookup requests on reassembled
rotation bytes are redundant: bounded low/high pieces and the equality already
force each result into [0,255]. Piece range requests and byte XOR membership stay.

An initial proposal also removed twelve scaled-piece columns, targeting 100 main
columns. The typed lookup registry rejects field-valued multiplication expressions
where its exact byte schema is required. That proposal was withdrawn rather than
weakening registry admission. Explicit scaled bytes and their equations remain.

New arithmetic identity: 9c571892e3c6acfb17302af37b1f60a59860379e9befe708563faff6a0505fa7.
New call identity: 878a0938353a5e45fc932363ddb324721a1797de85a52a36aa5d64b918713ee5.
These change the authenticated AIR and proof layout. Prior proof hashes are not an
acceptance oracle for new proofs; independent verification, public input/output
identity and canonical security parameters are required.

Six focused ReleaseSafe tests pass: independent typed-bit arithmetic comparison,
all-coordinate mutation rejection, a malformed field witness that demonstrates
lookup necessity, every G call of a full compression, authenticated wire closure,
endpoint substitutions and allocation-failure cleanup. Additional input cases
exercise 16-bit boundaries. The wire mutation test now derives its first endpoint
from EVENT_COUNT rather than hardcoding the old arithmetic lookup count.

Matched measurements and their limits are recorded below; full CSP recovery and whole-tree recursion remain open.

## Matched Metal results

| Workload | Complete median (s) | Peak physical footprint (GiB) | Candidate execution+witness+prove mean (s) |
| --- | ---: | ---: | ---: |
| ecdsa_secp256k1-32 | 0.676341 → 0.677494 | 1.74 → 1.72 | 0.536322 |
| sha256-128 | 1.633717 → 1.605834 | 4.53 → 4.22 | 1.143242 |
| sha256-2048 | 2.648323 → 2.593264 | 8.04 → 7.53 | 1.978277 |
| keccak-128 | 2.581169 → 2.493022 | 7.79 → 7.28 | 1.915439 |

Frozen previous and candidate products, 16 workers, canonical 70 queries / 26 PoW
bits, blowup 1, fold step 1, last-layer degree 0. ECDSA uses the precompile guest.
Control/candidate/candidate/control ordering, three samples per block, zero
warmups, six samples per arm. All 48 timed proofs and 16 fresh verifications pass.
Guest/input/output hashes and PCS settings match the retained control. Control
proof hashes remain unchanged and each arm produces deterministic proof bytes.
Candidate proof hashes differ because the authenticated layout changed.

Both arms retain overlapped GPU leaves, GPU interactions and GPU composition.
Complete time includes witness, admission, encoding and fresh verification;
the narrower mean is separately reported to match historical timing scope.
Larger-case time reductions are 1.7–3.4%, with roughly 6–7% lower physical peaks.
ECDSA time is flat. These are shared trace-layout benefits, not full CSP baseline
recovery. No cross-prover superiority or recursive performance claim follows.

Core ABI is now 23, with 199 core exports. Both core and recursive catalogs were
regenerated from authenticated typed AIRs. The focused shader-authority root now
includes AOT profile/source-pin tests: all eight checks pass without running a
prover or the FRI device suite. Core source SHA256 is
769fb666604044cee8209e23c615746d2bc3a520d56b3ff2035de2ca5ee76a13.

## Canonical parent and full positive basket

All 16 positive Metal CSP cases pass one proof and a separate fresh artifact
verification each, with unchanged canonical guest/input/output and PCS settings.
These single-sample basket runs qualify correctness, not full-suite timing. The
separate negative guest and the complete CPU CSP basket were not rerun.
The previous-layout ECDSA artifact is rejected as UntrustedCommitmentPlan by the
new verifier; old proofs are not silently interpreted using the changed AIR.

The focused CPU recursive fixture independently verifies both child and parent
at 70 queries / 26 PoW bits. Transcript replay, fixed-plan reuse, rekey rejection
and success, and outputs outliving the worker all pass. The two-worker parent
records 43.525437 s across its profiled proving stages and 14,329,156,052 tracked
peak bytes. This excludes preparation outside the profile, verification and
compilation; it is one diagnostic observation, not a matched parent speedup or
production root-latency claim. No parent-of-parent or whole-tree qualification is
implied. The retained parent executable and parent-summary.json support replay.

Parent artifact: 857591 bytes, SHA256
87eacb69ec7dcf9d5aad70f4f36ff5ac8839bf78366fb11e7ac20da38755ce7b.
Child encoded proof: 483375 bytes. The parent artifact is slightly larger than
the earlier fixture despite narrower G columns, reinforcing that transcript,
query geometry and total proof cost must be measured rather than inferred.

The original persistent scheduling / PCS-DEEP fusion / direct final-layout
emission / separately reviewed parameter experiment remains active. This shared
G change contributes to trace cost reduction; it does not complete those goals.
