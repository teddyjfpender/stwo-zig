# Full-width BLAKE3 Ethereum artifact and capture

Status: canonical CPU artifact/capture qualification and shared CSP regression passed.

B3EHART1 is a versioned envelope binding a caller-pinned key, native/hash claims,
extension claims and the BLAKE3 STARK. Fixed claim geometry, canonical field
limbs, total byte counts and nested proof vector limits are checked before
allocating from received payloads. Verifier preprocessing derives these limits
from admitted native, hash and Ethereum component geometry.

Successful verification can retain a proof capture with owned native claims,
extension claims, all 26 extension challenge draws, the fourteen actual
component placements and the final channel. Its mutation seal includes the
retained fields and rejects inconsistent cached universal challenge powers.
The seal is not a replacement for STARK verification or recursive constraints.

The focused fixture now uses CPU q70/PoW26 with four workers. It serializes the
proof, destroys its original witness and proof, mutates source public I/O,
then decodes and independently verifies. Checks cover byte-for-byte re-encoding,
malformed envelope/key/native field rejection with an allocator that cannot
allocate, capture challenge/placement/power mutation rejection, and agreement
between captured and ordinary verification.

```sh
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments '-Driscv-test-filter=BLAKE3 execution commitment Ethereum full proof independently verifies' -Doptimize=ReleaseSafe --summary all
```

Ethereum recursive composition, transcript export/routing, canonical multi-segment
aggregation, Metal qualification and production activation remain open. Existing
CSP timings do not benchmark this full-width Ethereum path.

## Next integration batch, based on current source inspection

- Generalize the shared execution composition preparation to admit the B3EH
  capture and full extension assembly. Preserve native/hash equations and add
  fourteen extension components through production generic evaluators. Existing
  `ethereum_vm_composition_graph_extension_v2.zig` records these equations but
  binds its older scalar/layout types; adapt that shared authority rather than
  copying a second verifier implementation.
- Include detailed extension claims as transcript inputs and separately bind
  their aggregates before global closure. Their framing includes component
  metadata and aggregate values, so simply appending all claims to closure is
  incorrect.
- Replay the B3EH statement prefix, 47 universal relation pairs and 13 extension
  pairs. The recorder can number pairs, but execution challenge routing currently
  fixes the count at 47. Extend the admitted count and check every export/use.
- Derive DEEP masks from the complete assembly using existing
  `blake3_execution_deep.prepareComponents`. Reuse FRI, roots/nonce, PCS paths,
  final hash-column emission and bounded parent scheduling.
- Qualify a full extension leaf-to-parent proof before routing Ethereum segments
  into the production aggregation tree. A successful capture is only input to
  this work, not evidence that recursive equations have been implemented.

## Canonical CPU result

Passed at q70/PoW26 with four proof workers. The complete build/test gate reports
10 minutes and 30 GiB peak RSS. The full-width signer-recovery + Keccak proof
survives serialization, original proof/witness destruction and source public-I/O
mutation, then independently verifies through both capture and ordinary APIs.
Artifact round-trip equality, rejection before payload allocation, and mutation
checks for extension challenges, component placements and cached universal
powers all pass. See `canonical-proof.log`. This is not a stage-isolated latency
benchmark, recursive Ethereum qualification or a production-default switch.

## Shared CSP regression

Passed 1/1 tests at q70/PoW26 after the shared extension wire/challenge changes.
ReleaseSafe compilation reports 1 minute / 4 GiB; test execution reports 2 seconds /
1 GiB. Proof bytes remain 3,748,258. See `csp-regression.log`. This is the existing
CSP memory contract with BLAKE3 PCS/transcript and does not replace the recorded
ReleaseFast suite results or benchmark the full-width B3EH path.

```sh
STWO_CSP_FIXTURE_ROOT=/Users/theodorepender/code/cryptography/stwo-zig/vectors/riscv_csp python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-csp-ecdsa -Doptimize=ReleaseSafe --summary all
```
