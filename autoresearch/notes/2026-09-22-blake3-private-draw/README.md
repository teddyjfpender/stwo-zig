# Authenticated private state into ordered draws — 2026-09-22

The previous turn proved two native absorptions through a private intermediate
state. This turn connects the same frame-witness mechanism to ordered challenge
attempts without introducing a second rejection implementation.

`blake3_draw_witness.zig` now accepts an optional authenticated state producer.
Each attempt replaces public message-input boundaries with frame routes, and the
builder sums producer multiplicities across all attempts. Public-state callers
retain their existing path. Namespace overlap with either hash or challenge
components is rejected; counts cannot wrap or alias M31. All eight raw words
still control rejection, including in single-QM31 mode. Private consumers must
include the returned route rows as an additional AIR component.

The new complete proof starts with native mixU64(198), then derives a single
secure challenge at counter zero from its private output. The state producer's
public output sinks are removed and its copy counts match the draw router.
Trusted preprocessing uses zero placeholders, never receives the intermediate
state digest, and binds only the expected final scalar outputs. Private means
outside the public statement, not a zero-knowledge claim.

Focused commands:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-draw test-blake3-challenge-proof -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-private-draw-proof -Doptimize=ReleaseSafe --summary all
```

The draw unit tests check placeholder-independent fixed columns across all five
component types, native outputs, exact summed state multiplicities across two
attempts, namespace collision rejection and backing allocation failures. The
existing public-state proof gate covers both consumption modes. The private-state
gate connects producer, router, hash, rejection and scalar output in one STARK.

These remain development fixtures (eight queries, blowup 1, zero PoW), not
production speed or security qualification. A complete dynamic transcript still
needs counter/absorption sequencing, private scalar payload encoding, raw-u32
query extraction and PoW, then PCS/FRI source admission, key identities, Metal
and parent-of-parent qualification. Production still selects Poseidon; the
original recursion optimization goal remains active.

All four guarded tests pass. The private-state STARK passes the core verifier;
changed expected scalar outputs and substituted preprocessing roots fail trusted
admission. Unit runtime was 511 ms; the two public-mode proofs took about 6 seconds
and the new private-state proof about 3 seconds, max RSS 349 MiB, on M5 Max.
Formatting and diff checks pass. Changed source files remain below the manual
source-size ceiling. Evidence snapshots leave previous runs untouched.
