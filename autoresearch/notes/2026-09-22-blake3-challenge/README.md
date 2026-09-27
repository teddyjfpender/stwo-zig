# BLAKE3 constrained challenge extraction — 2026-09-22

Progress toward the production hash migration; production remains Poseidon.

The new typed challenge block consumes all eight packed words of a BLAKE3 draw,
checks byte ranges with the canonical range8_8 provider, rejects the entire block
if any word is 0xfffffffe or 0xffffffff, and reduces accepted words to M31.
This includes words in the unused half of a single-QM31 draw. Accepted scalar
outputs have coordinates (value,0,0,0); they are not packed byte wires.

The component has 71 main columns, 15 fixed columns, 47 quadratic direct roots,
33 relation events and 68 interaction columns. A nonnegative bounded integer
certificate detects precisely the two rejected words without bit-decomposing
all inputs. Its derivation is in the registered problem-match note. Semantic pin:
`14883ec735144475a7119bee94bb05fce6b739e444b6fdd568d8a0abb9362b5e`.
Fixed rows depend only on the public schedule, not on draw bytes or acceptance.

A complete CPU STARK now connects a canonical BLAKE3 draw frame to this component
and then to eight native scalar challenges. It replaces public digest consumers
with authenticated challenge input wires. The existing boundary AIR also exposes
a coordinate-based witness constructor; its semantics and digest are unchanged.
The proof closes production byte/bitwise table claims, independently reconstructs
trusted preprocessing, and passes the core verifier. A changed expected challenge
and substituted preprocessing root fail trusted admission.

Focused commands:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-challenge -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-challenge-proof -Doptimize=ReleaseSafe --summary all
```

All four guarded tests pass. Unit checks cover native threshold vectors in every
position, random blocks, exact output weights, out-of-range bytes, mutations of
validity/reduction/product/acceptance, padding, semantic identity and framework
export. Unit runtime was 507 ms; the proof runtime was about 3 seconds, maximum
RSS 349 MiB, on M5 Max. These are development diagnostics at eight queries,
blowup 1, zero PoW, not production speed/security measurements.

The proof fixture exposes transcript state and draw index as statement inputs.
It verifies an accepted first attempt. It does not yet prove private transcript
state transitions, ordered retries, query-index extraction, or a whole recursive
verifier. Invalid-word tests exercise both rejection values without relying on
finding an astronomically unlikely hash preimage. Production integration still
requires those bindings, lifted PCS/FRI geometry, PoW, child-source admission,
new key/artifact identities and CPU/Metal parent-of-parent qualification.

Source conformance retains the same 103 pre-existing finding identities, with no
additions or removals. Source snapshots and terminal logs are pinned separately
from previous runs.
