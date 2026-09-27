# Canonical PCS DEEP arithmetic in the combined BLAKE3 proof

Previous turn: progress; the joined proof constrained the standalone PCS
transcript, canonical FRI arithmetic and all FRI paths.

The combined gate now also lowers the EXISTING canonical PCS DEEP circuit into
the same multiply/inverse/linear components. It uses verifier-captured sampled
values, queried values, DEEP randomness, raw queries and answers. FRI and DEEP
consume the same public answer values. Separate circuit namespaces and the
existing lowering keep all four segment/binary lanes unambiguous. The exact wire
ledger still closes and the complete outer proof passes core verification.
Changing a sampled value makes the canonical DEEP circuit unsatisfied.

The previous standalone PCS fixture sampled an arbitrary point while recording
a zero placeholder OODS seed. That was insufficient for the real DEEP circuit,
which derives its sample geometry from the seed. The fixture now explicitly uses
seed (7,11,13,17) and its canonical circle point; native PCS generation and capture
record the same seed. This seed is a FIXTURE INPUT, not a transcript-derived
outer-STARK challenge. The composition-randomness field remains a placeholder.
A small test-only adapter asserts exact [6,4] column logs, two current-point
samples and 17 queries before building the production DEEP graph. It does not
claim to replace production capture admission.

Commands:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-combined-fri -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-pcs-capture -Doptimize=ReleaseSafe --summary all
```

Combined result: all four steps succeeded; one guarded test passed, approximately
6 seconds runtime and 779 MiB max RSS; compilation took 30 seconds on M5 Max.
The capture regression passes fold1/2/4 with the changed sample-point fixture:
four steps succeeded, one test passed, approximately 3 seconds runtime, 352 MiB
max RSS and 21 seconds compilation.
Formatting and diff checks pass. These are development qualification costs,
not production timings or security parameters.

Remaining: authenticated trace openings must enter this same proof, replacing
public queried-value boundaries; then full outer-STARK transcript/composition/
OODS admission, production keys/suite/artifacts, CPU/Metal and parent-of-parent.
When making trace inputs private, their scalar wire must enforce (value,0,0,0).
An unconstrained four-coordinate producer plus an encoder whose last three
outputs have zero uses would NOT enforce that scalar condition. The FRI private
inputs already enforce it through the scalar-consuming repacking component.
Production remains Poseidon and no speed or soundness improvement is claimed.
The active goal is unfinished.
