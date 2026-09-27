# All native BLAKE3 absorption variants — 2026-09-22

The previous turn proved integer absorption and ordered secure-draw sequencing.
This turn extends that same sequence builder to words, secure fields and roots.
All four native absorption operations share state replacement and counter reset.

Word and QM31 payloads use the native Frame serializer, including length prefixes
and canonical M31 coordinates. Root absorption reserves a separate public digest
source namespace and routes both state and root through the existing frame AIR.
Its exact source multiplicities come from the shared router. Intermediate state
producers remain private; operation payloads remain public in this gate.
No new evaluator, lookup schema or cryptographic parameter was introduced.

Focused command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-transcript-sequence -Doptimize=ReleaseSafe --summary all
```

The sequence fixture now contains eleven operations: integer absorption, two
draws, another integer absorption and draw, then word/field/root absorption each
followed by a draw. It compares all six scalar challenges to the native channel.
Raw words include high bits and 0xffffffff; the QM31 value has four nontrivial
coordinates and the root contains high-bit bytes. Unit checks also cover empty
word/field arrays, exact trusted fixed columns, reset-output substitution,
namespace overflow, invalid attempts and allocation failures for root plus draw.
The complete CPU proof uses the same sequence, real provider tables and core
verification, with changed-output and substituted-preprocessing rejection.

These development fixtures use eight queries, blowup 1 and zero PoW; their
runtime is not a production speed or security claim. Private payload encoding
and source admission remain required: accepting public payloads here does not
make arbitrary child-proof fields publicly trusted in production. Raw query
draws, PoW, production identities, Metal and parent-of-parent qualification also
remain. Production still selects Poseidon; the full goal remains active.

Both guarded tests pass, including the complete CPU proof. Total test runtime
was approximately 4 seconds, max RSS 373 MiB on M5 Max; compilation took 21
seconds. Formatting and diff checks pass. Changed manual source files remain
below the source-size ceiling. Evidence/source snapshots preserve earlier runs.
