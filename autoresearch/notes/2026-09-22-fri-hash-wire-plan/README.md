# Canonical FRI hash wiring and export-aware arithmetic lowering

Previous goal turn: progress (typed scalar repacking and a passing complete
seven-component hash-group proof).

This turn replaces the test-only node-ID table with reusable `fri_hash_wire_plan`.
It validates the canonical FRI circuit, derives repacking schedules in layer,
raw-query and offset order, and derives sorted, unique exports in input-node
order. Every authenticated coordinate contributes one additional arithmetic
wire read. Destination tuple wires have unique global indices across layers
and queries. The plan checks namespace separation, complete coordinate coverage,
canonical ranges and group indices; it owns its schedules and export arrays.

The focused gate uses these schedules in the existing complete hash-group
proof. It also admits segment and binary lanes to the EXISTING arithmetic
lowering, verifies each exported input's count increases by exactly one, and
materializes multiply, inverse and linear invocations from the actual canonical
FRI evaluation in both modes. Fold1/2/4 native captures remain covered. The
initial lowering test omitted the mandatory binary mode and correctly failed
MissingProofMode; both modes are now supplied. No lowering contract was relaxed.

Command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-fri-group -Doptimize=ReleaseSafe --summary all
```

Final validation: four build steps succeeded and one guarded test passed;
approximately 3 seconds runtime, 381 MiB max RSS, 24 seconds compilation on M5 Max.
Formatting and diff checks pass. See tests.log. This is integration evidence, not a speed
benchmark. The arithmetic invocations are generated on the host, not yet committed
as components in this outer proof. Public scalar source boundaries remain in the
hash fixture. Full operation-row proof integration, private source admission,
transcript connection, CPU/Metal key/suite migration and parent-of-parent
qualification remain unfinished. Production still uses Poseidon. Goal active.
