# Typed scalar-to-QM31 bridge for the BLAKE3 FRI proof

Previous turn: progress; owned native BLAKE3 captures passed the canonical FRI
arithmetic graph and changed DEEP answers were rejected.

This stage adds `qm31_pack_wire`, a typed lookup-only component consuming four
scalar recursion wires and emitting one four-coordinate QM31 wire. It uses four
main fields, eight fixed fields, five relation events and three interaction
batches. All circuit/node identities are fixed; values remain in main columns.
Zero padding has zero relation multiplicities. Its semantic digest is pinned:
`aa96adb02a58779fe9b1248419126894a259c0c4e2c3ebedc1717e7f089db58b`.

The FRI group test derives scalar source IDs from the canonical graph's exact
(layer, query, offset, word) bindings, checks uniqueness and coverage, and uses
those IDs in independently prepared repacking rows. Source scalar wires now
flow through this component, the canonical field-byte encoder, every BLAKE3 leaf
hash and the shared folding subtree, all in one seven-component CPU proof.
Changing the last leaf's scalar source still rejects the public statement.
Live and independently prepared fixed columns agree. A source/destination
namespace collision is rejected. The existing fold1/2/4 native graph and root
checks remain in the gate.

Command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-fri-group -Doptimize=ReleaseSafe --summary all
```

The first build measured the newly authored AIR's semantic digest; the final
build pins it and includes the seven-component proof. See tests.log for final
terminal results: all four steps succeeded and one guarded test passed, with
approximately 3 seconds runtime and 378 MiB max RSS; compilation took 24 seconds
on M5 Max. Formatting and diff checks pass. This is integration validation, not
a performance benchmark.

Limits: scalar inputs are still supplied by public boundary rows at the real
FRI graph node IDs. The arithmetic operations are evaluated on the host but are
not yet included in this outer proof. When adding arithmetic rows, producer use
counts must include both graph reads and these repacking reads. This component
does not establish transcript provenance or independently authenticate a FRI
profile. Production admission, full combined proof, CPU/Metal suite/key switch
and parent-of-parent qualification remain. Poseidon remains production default;
no production speedup or stronger security is claimed. Goal remains active.
