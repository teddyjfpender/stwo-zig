# Shared private DEEP answers and FRI terminal coefficients

Previous turn: progress; opening inputs were private, but answer and terminal
coefficient inputs remained independently anchored public values.

An owned terminal-link plan derives DEEP answer, FRI answer and terminal coefficient
nodes from canonical input-binding tags. Complete unique coordinates are required.
Parent admission rejects overlapping/non-input nodes and non-scalar or mismatching
answer values. A private DEEP scalar producer emits its graph uses plus one route
read. The corresponding FRI scalar route consumes that same value and supplies
its graph uses. Both public answer boundaries are removed.

Terminal coefficient scalars emit their FRI graph uses plus one pack read. Existing
QM31 packing feeds canonical field-byte encoding, which supplies routed transcript
absorption. The public coefficient boundaries and public coefficient absorption
are removed. The PCS source options now independently select routed sample and
terminal-coefficient inputs; the original public entrypoints remain wrappers over
the same implementation and retain transactional publication.

The terminal packing namespace is 5,000,002, and its transcript byte destination
is 4,000,002. Existing sample, opening and transcript namespaces remain separate.
No AIR equations or semantic digests changed; the parent still uses thirteen AIRs.
The owned link plan releases partial allocations on failed mapping and lives until
prefix cleanup. Unit checks include missing answers/coefficients and duplicate
coefficient coordinates, alongside existing weighted packing/sample checks.

Claims, samples, openings, answers and terminal coefficients are now shared private
inputs in this qualification fixture. Public challenge outputs, commitment roots,
query data, nonce data and fixed rejection/path scheduling remain. Thus reusable
production keys, complete private child-proof admission, CPU/Metal migration,
parent-of-parent and performance qualification are still incomplete. Production
still uses Poseidon. No production speedup or migration completion is claimed.

Validation (serialized ReleaseSafe):

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-qm31-pack-wire test-blake3-combined-fri test-blake3-fri-arithmetic-proof -Doptimize=ReleaseSafe --summary all
```

Twelve steps succeeded; all three guarded tests passed. Mapping/packing unit:
659 ms / 2 MiB, compilation 4 seconds / 518 MiB. Combined original/parent proof
gate: 29 seconds / 6 GiB, compilation 36 seconds / 2 GiB. Single-graph FRI regression:
5 seconds / 368 MiB, compilation 30 seconds / 2 GiB. These are fixture qualification
costs, not production recursion latency. Formatting and diff checks passed.
No broad suite was run.
