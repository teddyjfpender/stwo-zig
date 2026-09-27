# Complete typed proof of canonical FRI arithmetic under BLAKE3

Previous turn: progress (canonical repacking schedules, exact extra use counts,
and successful native arithmetic invocation generation).

The new gate now commits the canonical FRI arithmetic as an actual CPU STARK.
A real verified BLAKE3 PCS capture uses fold widths [16,2], 17 queries, lifting
log6, blowup1 and terminal polynomial degree log0. The existing canonical circuit
and arithmetic lowering produce rows for the existing qm31_mul_full, qm31_inv
and linear_ops AIRs. Graph input wires, constants and designated zero outputs
are explicit public boundary rows with graph-derived signed multiplicities.
The interaction ledger closes and the complete proof passes core verification.
Operation preprocessing is rebuilt from the admitted lowering plan, separately
from operation main rows. Changed public input preprocessing is rejected.

The shared proof harness now has an explicit parameter-tuple entry point;
existing hash gates retain their empty-parameter wrapper. It also supports the
existing arithmetic AIR builders' generated source-location argument. Arithmetic
components gain only a logical Row alias, without changing their AIR or digest.
Proof-kind selectors are supplied both in logical witness rows and as verifier
parameters, including padded rows. No arithmetic implementation was duplicated.

Commands:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-fri-arithmetic-proof -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-fri-group -Doptimize=ReleaseSafe --summary all
```

Arithmetic result: four steps succeeded; one guarded test passed, approximately
3 seconds runtime, 367 MiB max RSS, 23 seconds compilation on M5 Max. The initial
compile exposed the existing AIR build location argument; the harness now
supplies it. The hash-group regression also passes: four steps, one guarded test, approximately
3 seconds runtime and 381 MiB max RSS, 24 seconds compilation.
Formatting and diff checks pass. These are development integration proofs,
not production security parameters or performance benchmarks.

The arithmetic is now constrained in an outer proof, rather than only evaluated
on the host. However, its input values remain public auxiliary inputs in this
arithmetic gate. The separate hash-group proof authenticates hash paths. These
must still be joined in ONE proof with shared private scalar producers, correct
combined use counts and all query/layer roots, followed by transcript and PCS
DEEP admission. Production suite/key identities, Metal and parent-of-parent
qualification remain unfinished. Production still uses Poseidon; no speed or
security gain is claimed. The full active goal remains unfinished.
