# Experimental degree-two subtraction-product AIR

The canonical planning census found 6,800 single-use subtraction inputs to residual
multiplications. This candidate proves `(a - b) * factor = output` directly, removing
the subtraction's intermediate producer/consumer pair while retaining its three
external input consumptions and the multiplication output's exact multiplicity.

The typed component uses 17 main columns, seven fixed routing fields, five direct
constraints and four relation events (two interaction batches/eight columns). Its
constraint degree, including preprocessing inputs, is two. Its pinned semantic
digest is `9eb981d37251406e7afcc56bf0046686365ea8a20c904c09250fa9310fe28382`.
The field product coordinates reuse the existing canonical QM31 implementation.

The matcher accepts either multiplication operand position, only hides a single-use
subtraction, and respects earlier dot4/FMA reservations. Its caller must supply the
authenticated graph and actual use counts, including graph outputs and external
exports, just as for the existing fusion matchers. Reservation avoids duplicate
contraction. It does not itself replace graph admission.

## Qualification

`focused.log`: three ReleaseSafe checks pass, 714 ms testing and five seconds
compilation. They cover semantic digest, degree, every main-coordinate mutation on
nondegenerate field inputs, inert padding, invalid field identifiers, and exact
signed lookup closure against the existing subtraction and multiply rows. Closure
also covers zero/cancelling inputs and field-edge values; every fixed routing field
is mutated independently. Matcher checks cover both operand orders, exports that
make an intermediate shared, earlier reservation and duplicate reservation.

`initial.log` records a missing location argument in the first test build;
`digest.log` records the expected initial pinning failure before the generated
semantic digest was installed. Neither is passing qualification evidence.

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  test-recursive-subtraction-product -Doptimize=ReleaseSafe --summary all
```

This remains an experimental component, not an active prover path. Next work is
admitted row materialization, independent preprocessing/key integration, backend
coverage and actual proofs followed by canonical parent-of-parent cost comparison.
No end-to-end speed benefit, production promotion, standalone STARK proof or 10x
improvement is claimed by these symbolic/matcher checks.
