# Separate residual prelinear fusion shapes before selecting an AIR

The live arithmetic census previously combined add, subtract and negate inputs to
remaining multiplication nodes. It now records each operation separately, plus
products with two removable operands. All candidates retain the existing single-use,
export and dot4/FMA reservation checks. This changes diagnostics only; it does not
alter lowering authority, AIRs, keys, proof parameters or emitted witnesses.

The existing export-safety test now checks separate subtraction accounting, verifies
exports remove those candidates, and covers one product with independently removable
addition and negation operands. Fifteen focused ReleaseSafe checks pass in
`focused.log` (33 seconds compilation, three seconds testing), including existing
lookup closure, main-coordinate mutation and padding checks.

## Concrete design constraint

The current `qm31_mul_add_v1` proves a degree-two equation
`a*b = output_sign*out + addend_coefficient*c`, counting preprocessing columns in
the polynomial degree. Naively extending it with `(a + selector*c)*b` raises the
expression to degree three. A fixed-operation subtraction component can keep
`(a-c)*b = out` degree two, but adds a cohort and commitment width. Both alternatives
must be evaluated at the next recursion level before promotion. The archived
quotient fusion already demonstrated that a first-level padded-height saving can
be outweighed by new next-level hash work.

Negation offers a narrower alternative: the existing polynomial already expresses
`a*b = -out` without additional columns. Supporting that through an authenticated
operation/schedule and matcher could remove a single-use negation row, while keeping
its original input consumption and output multiplicity. No such lowering change is
implemented here; the new census must first establish its actual incidence.

## Next evidence required

Collect these separate counts from current canonical leaf and parent captures, then
compare padded domains, committed field bytes, relation degree and next-level hash
rows for the selected shapes. The old archived 6,855 combined candidates are not
current-tree measurements and cannot establish a gain for a subtraction-only AIR.

The host remained at 2% battery. Full powered timing and new canonical census runs
were deferred; only the small focused correctness gate ran. No performance result,
full-tree shape count, or completed fusion optimization is claimed by this step.
