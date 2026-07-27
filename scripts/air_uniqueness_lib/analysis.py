"""Static analyses that keep the SMT query inside the solver's reach.

Every result here is an exact consequence of the IR, never an approximation.
That matters more than the speed it buys: an analysis that over-constrained the
system would delete counterexamples, which is the one failure mode this
pipeline cannot tolerate.  Each function below states the argument for why its
output is implied.
"""

from __future__ import annotations

from dataclasses import dataclass

from .ir import LEAF_OPS, MODULUS, Node, System


def degrees(system: System) -> list[int]:
    """Total degree per node.  The SMT encoding is correct at any degree, but a
    family whose degree exceeded the AIR's composition bound would mean the
    extractor read something other than the constraint path."""
    out: list[int] = []
    for node in system.nodes:
        if node.op == "const":
            out.append(0)
        elif node.op == "col":
            out.append(1)
        elif node.op == "neg":
            out.append(out[node.args[0]])
        elif node.op == "mul":
            out.append(out[node.args[0]] + out[node.args[1]])
        else:
            out.append(max(out[node.args[0]], out[node.args[1]]))
    return out


def _interval(
    node: Node, child: list[tuple[int, int]], column_bounds: dict[str, tuple[int, int]]
) -> tuple[int, int]:
    """Interval of one node's defining expression, given its children's."""
    if node.op == "const":
        assert node.value is not None
        return (node.value, node.value)
    if node.op == "col":
        assert node.name is not None
        return column_bounds[node.name]
    if node.op == "neg":
        lo, hi = child[node.args[0]]
        return (-hi, -lo)
    (a_lo, a_hi), (b_lo, b_hi) = child[node.args[0]], child[node.args[1]]
    if node.op == "add":
        return (a_lo + b_lo, a_hi + b_hi)
    if node.op == "sub":
        return (a_lo - b_hi, a_hi - b_lo)
    products = (a_lo * b_lo, a_lo * b_hi, a_hi * b_lo, a_hi * b_hi)
    return (min(products), max(products))


def node_bounds(
    system: System, column_bounds: dict[str, tuple[int, int]]
) -> list[tuple[int, int]]:
    """Exact integer interval per node, given per-column intervals.

    Interval arithmetic over the exact integer expression -- no reduction --
    because these bounds are what make the quotient variables in the SMT
    encoding finite.  They are only as tight as `column_bounds`, and every
    caller must be able to justify those as implied.
    """
    out: list[tuple[int, int]] = []
    for node in system.nodes:
        out.append(_interval(node, out, column_bounds))
    return out


@dataclass(frozen=True)
class Renormalisation:
    """Where a node's field value is pinned, the emitter may pass its parents a
    small representative instead of the expression itself.

    `raw[i]` bounds the defining expression of node `i`; `effective[i]` bounds
    the term its parents receive.  They differ exactly on `representatives`,
    which maps a node to the signed representatives its field value may take.
    """

    raw: list[tuple[int, int]]
    effective: list[tuple[int, int]]
    representatives: dict[int, tuple[int, ...]]


def _signed(value: int) -> int:
    """The representative of `value mod p` nearest zero.

    Sign matters only for interval width: a carry pinned to {0, p-1} spans the
    whole field read as {0, p-1} and spans [-1, 0] read as {-1, 0}, and it is
    the width that sizes every quotient variable downstream.
    """
    return value - MODULUS if value > MODULUS // 2 else value


def renormalise(
    system: System,
    column_bounds: dict[str, tuple[int, int]],
    values: dict[int, tuple[int, ...]] | None = None,
) -> Renormalisation:
    """Interval analysis that stops at every node the constraints already pin.

    Without this the byte-carry idiom is unusable.  A carry is spelt
    `(a + b + carry_in - result) * inv(256)`, `inv(256) = 2^23` in M31, and each
    limb feeds the next, so plain interval arithmetic multiplies the width by
    2^23 per limb: four limbs reach 10^27 and the quotient variable discharging
    `P = p*k` ranges over 10^18 values.  The `bit(carry)` constraint says the
    carry's field value is 0 or 1, so passing the parent a representative in
    [0, 1] is exact and the width stops compounding.

    Exactness: every assertion this encoding makes about a node reads only its
    residue mod p, so substituting a congruent term into any parent changes
    nothing; and the representative exists in every satisfying assignment
    because the pinning is an implication of the constraints.
    """
    if values is None:
        values = constrained_node_values(system, pins(column_bounds))
    raw: list[tuple[int, int]] = []
    effective: list[tuple[int, int]] = []
    representatives: dict[int, tuple[int, ...]] = {}
    for index, node in enumerate(system.nodes):
        span = _interval(node, effective, column_bounds)
        raw.append(span)
        roots = values.get(index)
        reps = tuple(sorted(_signed(root) for root in roots or ()))
        # Leaves are their own representative; a column already carries its
        # implied bounds, and re-deriving them here would only add a quotient.
        if node.op in LEAF_OPS or not reps or reps[-1] - reps[0] >= span[1] - span[0]:
            effective.append(span)
            continue
        representatives[index] = reps
        effective.append((reps[0], reps[-1]))
    return Renormalisation(raw, effective, representatives)


def factors(system: System, node: int) -> list[int]:
    """Flatten a product node into its factors, discarding sign.

    A product vanishes in a field exactly when one factor vanishes, so a
    constraint may be discharged as a disjunction over these.  Sign is
    irrelevant to vanishing, hence `neg` is transparent here.
    """
    out: list[int] = []
    stack = [node]
    while stack:
        current = stack.pop()
        entry = system.nodes[current]
        if entry.op == "mul":
            stack.extend(entry.args)
        elif entry.op == "neg":
            stack.append(entry.args[0])
        else:
            out.append(current)
    return out


LinearForm = tuple[dict[str, int], int]


Pinned = dict[str, int]


def linear_forms(
    system: System, pinned: Pinned | None = None
) -> list[LinearForm | None]:
    """Per node, its expansion as `sum(coeff * column) + constant` mod p, or
    None where the node has degree above one.

    A column in `pinned` reads as its constant.  That is what makes an
    opcode-gated constraint analysable: `flag * carry * (carry - 1)` is degree
    three and spans two directions, so nothing can be read off it, while with
    `flag = 1` substituted it is the plain `bit(carry)` whose factors share one
    direction.  Substituting a column the system already forces to a constant
    is exact; the caller owes the proof that it does.
    """
    out: list[LinearForm | None] = []
    for node in system.nodes:
        if node.op == "const":
            assert node.value is not None
            out.append(({}, node.value % MODULUS))
            continue
        if node.op == "col":
            assert node.name is not None
            fixed = None if pinned is None else pinned.get(node.name)
            out.append(({}, fixed) if fixed is not None else ({node.name: 1}, 0))
            continue
        if node.op == "neg":
            inner = out[node.args[0]]
            out.append(_scale(inner, MODULUS - 1))
            continue
        lhs, rhs = out[node.args[0]], out[node.args[1]]
        if lhs is None or rhs is None:
            out.append(None)
            continue
        if node.op == "add":
            out.append(_combine(lhs, rhs, 1))
        elif node.op == "sub":
            out.append(_combine(lhs, rhs, MODULUS - 1))
        elif not lhs[0]:
            out.append(_scale(rhs, lhs[1]))
        elif not rhs[0]:
            out.append(_scale(lhs, rhs[1]))
        else:
            out.append(None)
    return out


def _scale(form: LinearForm | None, factor: int) -> LinearForm | None:
    if form is None:
        return None
    terms, constant = form
    return (
        {name: (coeff * factor) % MODULUS for name, coeff in terms.items()},
        (constant * factor) % MODULUS,
    )


def _combine(lhs: LinearForm, rhs: LinearForm, sign: int) -> LinearForm:
    scaled = _scale(rhs, sign)
    assert scaled is not None
    terms = dict(lhs[0])
    for name, coeff in scaled[0].items():
        merged = (terms.get(name, 0) + coeff) % MODULUS
        if merged:
            terms[name] = merged
        else:
            terms.pop(name, None)
    return (terms, (lhs[1] + scaled[1]) % MODULUS)


def solved_forms(system: System, pinned: Pinned | None = None) -> dict[str, LinearForm]:
    """Row-reduce the constraints that are single linear equations.

    A constraint that is a product says only that *some* factor vanishes, so it
    yields no equation.  A constraint that is not a product and whose expansion
    is degree one says `sum(a_i x_i) + c = 0`, which does.  Gaussian elimination
    over F_p turns that set into `pivot -> (terms, constant)`, read as
    "pivot equals this expression in non-pivot columns", and every satisfying
    assignment obeys it.

    This is what makes the AIR's enabler-gated table requests visible.  Every
    numerator in the shipped families is `-enabler`, never a literal, and the
    placement constraint pins `enabler = 1`; without elimination the analysis
    sees a non-constant numerator, declines to conclude the request is live, and
    leaves every limb free over the whole field.
    """
    pivots: dict[str, LinearForm] = {}
    forms = linear_forms(system, pinned)
    for constraint in system.constraints:
        if len(factors(system, constraint)) != 1:
            continue
        candidate = forms[constraint]
        if candidate is None:
            continue
        terms, constant = _substitute(candidate, pivots)
        if not terms:
            continue  # Either trivial, or a contradiction the solver will find.
        # `min` rather than dictionary order: the pivot choice must not depend
        # on how the emitter happened to build the expression.
        var = min(terms)
        inverse = pow(terms[var], MODULUS - 2, MODULUS)
        rest = {
            name: (-coeff * inverse) % MODULUS
            for name, coeff in terms.items()
            if name != var
        }
        solution = (rest, (-constant * inverse) % MODULUS)
        pivots = {
            name: _substitute(existing, {var: solution})
            for name, existing in pivots.items()
        }
        pivots[var] = solution
    return pivots


def _substitute(form: LinearForm, pivots: dict[str, LinearForm]) -> LinearForm:
    terms, constant = form
    out: dict[str, int] = {}
    for name, coeff in terms.items():
        replacement = pivots.get(name)
        if replacement is None:
            out[name] = (out.get(name, 0) + coeff) % MODULUS
            continue
        for inner, inner_coeff in replacement[0].items():
            out[inner] = (out.get(inner, 0) + coeff * inner_coeff) % MODULUS
        constant = (constant + coeff * replacement[1]) % MODULUS
    return ({n: c for n, c in out.items() if c}, constant % MODULUS)


def unconditionally_live(
    system: System,
    lookup_numerator: int,
    pivots: dict[str, LinearForm],
    forms: list[LinearForm | None] | None = None,
) -> bool:
    """Whether the request fires in every assignment satisfying the system."""
    form = (linear_forms(system) if forms is None else forms)[lookup_numerator]
    if form is None:
        return False
    terms, constant = _substitute(form, pivots)
    return not terms and constant != 0


Direction = tuple[tuple[str, int], ...]


def _direction(form: LinearForm) -> tuple[Direction, int] | None:
    """Split a degree-one form into a normalised direction and a scale.

    `form` is then `scale * direction + constant`.  Normalising by the
    lowest-named coefficient makes the direction independent of how the emitter
    happened to build the expression, so two nodes along the same line are
    recognisably the same line.
    """
    terms, _ = form
    if not terms:
        return None
    scale = terms[min(terms)]
    inverse = pow(scale, MODULUS - 2, MODULUS)
    return tuple(sorted((n, c * inverse % MODULUS) for n, c in terms.items())), scale


def _constraint_roots(
    system: System, constraint: int, forms: list[LinearForm | None]
) -> tuple[Direction, set[int]] | None:
    """The values a constraint pins one line of the column space to, if any.

    Applies when every factor is degree one along a single common direction:
    the product vanishes iff some factor does, p is prime, and each factor
    vanishes at one point of that line.
    """
    direction: Direction | None = None
    roots: set[int] = set()
    for factor in factors(system, constraint):
        form = forms[factor]
        if form is None:
            return None
        split = _direction(form)
        if split is None:
            if form[1] == 0:
                return None  # Trivially satisfied; says nothing about anything.
            continue  # A non-zero constant factor cannot vanish.
        line, scale = split
        if direction is not None and direction != line:
            return None
        direction = line
        roots.add(-form[1] * pow(scale, MODULUS - 2, MODULUS) % MODULUS)
    if direction is None or not roots:
        return None
    return direction, roots


def constrained_node_values(
    system: System, pinned: Pinned | None = None
) -> dict[int, tuple[int, ...]]:
    """Per node, the finite set of field values the constraints allow it, where
    they allow only finitely many.

    A constraint pins a *line* through the column space, not a column: the
    byte-carry idiom pins `(a + b + carry_in - result) * inv(256)` to {0, 1}
    without pinning any column in it.  Every node lying on that line inherits
    the pinning under its own scale and offset, which is what lets the emitter
    hand a carry's parent a term in [0, 1].
    """
    forms = linear_forms(system, pinned)
    lines: dict[Direction, set[int]] = {}
    for constraint in system.constraints:
        found = _constraint_roots(system, constraint, forms)
        if found is None:
            continue
        direction, roots = found
        known = lines.get(direction)
        # An empty intersection means the constraints contradict each other.
        # Dropping the line leaves that for the solver to report as the vacuous
        # unsat it is, rather than encoding it as an unsatisfiable bound here.
        lines[direction] = roots if known is None else (known & roots) or known
    out: dict[int, tuple[int, ...]] = {}
    for index, form in enumerate(forms):
        split = None if form is None else _direction(form)
        if split is None:
            continue
        roots = lines.get(split[0], set())
        if roots:
            out[index] = tuple(
                sorted((split[1] * r + form[1]) % MODULUS for r in roots)
            )
    return out


def determined_columns(
    system: System, seed: frozenset[str], pinned: Pinned | None = None
) -> frozenset[str]:
    """Columns whose value the constraints fix once `seed`'s values are fixed.

    Seeded with the architectural inputs, this is the set of columns the two
    copies of a uniqueness query must agree on, because agreeing on the inputs
    is the hypothesis.  A column joins when some node the constraints pin to a
    single value is degree one and has exactly one column outside the set: that
    node reads `c*x + rest = v` with `c` a non-zero field constant, so
    `x = (v - rest)/c` is a function of columns already in the set.  Iterated to
    a fixpoint, since each new member can unlock the next.

    The AIR needs the fixpoint rather than just the seed.  A register the row
    only reads still has a `_next` column, tied to `_prev` by a constraint the
    one-hot selector gates; that column is a witness, it is the operand of the
    bitwise requests, and leaving it unshared makes the solver prove an 8-bit
    decomposition unique before it can conclude anything about the result.
    """
    forms = linear_forms(system, pinned)
    values = constrained_node_values(system, pinned)
    known = set(seed) | set(pinned or {})
    pending = [
        (index, roots[0]) for index, roots in values.items() if len(roots) == 1
    ]
    changed = True
    while changed:
        changed = False
        for index, _ in pending:
            form = forms[index]
            if form is None:
                continue
            free = [name for name in form[0] if name not in known]
            if len(free) == 1:
                known.add(free[0])
                changed = True
    return frozenset(known)


def one_hot_selectors(system: System) -> tuple[str, ...]:
    """Input columns the constraints force into exactly-one-of, or ().

    Two facts have to come out of the IR, never out of a naming convention:
    a single non-product constraint expanding to `sum(f) - 1 = 0`, and a `bit`
    constraint on every `f` in it.  Together they say the assignment picks
    exactly one, so enumerating them is a complete case split -- a family is
    unsat iff every case is.  Splitting a case split that is not complete would
    delete cases and so delete counterexamples, which is why neither fact is
    assumed.

    Restricted to inputs: the two copies are asserted equal on inputs, so one
    case pins both.  A one-hot over witnesses would need the |F|^2 cross
    product, and the shipped families do not have one.
    """
    bounds = implied_column_bounds(system)
    forms = linear_forms(system)
    roles = {column.name: column.role for column in system.columns}
    for constraint in system.constraints:
        if len(factors(system, constraint)) != 1:
            continue
        form = forms[constraint]
        if form is None or form[1] != MODULUS - 1 or len(form[0]) < 2:
            continue
        names = tuple(sorted(form[0]))
        if any(form[0][name] != 1 for name in names):
            continue
        if all(roles[n] == "input" and bounds[n] == (0, 1) for n in names):
            return names
    return ()


def pins(column_bounds: dict[str, tuple[int, int]]) -> Pinned:
    """The columns an interval map has narrowed to a single value."""
    return {name: lo for name, (lo, hi) in column_bounds.items() if lo == hi}


def _narrow_once(
    system: System, bounds: dict[str, tuple[int, int]]
) -> dict[str, tuple[int, int]]:
    """One narrowing pass, reading the columns `bounds` already pins."""
    from . import tables  # Local import keeps ir/analysis free of table policy.

    pinned = pins(bounds)
    refined = dict(bounds)
    forms = linear_forms(system, pinned)

    def narrow(name: str, lo: int, hi: int) -> None:
        current_lo, current_hi = refined[name]
        refined[name] = (max(current_lo, lo), min(current_hi, hi))

    for index, values in constrained_node_values(system, pinned).items():
        entry = system.nodes[index]
        if entry.op == "col":
            assert entry.name is not None
            narrow(entry.name, min(values), max(values))

    pivots = solved_forms(system, pinned)
    for name, (terms, constant) in pivots.items():
        if not terms:
            narrow(name, constant, constant)

    for lookup in system.lookups:
        widths = tables.box_widths(lookup.domain)
        if widths is None:
            continue
        if not unconditionally_live(system, lookup.numerator, pivots, forms):
            continue
        for component, width in zip(lookup.tuple_, widths):
            entry = system.nodes[component]
            if entry.op == "col":
                assert entry.name is not None
                narrow(entry.name, 0, (1 << width) - 1)

    return refined


def implied_column_bounds(system: System) -> dict[str, tuple[int, int]]:
    """Column intervals implied by the asserted obligations themselves.

    Three sources, each an implication rather than an assumption:

      * a constraint that pins a line of the column space, where that line is a
        single column, confines it to the finite set of factor roots.  `bit(x)`
        is this case, and it is the most common constraint in the AIR;
      * a pivot that eliminates to a bare constant pins its column to that
        value.  This is where `enabler = 1` comes from;
      * a box-table request that is live in every satisfying assignment bounds
        any bare column in its tuple by the component width.

    Iterated to a fixpoint, because each pinned column unlocks the next pass:
    substituting `enabler = 1` turns the enabler-gated `bit` constraints into
    plain ones, whose roots pin more columns.  Narrowing only ever shrinks the
    quotient ranges the solver must search; it never removes an assignment the
    AIR admits, so a counterexample cannot be lost this way.
    """
    bounds = {column.name: (0, MODULUS - 1) for column in system.columns}
    while True:
        narrowed = _narrow_once(system, bounds)
        if narrowed == bounds:
            return bounds
        bounds = narrowed
