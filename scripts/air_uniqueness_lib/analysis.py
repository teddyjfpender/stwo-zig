"""Static analyses that keep the SMT query inside the solver's reach.

Every result here is an exact consequence of the IR, never an approximation.
That matters more than the speed it buys: an analysis that over-constrained the
system would delete counterexamples, which is the one failure mode this
pipeline cannot tolerate.  Each function below states the argument for why its
output is implied.
"""

from __future__ import annotations

from dataclasses import dataclass

try:
    from riscv_air_ir_lib import tables
    from riscv_air_ir_lib.ir import LEAF_OPS, MODULUS, Node, System
except ModuleNotFoundError:  # Imported as scripts.air_uniqueness_lib in tests.
    from scripts.riscv_air_ir_lib import tables
    from scripts.riscv_air_ir_lib.ir import LEAF_OPS, MODULUS, Node, System


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
    which maps a node to the signed representatives its field value may take,
    and on `windows`, which maps a node to the canonical range a live box
    lookup confines it to.
    """

    raw: list[tuple[int, int]]
    effective: list[tuple[int, int]]
    representatives: dict[int, tuple[int, ...]]
    windows: dict[int, tuple[int, int]]


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

    The multiplier families spell the same idiom with an 11-bit carry, pinned
    by a `range_check_8_11` request rather than a `bit` constraint, so the
    value-set pass above never sees it.  `_live_box_windows` recovers those
    pins from the requests the constraints force live; a window is a range
    representative rather than a value set, and it is what keeps MUL's carry
    chain from compounding through all four limbs.

    Exactness: every assertion this encoding makes about a node reads only its
    residue mod p, so substituting a congruent term into any parent changes
    nothing; and the representative exists in every satisfying assignment
    because the pinning is an implication of the constraints -- for a window,
    of the constraints plus the table membership they force live.
    """
    windows = _live_box_windows(system, pins(column_bounds)) if values is None else {}
    if values is None:
        values = constrained_node_values(system, pins(column_bounds))
    raw: list[tuple[int, int]] = []
    effective: list[tuple[int, int]] = []
    representatives: dict[int, tuple[int, ...]] = {}
    ranged: dict[int, tuple[int, int]] = {}
    for index, node in enumerate(system.nodes):
        span = _interval(node, effective, column_bounds)
        raw.append(span)
        roots = values.get(index)
        reps = tuple(sorted(_signed(root) for root in roots or ()))
        window = windows.get(index)
        # Leaves are their own representative; a column already carries its
        # implied bounds, and re-deriving them here would only add a quotient.
        if node.op in LEAF_OPS:
            effective.append(span)
            continue
        span_width = span[1] - span[0]
        if reps and reps[-1] - reps[0] < span_width and (
            window is None or reps[-1] - reps[0] <= window
        ):
            representatives[index] = reps
            effective.append((reps[0], reps[-1]))
            continue
        if window is not None and window < span_width:
            ranged[index] = (0, window)
            effective.append((0, window))
            continue
        effective.append(span)
    return Renormalisation(raw, effective, representatives, ranged)


def _live_box_windows(system: System, pinned: Pinned) -> dict[int, int]:
    """Per node, the top of the canonical range a live box request confines it
    to: `node -> 2^width - 1` over the components of every box-table lookup
    whose request fires in all satisfying assignments.

    Narrowing from a lookup is only exact when the request cannot be dodged,
    which is why liveness is required to be *unconditional* -- proved by row
    reduction of the constraints, exactly as `_narrow_once` requires before it
    narrows a bare column.  A conditionally live request narrows nothing here,
    so a window can never delete a witness the AIR admits.
    """
    pivots = solved_forms(system, pinned)
    forms = linear_forms(system, pinned)
    windows: dict[int, int] = {}
    for lookup in system.lookups:
        widths = tables.box_widths(lookup.domain)
        if widths is None:
            continue
        if not unconditionally_live(system, lookup.numerator, pivots, forms):
            continue
        for component, width in zip(lookup.tuple_, widths):
            top = (1 << width) - 1
            windows[component] = min(windows.get(component, top), top)
    return _propagate_windows(system, windows)


def _propagate_windows(system: System, windows: dict[int, int]) -> dict[int, int]:
    """Push a window through `inner * constant` onto `inner` where that is
    exact: canonical(inner) = canonical(c^-1 * node), and for t = canonical(node)
    <= top the products c^-1 * t stay below p, so they *are* the canonical
    values and inner's window is c^-1 * top.

    This is the carry idiom's other half.  The AIR divides by 256 as
    `* inv(256)`, `inv(256) = 2^23`, so the windowed carry is `mul(sum, 2^23)`
    and the sum it divides -- the node every parent actually reads -- spans
    2^23 times the window until this step gives it `256 * top`.  Guarded to
    small inverses: a c^-1 of field size would put the product past p, where
    canonical values wrap and the equality above is simply false.
    """
    out = dict(windows)
    for index, top in windows.items():
        node = system.nodes[index]
        if node.op != "mul":
            continue
        for side in (0, 1):
            constant = system.nodes[node.args[side]]
            if constant.op != "const" or constant.value is None:
                continue
            value = constant.value % MODULUS
            if value == 0:
                continue
            inverse = pow(value, MODULUS - 2, MODULUS)
            if inverse * top >= MODULUS:
                continue
            inner = node.args[1 - side]
            bound = inverse * top
            out[inner] = min(out.get(inner, bound), bound)
    return out


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


def projectable_sinks(
    system: System, keep: frozenset[str]
) -> tuple[tuple[int, str], ...]:
    """Constraints that only define a column nothing else observes, in drop
    order, as `(constraint position, column)`.

    A single-factor constraint whose expansion is linear in `Z` with a nonzero
    *constant* coefficient has exactly one solution in `Z` for every value of
    the other columns.  If no other constraint and no constraining lookup reads
    `Z`, and `Z` is not in `keep` (the conclusion, the inputs, an assumed
    prefix), then dropping the constraint is the exact existential projection
    of `Z` -- the witness set over every observed column is unchanged, in both
    directions.  The write-back idiom is the shape this exists for: a lemma
    about `q` drags `rd_next = nonzero * result` along, and that equation adds
    nothing about `q` while adding four full-field unknowns per copy.

    Iterated to a fixpoint because dropping one definition can orphan the next:
    `z2 = f(z1)` frees `z1` once `z2`'s definition is gone.  The decoder must
    re-solve the dropped definitions in *reverse* drop order, so `z1` is back
    before `f(z1)` is evaluated.
    """
    support = column_support(system)
    lookup_read: set[str] = set()
    for lookup in system.lookups:
        if not tables.is_constraining(lookup.domain):
            continue
        lookup_read |= support[lookup.numerator]
        for component in lookup.tuple_:
            lookup_read |= support[component]

    dropped: list[tuple[int, str]] = []
    gone: set[int] = set()
    changed = True
    while changed:
        changed = False
        readers: dict[str, set[int]] = {}
        for position, root in enumerate(system.constraints):
            if position in gone:
                continue
            for name in support[root]:
                readers.setdefault(name, set()).add(position)
        for position, root in enumerate(system.constraints):
            if position in gone or len(factors(system, root)) != 1:
                continue
            for name in sorted(support[root]):
                if name in keep or name in lookup_read:
                    continue
                if readers.get(name) != {position}:
                    continue
                if _constant_coefficient(system, root, name):
                    dropped.append((position, name))
                    gone.add(position)
                    changed = True
                    break
    return tuple(dropped)


def _constant_coefficient(system: System, root: int, name: str) -> int | None:
    """The coefficient of column `name` in `root`, where `root` is linear in
    `name` and that coefficient is a field constant; None otherwise.

    The rest of the expression may be any degree -- `rd_next - nonzero * value`
    is degree two overall and still has coefficient 1 in `rd_next`, which is
    exactly why `linear_forms` cannot answer this question.
    """
    coefficient: list[int | None] = []
    for index, node in enumerate(system.nodes[: root + 1]):
        if node.op == "const":
            coefficient.append(0)
        elif node.op == "col":
            coefficient.append(1 if node.name == name else 0)
        elif node.op == "neg":
            inner = coefficient[node.args[0]]
            coefficient.append(None if inner is None else -inner % MODULUS)
        elif node.op in ("add", "sub"):
            lhs, rhs = (coefficient[a] for a in node.args)
            if lhs is None or rhs is None:
                coefficient.append(None)
            elif node.op == "add":
                coefficient.append((lhs + rhs) % MODULUS)
            else:
                coefficient.append((lhs - rhs) % MODULUS)
        else:  # mul: linear only when the side carrying `name` is scaled by a
            # constant node; anything else makes the coefficient non-constant.
            lhs, rhs = (coefficient[a] for a in node.args)
            if lhs == 0 and rhs == 0:
                coefficient.append(0)
            elif None in (lhs, rhs) or (lhs != 0 and rhs != 0):
                coefficient.append(None)
            else:
                scale_node, linear = (
                    (node.args[0], rhs) if lhs == 0 else (node.args[1], lhs)
                )
                scale = system.nodes[scale_node]
                if scale.op == "const":
                    assert scale.value is not None and linear is not None
                    coefficient.append(scale.value * linear % MODULUS)
                elif name in column_support(system)[scale_node]:
                    coefficient.append(None)
                else:
                    # A non-constant scale is fine while the other side is
                    # `name`-free (coefficient stays 0); with `name` inside,
                    # the coefficient would be an expression, not a constant.
                    coefficient.append(None if linear else 0)
    return coefficient[root] or None


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


def column_support(system: System) -> list[frozenset[str]]:
    """Per node, the set of column names its expression reads."""
    support: list[frozenset[str]] = []
    for node in system.nodes:
        if node.op == "col":
            assert node.name is not None
            support.append(frozenset({node.name}))
        elif node.op == "const":
            support.append(frozenset())
        else:
            support.append(frozenset().union(*(support[a] for a in node.args)))
    return support


def eliminable_inverses(system: System) -> dict[int, tuple[int, int, str]]:
    """Factor nodes of the shape `A*Z - B` whose witness `Z` may be projected
    out, as `factor -> (A, B, Z)`.

    The AIR's inverse-marker idiom -- `rd_addr * rd_inv = rd_nonzero`,
    `(r_abs - 256) * r_inv = 1` -- burns one witness column per non-zero test,
    and each one puts a full-field product into the query per copy.  Where `Z`
    is read by exactly one factor of exactly one constraint and by no lookup,
    the witness set projected onto every other column is unchanged by replacing
    that factor's vanishing with

        exists Z. A*Z = B   <=>   A != 0  or  B = 0        (in F_p)

    which is exact, not an approximation: for A != 0 the solution Z = B/A
    exists and is unique, for A = 0 the equation forces B = 0, and because
    nothing else reads Z the existential distributes over the constraint's
    factor disjunction.  Exactness is directional evidence too -- a projection
    admits the same witnesses, so it can neither hide a counterexample nor
    manufacture one.  The decoder still owes the caller a value for `Z`
    (`Query.eliminated` carries A and B so it can divide); a witness pair
    missing a column would fail replay against the AIR for a reason that has
    nothing to do with uniqueness.

    Restricted to witnesses: projecting an input would weaken the hypothesis
    of the uniqueness theorem, and an output is exactly what the conclusion
    quantifies over.
    """
    support = column_support(system)
    constraints_reading: dict[str, set[int]] = {}
    for position, root in enumerate(system.constraints):
        for name in support[root]:
            constraints_reading.setdefault(name, set()).add(position)
    read_by_lookups: set[str] = set()
    for lookup in system.lookups:
        read_by_lookups |= support[lookup.numerator]
        for component in lookup.tuple_:
            read_by_lookups |= support[component]

    found: dict[int, tuple[int, int, str]] = {}
    for column in system.columns:
        name = column.name
        if column.role != "witness" or name in read_by_lookups:
            continue
        positions = constraints_reading.get(name, set())
        if len(positions) != 1:
            continue
        containing = [
            f
            for f in factors(system, system.constraints[next(iter(positions))])
            if name in support[f]
        ]
        if len(containing) != 1:
            continue
        match = _linear_in(system, support, containing[0], name)
        if match is not None:
            found[containing[0]] = (*match, name)

    # A factor whose A or B reads another eliminated witness would leave the
    # reconstruction order-dependent; no shipped family does this, so the rare
    # overlap keeps the exact-but-slower spelling instead.
    names = {name for _, _, name in found.values()}
    return {
        f: (a, b, name)
        for f, (a, b, name) in found.items()
        if not (support[a] | support[b]) & (names - {name})
    }


def _linear_in(
    system: System, support: list[frozenset[str]], factor: int, name: str
) -> tuple[int, int] | None:
    """Match `factor` as `+/-(A*Z - B)` with `Z` the column `name` appearing
    only as the multiplicand, returning (A, B).  `bare Z` never reaches here:
    `factors` would have split it out of any product, and a witness that IS a
    whole factor pins nothing eliminable."""
    node = system.nodes[factor]
    if node.op not in ("add", "sub"):
        return None
    for z_side in (0, 1):
        product = system.nodes[node.args[z_side]]
        other = node.args[1 - z_side]
        if product.op != "mul" or name in support[other]:
            continue
        for a_side in (0, 1):
            z_node = system.nodes[product.args[1 - a_side]]
            a = product.args[a_side]
            if z_node.op == "col" and z_node.name == name and name not in support[a]:
                return a, other
    return None


def _narrow_once(
    system: System, bounds: dict[str, tuple[int, int]]
) -> dict[str, tuple[int, int]]:
    """One narrowing pass, reading the columns `bounds` already pins."""
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
