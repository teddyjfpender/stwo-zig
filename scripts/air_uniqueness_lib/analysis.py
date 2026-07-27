"""Static analyses that keep the SMT query inside the solver's reach.

Every result here is an exact consequence of the IR, never an approximation.
That matters more than the speed it buys: an analysis that over-constrained the
system would delete counterexamples, which is the one failure mode this
pipeline cannot tolerate.  Each function below states the argument for why its
output is implied.
"""

from __future__ import annotations

from .ir import MODULUS, System


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
        if node.op == "const":
            assert node.value is not None
            out.append((node.value, node.value))
        elif node.op == "col":
            assert node.name is not None
            out.append(column_bounds[node.name])
        elif node.op == "neg":
            lo, hi = out[node.args[0]]
            out.append((-hi, -lo))
        else:
            (a_lo, a_hi), (b_lo, b_hi) = out[node.args[0]], out[node.args[1]]
            if node.op == "add":
                out.append((a_lo + b_lo, a_hi + b_hi))
            elif node.op == "sub":
                out.append((a_lo - b_hi, a_hi - b_lo))
            else:
                products = (a_lo * b_lo, a_lo * b_hi, a_hi * b_lo, a_hi * b_hi)
                out.append((min(products), max(products)))
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


def linear_forms(system: System) -> list[LinearForm | None]:
    """Per node, its expansion as `sum(coeff * column) + constant` mod p, or
    None where the node has degree above one."""
    out: list[LinearForm | None] = []
    for node in system.nodes:
        if node.op == "const":
            assert node.value is not None
            out.append(({}, node.value % MODULUS))
            continue
        if node.op == "col":
            assert node.name is not None
            out.append(({node.name: 1}, 0))
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


def implied_column_bounds(system: System) -> dict[str, tuple[int, int]]:
    """Column intervals implied by the asserted obligations themselves.

    Two sources, each an implication rather than an assumption:

      * a constraint whose factors are all linear in one and the same column
        confines that column to the finite set of factor roots, because a
        product vanishes iff a factor does and p is prime.  `bit(x)` is this
        case, and it is the most common constraint in the AIR;
      * a box-table request with a constant non-zero numerator is
        unconditionally live, so a bare column in its tuple is bounded by the
        component width.

    Narrowing only ever shrinks the quotient ranges the solver must search; it
    never removes an assignment the AIR admits, so a counterexample cannot be
    lost this way.
    """
    from . import tables  # Local import keeps ir/analysis free of table policy.

    refined: dict[str, tuple[int, int]] = {
        column.name: (0, MODULUS - 1) for column in system.columns
    }
    forms = linear_forms(system)

    def narrow(name: str, lo: int, hi: int) -> None:
        current_lo, current_hi = refined[name]
        refined[name] = (max(current_lo, lo), min(current_hi, hi))

    for constraint in system.constraints:
        roots = _single_column_roots(system, constraint, forms)
        if roots is not None:
            name, values = roots
            narrow(name, min(values), max(values))

    for lookup in system.lookups:
        widths = tables.BOX_TABLES.get(lookup.domain)
        if widths is None:
            continue
        numerator = system.nodes[lookup.numerator]
        if numerator.op != "const" or numerator.value == 0:
            continue
        for component, width in zip(lookup.tuple_, widths):
            entry = system.nodes[component]
            if entry.op == "col":
                assert entry.name is not None
                narrow(entry.name, 0, (1 << width) - 1)

    return refined


def _single_column_roots(
    system: System, constraint: int, forms: list[LinearForm | None]
) -> tuple[str, list[int]] | None:
    column: str | None = None
    roots: list[int] = []
    for factor in factors(system, constraint):
        form = forms[factor]
        if form is None:
            return None
        terms, constant = form
        if not terms:
            if constant == 0:
                return None  # Trivially satisfied; says nothing about a column.
            continue  # A non-zero constant factor cannot vanish.
        if len(terms) != 1:
            return None
        name, coeff = next(iter(terms.items()))
        if column is not None and column != name:
            return None
        column = name
        roots.append((-constant) * pow(coeff, MODULUS - 2, MODULUS) % MODULUS)
    if column is None or not roots:
        return None
    return column, roots
