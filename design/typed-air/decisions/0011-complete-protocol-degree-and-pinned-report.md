# ADR-0011 — Complete protocol degree and pinned production report

**Status:** accepted
**Date:** 2026-08-05

## Context

Logical expression degree is not a sufficient backend bound. A direct root may
carry a gate or placement selector, and a lookup entry becomes part of a
cumulative LogUp constraint containing shifted committed columns, a boundary
selector, relation denominators, numerator cross-products, and batching. The
quotient is then divided by the trace-domain vanishing polynomial. Reporting
only the imported DAG roots would understate this protocol geometry.

The word “cubic” is also easy to misread as algorithmic complexity. Here it
means polynomial degree three in trace expressions. Evaluating such an identity
is constant work per row; it does not make proving time `O(N^3)`. Degree changes
the quotient-domain capacity and therefore protocol constants.

## Decision

`air/lang/protocol_degree.zig` is the compatibility authority for complete
degree analysis of an imported production opcode program. It first runs the
ordinary typed-DAG pass and then models these explicit layers:

- current direct roots already contain their shipped placement expression, so
  their external row-mask contribution is degree zero;
- a relation denominator is a transcript-constant affine combination of its
  tuple fields, so its degree is the maximum field degree;
- current and previous cumulative-column samples remain degree one under a row
  shift;
- `is_first` is a degree-one preprocessed boundary selector and the claimed sum
  is a degree-zero transcript parameter;
- a two-entry batch uses the exact shipped recurrence
  `(S - S_prev + is_first * claimed) * d1 * d2 - n1 * d2 - n2 * d1`;
- a one-entry batch uses the same recurrence with synthetic `n2 = 0, d2 = 1`;
  and
- after division by the trace-domain vanishing polynomial, a final algebraic
  degree `d` requires `ceil(log2(max(1, d - 1)))` extra log-degree bits.

All degree additions, trace-log additions, and batch traversal are checked and
fail closed. The analysis retains every direct, lookup, and interaction result,
including intermediate degree terms, rather than exposing only a maximum.

`air/lang/protocol_report.zig` emits report format 1 in stable family, role, and
relation-schema order. The report includes production column and DAG counts,
canonical merges, ordered direct and lookup counts, batch and interaction
geometry, role and relation dependencies, maximum degrees, and quotient
expansion bits. Its machine and human views are pinned under
[`artifacts/`](../artifacts/README.md) and regenerated in memory by the package
test; tests never rewrite them.

The current all-family result is:

- 17 families, 545 direct roots, 242 lookup entries, 155 batches, and 620 M31
  coordinate columns for the QM31 interaction traces when summed as independent
  family components;
- ten families have maximum direct degree three and seven have maximum direct
  degree two;
- every current interaction constraint has degree three;
- the production semantic component's `trace_log_size + 1` bound is exact for
  the degree-three families and conservative for the degree-two families; and
- the production opcode-lookup component's `trace_log_size + 1` bound agrees
  exactly for all 17 families.

These are compatibility observations. They neither change a backend bound nor
activate typed generation.

## Consequences

- M2 now distinguishes logical, direct, numerator, denominator, interaction,
  and post-vanishing quotient degree without relying on a handwritten family
  table.
- The typed abstraction adds no degree relative to the shipped protocol.
- Pair batching's width-versus-degree tradeoff is visible: combining two
  fractions can raise a linear-denominator interaction from degree two to three
  while reducing the number of cumulative columns. This report measures the
  existing choice; it does not optimize it.
- Seven direct components could in principle advertise a tighter bound, but
  changing production geometry is outside compatibility lowering and requires
  verified performance evidence plus a separate protocol decision.
- Any production-program drift that changes counts, dependencies, batching, or
  degree now produces a reviewable golden diff.
- The report remains deliberately incomplete as a layout identity until A-006
  defines `compat-v1` physical columns and A-010 binds the formal projection.

## Rejected alternatives

- **Use only the maximum imported root degree:** rejected because it omits the
  LogUp recurrence, row shift, boundary selector, and quotient geometry.
- **Blindly copy every backend's `log_size + 1` declaration:** rejected because
  agreement would be circular and would conceal conservative family bounds.
- **Treat transcript challenges or the claimed sum as trace-degree one:**
  rejected because they are parameters fixed for the component evaluation, not
  committed trace polynomials.
- **Charge an extra direct row mask outside every imported root:** rejected
  because current placement is already in the production expression and would
  falsely inflate degree.
- **Immediately tighten production bounds for quadratic families:** rejected
  because M2 is observation-only and the interaction component remains degree
  three.
- **Describe degree three as cubic runtime:** rejected because algebraic degree
  is not the asymptotic exponent of proving work.

## Revisit when

The lookup batching policy changes, components use wider row windows or new
boundary identities, `compat-v1` lowering introduces an external gate, or a
measured optimization proposes family-specific production degree bounds.
