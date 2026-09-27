# Hash emission into native main columns with separate metadata

Native preparation retains physical main columns and fixed logical metadata, while
the existing hash column sink writes all logical coordinates as columns. The next
integration boundary needs a destination matching the native representation.

Transfer: add a main-column sink to the existing canonical hash emitPlan. G/XOR
main coordinates write directly at the committed permutation and metadata stores
zero main coordinates plus the generated suffix. Small boundary rows retain their
canonical row sink. Admit every column, range and metadata shape before writes.
Generated metadata is witness data, not trusted preprocessing; independent fixed
admission remains mandatory. No hash equation or proof parameter changes.

This is structure-of-arrays emission with a separate metadata plane. It removes
the need to materialize G/XOR live rows for this sink. Parent-wide log sizes and
logical offsets must be planned before integrating it into transcript/path
production; that integration remains a separate required step, not assumed done.

Validate offsets/padding, complete reconstructed row parity, zero main metadata,
boundary parity, malformed destination before writes, and interactions against
row-oracle columns/claims. Use the focused hash gate; no full native rebuild for
an as-yet-unwired sink. No production timing or memory claim.
