# Word16 LS arithmetic lanes

This slice lifts the existing LS71/INTER48, scalable boundary23/20, paired
selection6/2/8 and scalar-table equations to dynamic arithmetic parameter wires.
It introduces no receiver, recursive proof, protocol version, geometry, claim
closure, or instruction semantics.

`memory/load_store_v2/component.Component` remains the Q alias of
`ComponentFor(Q)`. The native domain callback remains the existing PackedM31
path with secure random accumulation. `ComponentFor(C)` supplies typed claims,
challenges and public row count to the SAME residual authority, plus
`evaluateQuotientsAtPointFor` for arbitrary arithmetic lanes. Mask access uses
absolute offsets and each kind's exact current/previous sample schedule.
Quotient scaling calls the existing generic circle denominator authority.

A native component stores `rows:u32`. An external component stores a count wire
and `rows_nonzero`, the statement's derived `count != 0` wire. The point adapter
rejects an omitted flag. A future recursive statement must constrain/derive that
flag and bind the count to its admitted public transcript; supplying a guessed
flag is not sufficient statement admission. Direct `emitFor` is the low-level
arithmetic path and requires that same input contract. No accepting API is added.

The shared primitive changes are deliberately narrow:

- `closed_ram.equations.transitionLocalWithPublicFor` receives row-count and
  nonempty lane values. The old integer-count wrapper supplies the exact old
  constants, preserving all residual positions.
- `load_store_v1.equations.emitLocalWithPublicFor` delegates to that authority.
  Existing v1 equations and finite-image protocol remain the legacy controls.
- `load_store_v1.authority.selectionFor` contains the unchanged strict paired
  inverse, weighted numerator and cyclic prefix; both native v1 and lifted v2
  call it. Selection challenges share one typed five-coordinate definition.
- `closed_ram.equations.rangesFor` and `providers.scalar_range.rangeFor` accept
  typed challenge/claim constants. Their arithmetic and emitted order are the
  same for Q, packed native lanes and Circuit wires.

All dynamic values are constant with respect to the trace polynomial variable;
no trace polynomial product or degree bound changes. Every component retains
its declared degree3/split1 geometry. The native ownership, metadata, source
retirement, histogram and table construction paths are unchanged.

The focused suite checks complete arbitrary-Q residual equality for all six
kinds at empty/nonempty counts, wires every challenge and claim, rejects changes
to physical claims/challenges/count/nonempty, and compares the complete scaled
point accumulator at nonzero column offsets. It also tests malformed samples,
missing derived flags and the deliberately permitted redistribution of local
ledger shares. LS RAM debt remains separate; OWNER/range/selection share one
physical total, so the tests do not invent independent certificates.

Existing dense-Q cubic/native SIMD/memory/OOM/proof gates and fresh retained
native controls qualify compatibility. The receipt records the actual checks
and byte comparisons. No independent recursive verifier, Word16 global circuit
closure, compact initialization/terminal proof, or recursive topology/admission
qualification follows merely from this arithmetic seam.
