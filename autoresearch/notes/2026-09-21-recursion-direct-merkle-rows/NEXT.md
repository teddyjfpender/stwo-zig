# Next substantial target: fuse PCS input binding with opening accumulation

The current `pcs_deep_circuit_builder.evaluateQuery` already factors batch-common
conjugate-line coefficients outside the sampled-column loop. Reimplementing that
factorization or adding another standalone muladd is not a new optimization.
The current graph also already lowers suitable arithmetic into dot4 rows.

Investigate a larger component that consumes authenticated M31 queried values
directly from the trace-opening relation and accumulates their QM31-weighted sum.
This could combine PCS input binding and opening arithmetic, removing intermediate
generic wire exports and their rows. This is a hypothesis, not an implemented
component or a measured speedup.

Before choosing its arity, census eligible queried-value inputs, their exact
fanout, current opening4/muladd lowering and padded column costs. Inputs used by
multiple batches cannot silently lose consumers. Preserve tree/column/query/root
bindings, powers/challenges, accumulator dependencies, denominators and final
equality. The benefit must be measured across complete recursive proofs, including
new preprocessing and lookup costs. A new component requires explicit semantic
identity, keys, backend parity and rejection tests; existing pinned proofs cannot
be presented as qualification of changed constraints.

Keep the parameter experiment separate: compare larger domains against fewer
queries under an explicit security ledger, rather than importing the CSP query
count into this recursion profile.
