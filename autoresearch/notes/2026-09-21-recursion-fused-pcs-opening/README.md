# Fused PCS query binding and opening accumulation — experimental component

Implemented a typed component that consumes four authenticated M31 trace-query
values directly and accumulates their QM31-weighted sum. Weights, accumulator and
output retain their arithmetic-wire coordinates and exact output multiplicity.
This combines an existing opening4 row with four PCS queried-value input rows;
it is not merely a larger generic dot product.

The component has 29 main and 22 preprocessed fields, five direct constraints,
ten relation events and maximum constraint degree two. Its pinned semantic digest
is `d954ea0be1110a7132ecd827fc593776176699a6bd62a70ca8e9423f2df57cfc`.
It is **not yet selected by production lowering or the proving roster**. No new
full recursive proof or end-to-end speedup is claimed for these constraints.

## Conservative matching and real-parent census

The matcher extends the existing admitted opening4 groups. It only eliminates a
queried-value input with exactly one use, including graph outputs and external
exports in the use count. Shared inputs and non-query inputs are rejected. Either
multiply operand may hold the base-field query; the other stays a bound QM31 wire.
The census uses a privately owned, profile-admitted PCS graph, not candidate-supplied
source annotations. The standalone matching helper assumes the existing opening
match and source authority are already admitted; it is not an admission boundary.

The guarded real-parent capture test independently admitted the retained root at
`/tmp/pr198-typed-closure-ladder-20260921-v1/8-metal/parent-3-0`, then inspected its
PCS graph. This developmental fixture uses `recursive_q193_v1`; parameters and
production code paths are unchanged.

| Census, one child PCS graph | Count |
| --- | ---: |
| Graph nodes | 1,367,063 |
| Total PCS input rows | 391,028 |
| Queried-value inputs | 375,771 |
| Single-use queried-value inputs | 351,067 |
| Shared queried-value inputs | 24,704 |
| Existing opening4 groups | 105,869 |
| Eligible fused groups | 83,376 |
| Removable PCS input rows | 333,504 |

The eligible input rows are approximately 85.3% of this child's PCS input rows.
For each eligible group, 54 opening fields plus four 26-field input rows become
51 fused fields: 107 fewer logical fields. Across the census this is 8,921,232
M31 fields / 35,684,928 logical bytes. This is a derived layout opportunity, not
padded committed size, peak memory or time. Shared inputs must retain their bindings.

## Focused validation

`test-recursive-fused-pcs-opening` passes all five guarded tests:

- Pinned typed identity, degree analysis, exact lookup schemas, roles, coordinates
  and multiplicities.
- Native QM31 arithmetic parity and rejection of all 29 main-coordinate mutations
  across 12 nonzero test cases; inert padding and noncanonical schedule rejection.
- Every schedule coordinate changes a bound lookup or weight; zero and field-edge
  arithmetic. A zero query can make a weight locally irrelevant, but its wire lookup
  still binds that weight; the test checks this distinction explicitly.
- Query source matching, commuted operands, and rejection of shared/exported inputs,
  non-query sources and inconsistent binding indices.
- Exact signed lookup-multiset equivalence against the existing opening4 plus four
  PCS input rows, including intermediate-wire cancellation. A changed query column
  breaks this external closure even when local arithmetic is unchanged.

The real-parent capture guard also passes, including the existing both-lane witness
parity and provider checks. Source conformance remains at 103 existing finding
identities, with no new finding identities. No producer benchmarks were run because
the new AIR is not yet integrated. Evidence, source snapshots and manifests below
preserve the actual test/census scope.

## Completion boundary and next work

The full four-part goal remains active. This establishes the component semantics
and a measured opportunity in the real graph; it does not complete circuit fusion.
Next integrate the candidate schedule into authenticated parent preparation: replace
eligible opening rows, remove exactly their four original PCS input rows, preserve
unmatched and shared inputs, and check all-source closure before proving. Bind the
new component through the catalog, manifest, claims, verifier and Metal export path.
Use fresh keys and independently verify new CPU/Metal proofs, including recursion
over the newly shaped parents. Measure padded columns, lookup work, complete-parent
latency and complete products before claiming a performance improvement.

Persistent final-layout buffers/within-worker overlap, remaining direct final-layout
witness generation, and the separately reviewed parameter experiment also remain
unfinished. The earlier fixed-profile optimizations do not satisfy those requirements
or establish the tenfold aspiration.
