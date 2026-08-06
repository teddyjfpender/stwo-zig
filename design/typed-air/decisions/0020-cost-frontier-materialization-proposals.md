# ADR-0020 — Cost-frontier materialization proposals

**Status:** proposed
**Date:** 2026-08-06

## Context

The accepted degree-bounded policy deterministically reproduces the existing
426 Poseidon materializations, but it deliberately makes no optimality claim.
Degree feasibility is only one part of proving cost. A different cut can trade
one committed column, LDE, and device write for a smaller globally shared
composition DAG, fewer distinct column reads, or lower live-value pressure.
Those dimensions cannot be collapsed into “number of constraints,” and wall
time cannot choose a protocol layout without a canonical structural identity.

Production direct-polynomial lowering hash-conses the complete constraint DAG.
Therefore a cost model that sums each materialization equality independently
would double-count shared work and could rank proposals backwards. Conversely,
the typed Poseidon witness closure is essentially fixed by the sixteen outputs;
moving boundaries does not justify claiming that all 2,171 semantic witness
operations disappeared.

The search space is combinatorial. H-009 is an experiment, not a proof of global
optimality and not an authority switch. It needs deterministic, bounded,
machine-independent exploration whose output can be reviewed and benchmarked
without contaminating compatibility v1.

## Decision

`stwo.typed-air.materialize.cost-frontier-v1` is a separate proposal policy.
It does not modify or replace
`stwo.typed-air.materialize.degree-bounded-v1`.

For one ordered root set, gate, degree policy, and versioned search
configuration it:

1. starts from the fully revalidated H-003 cut set;
2. represents every candidate as a canonical, strictly ordered set of typed
   `ValueId`s with all declared outputs materialized;
3. explores a fixed semantic-DAG edge neighbourhood of deletion, addition, and
   swap edits in canonical order for a bounded number of passes;
4. fully recomputes reachability, degree, dependency, gate, row-mask, and
   topological feasibility for every candidate rather than trusting an edit;
5. lowers all candidate equalities into one canonical, globally hash-consed
   direct polynomial DAG; and
6. retains the nondominated frontier under an integer cost vector, with
   deterministic digest ordering only for deduplication and bounded retention.

The structural vector contains at least:

- materialization and total main-column counts;
- direct-root and fixed interaction-column counts;
- globally unique direct nodes and operation counts, including
  multiplications;
- distinct committed-column reads;
- peak live direct nodes under the specified canonical evaluation order;
- the unchanged semantic witness-node count; and
- checked main cells, interaction cells, and committed bytes for every pinned
  log-size scenario.

One proposal dominates another only when it is no worse in every ranked
coordinate and strictly better in at least one. No floating-point weight,
backend timing, or mutable machine profile participates in policy identity.
Backend-specific weights may select benchmark subjects later, but are not
serialized as semantic authority.

The search configuration, semantic digest, seed-policy identity, canonical cut
sets, cost vectors, scenarios, and proposal digests are encoded in a separate
section-framed `STWAIRM\0` artifact. A machine TSV and human Markdown report are
deterministic projections of that artifact. Check mode is fail-closed; update
mode is explicit and atomic. Compatibility manifests, H-005 witness plans,
H-006 relation plans, production build graphs, and proof statements do not
import the proposal artifact.

H-010 benchmarks ordered representatives from the retained frontier. A
proposal must still reproduce the typed Poseidon function and satisfy the same
degree bound before it is measured. This ADR does not approve any proposal for
production.

## Consequences

- A claimed structural improvement names the exact cut set and complete shifted
  cost vector rather than a single attractive metric.
- Global direct-DAG sharing is counted once, matching the production lowering
  model closely enough to choose honest benchmark candidates.
- Search is reproducible across allocator order, host, backend, and thread
  count; only checked integers and canonical byte order affect the result.
- The retained frontier can contain trade-offs rather than manufacturing one
  “winner.”
- Bounded local search can miss a better distant cut set. Every artifact and
  report must say so, and no result may be described as globally minimal.
- More columns can remain nondominated when they materially reduce composition
  work or live pressure; that is a hypothesis for H-010, not a performance win.
- No production witness, constraint, layout, transcript, or verifier authority
  changes.

## Rejected alternatives

- **Minimize materialization count only:** rejected because commitment savings
  can increase globally shared composition work and memory pressure.
- **Sum expanded equality syntax:** rejected because production lowering
  hash-conses across roots.
- **Use one weighted score:** rejected because weights hide shifted cost and
  are backend- and machine-dependent.
- **Random or wall-clock-guided search:** rejected because it cannot produce a
  canonical policy artifact and entangles exploration with transient hardware.
- **Mutate compatibility v1 in place:** rejected because it would erase the
  exact rollback and differential oracle established by H-004 through H-007.
- **Claim global optimality from bounded search:** rejected because the shared
  DAG cut problem is combinatorial and the experiment does not carry such a
  proof.

## Revisit when

H-010 identifies a verified frontier representative worth production review,
a backend exposes a materially different structural cost dimension, an exact
optimizer becomes practical for this graph class, or a statement-global layout
requires joint optimization across components.
