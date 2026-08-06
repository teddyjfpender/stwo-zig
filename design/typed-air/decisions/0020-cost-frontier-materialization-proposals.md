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
5. lowers an authenticated fixed prefix, all candidate equalities, and an
   authenticated fixed suffix, in that order, into one canonical, globally
   hash-consed direct polynomial DAG;
6. derives a canonical cost-model digest from the fixed-program identity and
   phase schedule, and binds that digest independently into the search
   configuration and every proposal; and
7. retains the nondominated frontier under an integer cost vector, with
   deterministic digest ordering only for deduplication and bounded retention.

For the Poseidon pilot, the fixed program is the permutation direct-AIR scope,
not the surrounding hash-component shell or its LogUp interactions. It
authenticates the main-tree materialization start, three main-column roles
(`enabler`, `wide`, and `io`), their candidate-relative placements, eleven
canonical SSA nodes, and four fixed roots. Fixed columns are rejected if they
alias the candidate interval. The enabler boolean root is the prefix; the wide
and io boolean roots
and their mutual-exclusion root are the suffix. Candidate materialization
equalities are lowered between those phases. Scope and format versions, the
fixed-program digest, column/node/root counts, and this evaluation schedule all
enter the cost-model digest. A matching root count without the matching
program identity is not the same cost model and fails closed.

The structural vector contains at least:

- materialization and total main-column counts;
- direct-root and fixed interaction-column counts;
- globally unique direct nodes and operation counts, including
  multiplications;
- distinct committed-column reads;
- canonical streaming peak-live nodes under a specified first-intern order in
  which roots fold at explicit ordered events and values are released after
  their final operand or root use;
- the unchanged semantic witness-node count; and
- checked main cells, interaction cells, and committed bytes for every pinned
  log-size scenario.

One proposal dominates another only when it is no worse in every ranked
coordinate and strictly better in at least one. No floating-point weight,
backend timing, or mutable machine profile participates in policy identity.
Backend-specific weights may select benchmark subjects later, but are not
serialized as semantic authority.

The search configuration, semantic digest, seed-policy identity, canonical
cost-model identity and digest, canonical cut sets, cost vectors, scenarios,
and proposal digests are encoded in a separate section-framed `STWAIRM\0`
artifact. The configuration digest commits to the cost-model digest, and each
proposal digest commits to it again alongside the cut and costs. A machine TSV
and human Markdown report are deterministic projections of that artifact.
Check mode is fail-closed; update mode is explicit and atomic. Compatibility
manifests, H-005 witness plans, H-006 relation plans, production build graphs,
and proof statements do not import the proposal artifact.

The implemented complete one-pass Poseidon neighbourhood is a cost plateau,
not a speedup. With an evaluation cap of 2,048, beam width 64, frontier limit
128, and log sizes 4, 6, 10, 14, and 18, the canonical neighbourhood contains
1,124 edits: 410 removals, 304 additions, and 410 swaps. The run evaluates all
1,124 without exhausting its budget, accepts 430 unique feasible proposals,
rejects 694 infeasible proposals, and encounters no duplicates. It retains 126
distinct, untruncated non-seed cuts, but every retained report equals the seed
report in the complete structural vector and every scenario cost. The seed has
426 materializations, 445 main columns, 430 direct roots, 3,460 canonical
direct nodes, 1,346 additions, 429 subtractions, 1,080 multiplications, 445
distinct committed reads, a canonical streaming peak of 39 nodes, and 2,171
semantic witness nodes. This is useful negative evidence about the local
neighbourhood. The checked binary and exact readable projections satisfy
H-009's prototype acceptance, but they do not identify an H-010 performance
winner.

H-010 benchmarks ordered representatives from the retained frontier. A
proposal must still reproduce the typed Poseidon function and satisfy the same
degree bound before it is measured. This ADR does not approve any proposal for
production.

## Consequences

- A claimed structural improvement names the exact cut set and complete shifted
  cost vector rather than a single attractive metric.
- Global direct-DAG sharing is counted once, matching the production lowering
  model closely enough to choose honest benchmark candidates.
- Fixed algebra is counted in the same direct DAG and authenticated by content,
  not represented by an unauthenticated root-count constant.
- Search is reproducible across allocator order, host, backend, and thread
  count; only checked integers and canonical byte order affect the result.
- The retained frontier can contain trade-offs or multiple cost-equivalent
  cuts rather than manufacturing one “winner.” Cost-equivalent cuts are not
  structural improvements.
- Bounded local search can miss a better distant cut set. Every artifact and
  report must say so, and no result may be described as globally minimal.
- More columns can remain nondominated when they materially reduce composition
  work or live pressure; that is a hypothesis for H-010, not a performance win.
- The streaming peak is an optimization opportunity, not current-backend
  telemetry. The 3,460-node count is the modeled hash-consed proposal DAG, not
  observed production scratch: the current Poseidon component uses a separate
  static evaluator, has no alternative-layout CPU/Metal execution path, and
  has no Metal composition capability. H-010 must first build one common
  candidate evaluator, then report its actual storage and measured memory
  separately from the 39-node theoretical schedule.
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
