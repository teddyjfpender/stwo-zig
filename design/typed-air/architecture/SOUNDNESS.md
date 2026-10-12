# Soundness and assurance contract

**Status:** project-specific preservation plan
**Last updated:** 2026-08-04

This document does not promote any repository soundness claim. It records what
the project must preserve and what new obligations it introduces.

## Authority chain

1. Pinned Sail owns admitted RV32IM retirement semantics.
2. Production typed semantics own shipped AIR constraints and relation events.
3. AIR IR v2 binds the formal exporter to that production program.
4. The composition contract owns cross-row state, memory, program, and public
   boundaries.
5. The proof system and verifier have separate computational-integrity
   obligations.

The compiler is inside the trusted implementation path until its outputs are
validated and its lowering is covered by formal evidence. Calling it
“single-source” does not make it trusted without review.

## Threat model

The design must address:

- a type or lowering bug changing a polynomial;
- honest witness and AIR sharing the same wrong semantic assumption;
- a materialized column not fully bound;
- a hint output remaining free in an exceptional case;
- missing or double selector gating;
- degree underestimation;
- relation arity, role, order, or domain confusion;
- padding or zero multiplicity creating live calls;
- repeated calls being undercounted;
- field wrap causing source cancellation or tuple collision;
- register aliases hiding a self-loop through reused clocks;
- detached function or state cycles;
- nondeterministic layout or constraint ordering;
- runtime and formal exporters consuming different programs;
- CPU and Metal accelerators evaluating different roots;
- a guest precompile changing base-RV32IM semantics invisibly;
- independently proven components using unrelated relation challenges; and
- recursion aggregating proofs without binding their shared calls.

## Required invariants

### S-01 — exact production/formal identity

The shipped evaluator and formal exporter consume the same lowered program.
Compatibility lowering reproduces AIR IR v2. No handwritten parallel list is
accepted.

### S-02 — complete degree accounting

Degree includes gates, masks, boundary selectors, materialization equalities,
lookup numerators, interaction recurrences, and batching. The accepted layout
contains a machine-checkable degree report.

### S-03 — explicit word/field boundary

Architectural words and field values are distinct types. Every conversion
carries a bound or decomposition proof. The project must not widen the current
FV-3 claim.

### S-04 — hint closure

Every hinted output is bound in all selector and exceptional cases. Each hint
class has a negative mutation demonstrating rejection.

### S-05 — typed relation domains

Schemas determine field types, domain/version separation, roles, event order,
and multiplicity. An event cannot be constructed with the correct arity but
wrong meaning.

### S-06 — liveness and multiplicity

Every live caller contribution is matched by a live supplier contribution with
bounded integral multiplicity. Padding and inactive rows contribute zero.
Duplicate calls are neither lost nor freely invented.

### S-07 — ordered architectural effects

Register and memory effects preserve source-before-destination subclocks,
strict clock gaps, x0 behavior, and alias safety. DSL sugar may not hide or
reorder those events.

### S-08 — state reachability

Public initial and final state events and monotone clocks exclude detached
state cycles exactly as required by the current composition contract.

### S-09 — function uniqueness

A relation-backed pure function must establish that live inputs determine its
outputs under all constraints and fixed-table memberships. Syntactic purity is
not a uniqueness proof.

### S-10 — no unchecked recursion

The initial function graph is acyclic. Later recursion requires an accepted
well-foundedness argument and cannot rely on multiset cancellation alone.

### S-11 — layout identity

Column order, event order, batching, trace geometry, and program roots are
canonical manifest data bound into artifacts where protocol-relevant.

### S-12 — shared challenge context

Relations that cancel are evaluated under the same transcript-derived
challenges. Future separate proofs expose and recursively compare bound
relation summaries.

### S-13 — backend equivalence

CPU, SIMD, Metal, and any generated fast path evaluate the same canonical
roots. A backend capability is admitted by semantic identity, not by function
pointer or workload name.

### S-14 — independent architecture evidence

Generated execution, when introduced, remains differential against pinned Sail,
Spike, architectural tests, and retained negative vectors. Shared generation
cannot serve as its own oracle.

## New proof obligations for precompiles

A guest precompile must establish:

1. invocation admission and decode are statement-bound;
2. core-visible inputs are the relation inputs;
3. core-consumed outputs are the relation outputs;
4. the specialized AIR makes outputs unique for inputs;
5. all calls appear with exact multiplicity;
6. call and supply tables close under the shared relation;
7. padding cannot supply a call;
8. exceptional inputs have one specified result or reject;
9. public call count and component geometry cannot be changed after challenge
   derivation;
10. the guest ABI's relationship to base RV32IM is stated accurately; and
11. any recursive aggregation verifies the same call commitment or relation
    summary on both sides.

## Evidence required per migration

For one component:

- exact current-versus-lowered constraint DAG comparison;
- exact relation-event comparison;
- random concrete replay;
- honest witness equality;
- one mutation per new witness/hint class;
- real prove and independent verify;
- source-bound formal export;
- deterministic manifest reproduction;
- CPU/Metal equivalence where accelerated;
- Sail differential for architectural behavior; and
- claim-ledger review.

Removing an old implementation requires all applicable evidence to be green in
the same revision.

## Change-impact rules

| Change | Minimum impact |
| --- | --- |
| Logical refactor with identical lowered manifest | focused IR tests, exact export differential, RISC-V package tests |
| Constraint or relation change | adversarial tests, proof gate, AIR IR regeneration, formal review |
| Column/order/batching change | protocol/version decision, golden manifest diff, proof artifact and verifier update |
| Hint change | honest differential plus forged-output mutation |
| Architectural effect change | live Sail/Spike differential and refinement regeneration |
| Precompile ABI change | statement/artifact version, guest corpus, relation closure and verifier tests |
| Backend lowering change | production-root identity, CPU reference differential, backend fail-closed gate |
| Recursive relation summary change | recursive verifier proof and independent cross-proof mismatch negatives |

## Claim language

During development, permitted statements are specific:

- “The compatibility lowerer reproduces the current LUI constraint and event
  program.”
- “The generated Poseidon witness satisfies and matches the current component
  on the tested corpus.”
- “The core and precompile tables close one shared relation in one proof.”

Until the corresponding proofs exist, do not say:

- the compiler guarantees AIR soundness;
- the RISC-V frontend is formally verified;
- precompile proofs can be composed independently;
- recursion proves reachability; or
- parallel proving reduces total work.
