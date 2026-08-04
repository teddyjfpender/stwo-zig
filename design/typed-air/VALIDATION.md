# Validation and evidence plan

**Status:** required gate design
**Last updated:** 2026-08-04

## Principle

Validation is layered because no single green test answers every question.
Every change names which layers it affects and runs all corresponding gates.

## Evidence ladder

### V0 — structural IR

Answers: is the program well-formed?

- type and ID validation;
- function-graph acyclicity;
- hint binding;
- relation schema/role/arity;
- effect order and access ordinals;
- deterministic serialization;
- ownership and allocation failure.

### V1 — production equivalence

Answers: did compatibility lowering preserve the current program?

- root-by-root normalized expression comparison;
- concrete random replay;
- column names/count/order;
- lookup domain/role/arity/value/order;
- batch size and interaction placement;
- runtime polynomial program identity;
- AIR IR v2 identity;
- witness column equality.

### V2 — adversarial witness

Answers: does the proof reject targeted prover freedom?

- mutate every new materialization class;
- mutate every hint output and exceptional selector;
- omit, duplicate, or alter relation calls;
- activate padding;
- change multiplicity or component count;
- alias register accesses;
- violate clock gaps;
- change public/component boundaries.

Each negative records the expected rejection stage and, where possible, the
specific constraint or relation that is load-bearing.

### V3 — proof path

Answers: does production prove and independently verify?

- focused real proofs;
- separate-process verification;
- statement and transcript identity;
- malformed artifact negatives;
- CPU and Metal paths where applicable;
- no backend fallback.

### V4 — architectural and formal

Answers: does the admitted AIR retain its semantic authority and formal binding?

- pinned Sail/Spike differential;
- architectural tests;
- AIR IR regeneration;
- Lean build and axiom/source inventory;
- claim-ledger review;
- cross-row composition obligations.

### V5 — performance

Answers: did the change improve its stated resource without hiding another?

- verified samples only;
- baseline and candidate from clean comparable builds;
- trace cells and degree;
- stage time and total wall time;
- total CPU/GPU work;
- peak memory and concurrency;
- proof size and verification time;
- host, power, compiler, commit, and protocol identity.

## Focused development commands

RISC-V package:

```sh
zig build test \
  --build-file src/frontends/riscv/build.zig \
  -Doptimize=ReleaseFast -j2
```

Focused semantic tests while iterating:

```sh
zig build test-air-semantics \
  --build-file src/frontends/riscv/build.zig \
  -Doptimize=ReleaseSafe
```

Production RISC-V product gate:

```sh
zig build test-riscv-cpu-product -Doptimize=ReleaseFast
```

Exhaustive proof/adversarial gate before removing an implementation:

```sh
zig build test-riscv-release-exhaustive -Doptimize=ReleaseFast
```

Formal AIR export:

```sh
zig build riscv-refinement-ir \
  -Driscv-refinement-ir-dir=zig-out/family-air
```

Lean source build:

```sh
(cd formal/riscv-refinement && lake build)
```

Live Sail and receipt commands remain those in
[`RISCV_FRONTEND_VERIFICATION_STATUS.md`](../../soundness/RISCV_FRONTEND_VERIFICATION_STATUS.md).
They are required when architectural semantics, source binding, or published
formal artifacts change.

## Compatibility golden data

For each component, retain a machine-readable manifest with:

- logical program identity;
- accepted layout policy;
- main and interaction columns;
- direct roots and inferred degree;
- relation events and batching;
- hint recipes;
- formal/runtime program identity; and
- source revision.

Golden checks have two commands:

- `check` regenerates in memory and requires byte identity;
- `update` writes a proposed artifact and prints a semantic diff.

Tests never update goldens automatically. A reviewer must be able to see why
every changed column or event moved.

## Differential design

Expression comparison should not rely solely on node IDs. Normalize or compare
structural DAGs with explicit operation/type/operand identity. For every root:

1. compare structural form;
2. replay fixed boundary values;
3. replay deterministic random M31 values;
4. compare production QM31 evaluation where applicable; and
5. report the first divergent source path.

Witness comparison uses exact M31 values in canonical committed row order. It
does not compare only final outputs.

## Mutation design

Mutations are generated from typed metadata:

- committed witness column;
- hint output;
- selector;
- call field;
- liveness/multiplicity;
- effect clock;
- output/boundary value.

Each mutation record contains:

- component and row;
- semantic value and physical column;
- original and forged values;
- expected guard;
- actual rejection stage;
- proof existence; and
- verification result.

A mutation rejected by an unrelated bus may be useful coverage but is not
attribution. Row-local or isolated-relation tests remain required.

## Precompile-specific cases

The Poseidon precompile must test:

- zero calls;
- one call;
- duplicate equal calls;
- distinct calls with equal output lane;
- maximum admitted calls;
- inactive padding;
- wrong input;
- wrong output;
- wrong mode/domain;
- omitted supplier;
- duplicated supplier;
- incorrect multiplicity;
- changed component geometry;
- cross-transcript relation summary, when recursion exists; and
- native software versus precompile output equivalence.

## Backend evidence

A backend accelerator receives the canonical lowered program identity and
declares the exact capability it implements. Required tests:

- reference evaluator versus backend on deterministic random rows;
- all-zero, all-one, and maximum canonical field cases;
- active and inactive rows;
- every constraint root and relation entry;
- mismatched program identity rejects;
- missing authenticated Metal artifact rejects;
- no CPU fallback in a Metal product.

## Clean-tree milestone receipt

At M3 and later milestones, record:

- commit and clean-tree state;
- Zig, Python, Lean, and Sail versions as applicable;
- logical and layout manifests;
- exact commands;
- test counts and results;
- proof/verifier receipt identities;
- benchmark report identity; and
- known open claims.

The receipt describes evidence. It does not promote the claim ledger by itself.

## Required gates by change class

| Change class | V0 | V1 | V2 | V3 | V4 | V5 |
| --- | :---: | :---: | :---: | :---: | :---: | :---: |
| IR-only, no lowered change | yes | targeted | targeted | no | source check | benchmark if hot |
| Compatibility lowering | yes | full | targeted | focused | AIR IR | yes |
| Constraint/relation change | yes | semantic diff | full | full | full | yes |
| Witness implementation | yes | witness full | full | full | Sail if architectural | yes |
| Layout/materialization | yes | manifest full | full | full | regenerate | full |
| Precompile ABI/component | yes | component | full | full | profile/formal review | full |
| Parallel scheduler | structural | byte/protocol | failure injection | full | no semantic drift | full |
| Recursive aggregation | yes | summaries | full cross-proof | full | theorem review | full |
