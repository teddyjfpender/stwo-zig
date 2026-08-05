# Validation and evidence plan

**Status:** required gate design
**Last updated:** 2026-08-05

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

Typed-AIR compatibility artifact check:

```sh
zig build typed-air-manifest \
  --build-file src/frontends/riscv/build.zig \
  -Doptimize=ReleaseFast
```

An intentional reviewed replacement adds
`-Dtyped-air-manifest-mode=update`. Check is the default; tests never select
update mode.

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

Golden artifact tooling has two explicit modes:

- `check` regenerates in memory and requires byte identity;
- `update` atomically writes a proposed artifact.

Tests never update goldens automatically. A reviewer must be able to see why
every changed column or event moved. A-012 supplies the field-aware semantic
diff used for that review. Both bodies are validated first; check then reports
the first named generated-versus-on-disk difference together with file lengths
and SHA-256 identities before failing.

M2 established the report check half of this contract: the package test renders
[`m2-production-shadow-report-v1.tsv`](artifacts/m2-production-shadow-report-v1.tsv)
and its [readable view](artifacts/m2-production-shadow-report-v1.md) in memory
and requires byte identity. A-011 adds the explicit family-manifest check/update
command. A-012 parses that sectioned `compat-v1` object without allocation and
compares detailed layout, runtime, relation, degree, hint, and formal records
before their repeated identity digests.

A-006 additionally reconstructs the existing Sail-authoritative witness-layout
digest from `compat-v1` descriptors and compares every physical name directly
to reflected production fields. Separate tests resolve local references at
nonzero offsets and require exact agreement with the semantic and lookup
backend capabilities. Logical and physical names are compared as a mapping,
not assumed equal.

A-007 compares direct lowering against an independent linear-interning
normalizer rather than sharing the implementation's hash-consing machinery.
All 17 families require exact normalized node slices and all 545 ordered roots,
then compare every root again under four deterministic randomized M31
assignments per family. The owned result separately exercises deterministic
reconstruction, structural corruption, malformed replay buffers, and induced
allocation failure.

A-008 extends that oracle to production lookup-only programs. Canonical
topological relabeling makes comparison independent of constants first interned
by an unrelated direct section. Every family requires exact node and flattened
`numerator, tuple...` root identity; every event separately matches schema,
role, arity, ordinal, order, and role-signed liveness, while every batch matches
its four physical interaction references. Random replay covers all 242 events;
corruption, sign mismatch, deterministic reconstruction, and allocation failure
are separate gates.

A-009 requires exact canonical node, ordered-root, and column identity for the
direct runtime type across all 17 families. The lookup runtime type additionally
requires every entry numerator/tuple root and arity, batch count, parameter
count, and deterministic unused tail. Both exporters validate input and output;
malformed owners and induced allocation failure are explicit negatives.

A-010 requires whole-byte equality with the existing AIR IR v2 writer, not a
parsed-object comparison. The compatibility path independently reconstructs
selector-to-one placement, source node numbering/orientation, column roles,
event ordinals, opcode projection, and fixed-table metadata, then uses the one
existing encoder. LUI is the acceptance floor; every manifest opcode is tested.
Digest-bound raw provenance corruption and allocation failure are negatives.

A-011 emits 17 separately reviewable `STWAIRC\0` version-1 manifests in
production-family order. Their seven framed sections carry authority and
source identities, all physical column descriptors, complete direct and lookup
runtime bytes, named roots, typed event and physical batch metadata, final
degree records, hint recipes, and formal export identities. Runtime ownership
is revalidated before serialization. Every formal entry is admitted only after
the typed and production AIR IR v2 bodies compare byte for byte, then records
its opcode, mnemonic, exact byte length, and SHA-256. The aggregate TSV index
pins each whole manifest and its source/semantic, layout, runtime, degree, and
formal digests together with geometry, export counts, and maximum direct and
interaction degree.

The package suite regenerates all 17 binaries and the index in memory and
requires exact bytes from the embedded checked artifacts. Separate determinism
and family-order negatives fail closed. Allocation testing uses a stable scratch
allocator for the legacy panic-on-OOM production symbolic builder and injects
failure at every allocation owned by new runtime/receipt results, requiring all
partial owners to deinitialize. The standalone command exposes default `check`
and explicit atomic `update`; see
[ADR-0017](decisions/0017-sectioned-compatibility-manifests.md).

A-012 validates the generated and on-disk manifest independently before
comparison. Its structured result is equality, one borrowed first difference,
or a malformed-side diagnostic with a stable semantic path and byte offset.
Tests cover all 17 equal artifacts; logical and physical column names; moved
references; runtime nodes and named roots; lookup schema, role, event, and batch
records; degree/formal identity; malformed framing, UTF-8, optionals, runtime
programs, and trailing bytes; and expected-side precedence. The command was
also exercised end to end against a temporary corrupted LUI artifact: check
named `layout.main[16].physical_name`, update rendered the same difference
before atomic repair, and the following check passed. Invalid magic was
attributed to `actual/on-disk` at `header.magic`.

H-005, H-006, and H-008 add the Poseidon-specific V1/V2 bridge. H-005 compiles the
authenticated typed closure independently of the production witness generator
and compares all 445 final columns across every mode, deterministic randomized
traces, bit-reversed placement, and zero padding. Shape, alias, executable, and
slot corruptions must fail before a sentinel destination changes; construction
is swept under allocation failure. H-006 independently derives four relation
entries, two pairs, eight interaction columns, and two claims, then compares
each with production and rejects tuple, mode, multiplicity, order, role,
domain, geometry, column, claim, and carried-output forgeries. H-008 binds all
426 generic/physical identities in a canonical 37-field report with golden
SHA-256
`33eadd080a715fe09d1b3ed3ad8abc18cb35f71e56895e6ac62810a1dfeb0ef2`.

These gates establish shadow witness and relation equality, not V3 proof-path
equivalence. H-007 must commit the generated main and interaction artifacts
inside real CPU and Metal proofs and independently verify them; proving the
unchanged production artifacts after an out-of-band equality assertion is not
sufficient.

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
The first concrete instance is the
[M3 compatibility receipt](receipts/m3-compatibility-v1.json), which records
green compatibility and focused proof evidence together with the broad
prover-core and formal-artifact gates that remain red.

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
