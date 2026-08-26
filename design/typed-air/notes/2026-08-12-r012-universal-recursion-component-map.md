# 2026-08-12 — R-012 universal recursion typed-AIR map and first substrate

## Question

What does “all recursion-local components through the typed compiler” mean at
an executable, non-marketing boundary, and what is the smallest useful piece we
can land without claiming that a recursive verifier exists?

## Exact sources and revisions

The reference is Stark-V commit
`59172a201bd01f2f4b699bc2f7d4442d8ee81597` from
`origin/chore/scratchpad-cleanups`. The adjacent checkout was on
`outbound/metal-backend` at `71d4584011201c7c0bcfa078992f9139e60a427e`;
its older nine-table recursion layout is not used as authority here. Every
reference below was read from the exact Git object with `git show` or
`git grep`, without switching that worktree.

The decisive sources are:

- `docs/recursion.md`, which describes the live universal verifier, its three
  proof branches, its honest incomplete tree/API boundary, and its 36-component
  fixed roster;
- `crates/recursion/src/recursion_air_program.rs`, whose
  `UNIVERSAL_COMPONENT_NAMES` fixes commitment, interaction, and composition
  order;
- `crates/recursion/tests/air_dsl_guard.rs`, which pins every universal and
  inner-VM component to an owning source and rejects hand-written
  `FrameworkEval`, standalone `define_component_tables!`, wrapper macros, and
  unrecognized item macros;
- `crates/recursion/src/qm31_mul.rs`, whose one `define_air_fns!` frame owns the
  complete multiplication table, witness fill, constraints, preprocessing,
  relations, evaluator, and interaction trace.

The local design input is the user-supplied `idea.txt` from the Downloads
directory. Its final rule is the acceptance boundary, not merely inspiration: every AIR source
reachable from recursion must be compiler-authored; a legacy table declaration
plus a manual evaluator is migration input, not a finished component.

## The no-escape-hatch contract

A Zig recursion component is complete only when all eight properties hold:

1. **One semantic owner.** Physical inputs, derived expressions, constraints,
   functions, and relation statements are nodes in the validated typed IR.
   Hand-written production symbolic roots or a second component evaluator are
   forbidden.
2. **Witness binding.** The direct/generated witness path is authenticated to
   the semantic digest and exact physical recipe. It writes final column-major
   storage directly, rejects malformed geometry before mutation, and has no
   legacy witness fallback.
3. **Verifier-owned schedule.** Preprocessed columns, proof-kind selectors,
   fixed capacities, and use counts are typed inputs whose identities are
   fixed by the protocol manifest, never selected by proof bytes.
4. **Typed relation closure.** Every relation schema, version, arity, role,
   multiplicity, order, and batch is compiler data used by both AIR evaluation
   and interaction-witness generation. A duplicated `combine`/`write` formula
   does not pass.
5. **Compiler evidence.** Semantic identity, physical width, root/effect count,
   maximum logical and modeled interaction degree, DAG size/reuse, and dead
   nodes come from the static profiler and are digest-pinned.
6. **Universal inventory wiring.** The concrete prover/verifier component and
   fixed roster evaluate the same compiled program. A test-only scalar replay
   is necessary evidence but is not production integration.
7. **Adversarial closure.** Constraint mutations, relation imbalance,
   inactive-lane smuggling, schedule substitution, branch substitution, and
   transcript/statement detachment are rejected at their authoritative gate.
8. **Mode and proof gates.** Debug, ReleaseSafe, and ReleaseFast component
   gates pass; once integrated, a real prove/independent-verify gate and proof
   mutation fleet also pass.

This definition intentionally makes “typed source exists” weaker than
“component migrated,” and “component migrated” much weaker than “recursive
verifier complete.”

## Authoritative 36-component universal roster

All 36 owners are accepted direct DSL sources at the reference revision. The
“Zig closure” column is the R-012 state after this change, not Stark-V status.

| # | Universal component | Reference owner | Responsibility / critical seam | Zig closure |
| ---: | --- | --- | --- | --- |
| 0 | `control` | `control_air.rs` | Manifest-owned VM/left/right verifier step schedule; `step(7)` | **Exact logical component, concrete adapter, and real proof-byte gate** |
| 1 | `transcript_air` | `transcript_air.rs` | Atomic Poseidon hash call, rate input/output and sponge state chaining | **Exact logical component, generic adapter, and shared Poseidon closure** |
| 2 | `transcript_binding` | `transcript_binding_air.rs` | Fixed frame/call coordinates to hash, PoW, step and word relations | **Exact logical component, schedule-derived witness, and generic adapter** |
| 3 | `transcript_state` | `transcript_state_air.rs` | Persistent digest transition and scoped draw ownership | **Exact logical component, schedule-derived witness, and generic adapter** |
| 4 | `transcript_word` | `transcript_word_air.rs` | Fixed header/delimiter/padding words and delegated payload slots | **Exact logical component, schedule-derived witness, and generic adapter** |
| 5 | `transcript_payload` | `transcript_payload_air.rs` | Protocol/PCS constants and indexed statement/proof word ownership | **Exact logical component, schedule-derived witness, and generic adapter** |
| 6 | `pow_check` | `pow.rs` | Canonical M31 low-bit predicate, scoped by verifier/kind/call | **Exact logical component, schedule-derived witness, and generic adapter** |
| 7 | `pow_frame` | `pow.rs` | Transcript PoW frame ownership and check activation | **Exact logical component, transcript-frame witness, and generic adapter** |
| 8 | `relation_challenge` | `relation_challenge_air.rs` | Atomic challenge draw and separately scoped challenge consumers | **Exact logical component, three-lane schedule witness, and generic adapter** |
| 9 | `verifier_randomness` | `verifier_randomness_air.rs` | Secure draws/query words with verifier/kind/item/limb ownership | **Exact logical component, complete 193-query schedule witness, and generic adapter** |
| 10 | `statement_input` | `statement_input_air.rs` | Transcript statement words to segment/left/right private scopes | **Exact logical component and generic adapter** |
| 11 | `statement_semantics_input` | `statement_semantics_input_air.rs` | Statement circuit inputs, byte decomposition/range proof, wire uses | **Exact logical component and generic adapter** |
| 12 | `vm_public_claim_input` | `vm_public_claim_input_air.rs` | Fixed VM public claim words, capacities, range classes and scopes | **Exact logical component and generic adapter** |
| 13 | `vm_public_claim_hash` | `vm_public_claim_hash_air.rs` | Poseidon claim-word hash bound to transcript digest | **Exact logical component, schedule-derived witness, generic adapter, and shared Poseidon closure** |
| 14 | `vm_public_io_hash` | `vm_public_io_hash_air.rs` | Domain-separated public input/output stream hashes | **Exact logical component, dual-stream witness, generic adapter, and shared Poseidon closure** |
| 15 | `vm_public_claim_semantics_input` | `vm_public_claim_semantics_input_air.rs` | Claim-to-statement circuit inputs and exact wire multiplicities | **Exact logical component and generic adapter** |
| 16 | `vm_public_logup_input` | `vm_public_logup_input_air.rs` | Claim/challenge/sum inputs for public LogUp arithmetic | **Exact logical component and generic adapter** |
| 17 | `vm_public_logup_control` | `vm_public_logup_control_air.rs` | Trusted public-term steps and global-zero assertion | **Exact logical component and generic adapter** |
| 18 | `vm_air_composition_input` | `vm_air_composition_input_air.rs` | VM/recursion sampled values, sums, randomness, statements and constants to composition wires | **Exact logical component, generic adapter, and production VM-graph real proof gate** |
| 19 | `vm_air_composition_control` | `vm_air_composition_control_air.rs` | Fixed AIR-evaluation spans and composition assertions | **Exact logical component and generic adapter** |
| 20 | `query_bits` | `query_position_air.rs` | Unique 31-bit decomposition of transcript raw query words | **Exact logical component and generic adapter** |
| 21 | `query_mapping` | `query_position_air.rs` | Fixed routing to trace, DEEP, FRI subtree/fold and last-layer uses | **Exact logical component and generic adapter** |
| 22 | `merkle_root` | `merkle_root_air.rs` | Transcript roots expanded into verifier/tree/query-scoped root claims | **Exact logical component and generic adapter** |
| 23 | `trace_merkle` | `trace_merkle_air.rs` | Fixed trace-leaf hashing, path anchor, authenticated values to DEEP | **Exact logical component and generic adapter** |
| 24 | `pcs_deep_input` | `pcs_deep_input_air.rs` | DEEP circuit inputs/outputs and exact wire multiplicities | **Exact logical component and generic adapter** |
| 25 | `fri_merkle_leaf` | `fri_merkle_air.rs` | Packed secure-evaluation FRI leaf construction | **Exact logical component and generic adapter** |
| 26 | `fri_merkle_node` | `fri_merkle_air.rs` | Local packed-subtree internal hash nodes | **Exact logical component and generic adapter** |
| 27 | `fri_merkle_anchor` | `fri_merkle_air.rs` | Local root to global path/query/control route | **Exact logical component and generic adapter** |
| 28 | `fri_verifier_control` | `fri_verifier_control_air.rs` | DEEP/fold/last-layer schedule and query route adapter | **Exact logical component and generic adapter** |
| 29 | `fri_verifier_input` | `fri_verifier_input_air.rs` | DEEP answer, FRI values, alphas, coefficients, bits and positions to circuit wires | **Exact logical component, generic adapter, and ordered real PCS/FRI proof gate** |
| 30 | `qm31_mul` | `qm31_mul.rs` | QM31 product plus fixed circuit schedule and `wire(6)` closure | **Exact logical component and compiler-derived generic `wire(6)` adapter** |
| 31 | `qm31_inv` | `qm31_inv.rs` | Nonzero inverse plus fixed circuit schedule and `wire(6)` closure | **Exact logical component and compiler-derived generic `wire(6)` adapter** |
| 32 | `linear_ops` | `linear_ops.rs` | Scheduled QM31 add/sub/neg with operand/result wire multiplicities | **Exact logical component and compiler-derived generic `wire(6)` adapter** |
| 33 | `merkle_path` | `merkle_path.rs` | Atomic Poseidon step and parent-to-selected-child node chain | **Exact logical component, generic adapter, shared Poseidon closure, and nonzero-interaction real PCS/FRI proof gate** |
| 34 | `poseidon2` | `crates/air/src/poseidon2.rs` | Shared typed permutation component | **Authenticated shared-provider bridge; deliberately not a duplicate logical owner** |
| 35 | `range_check_8_8` | `crates/air/src/schema.rs` | Shared two-byte range table | **Authenticated zero-duplicate bridge to the production 2^16 table** |

The roster order is protocol data: it determines trace commitment layout,
claimed-sum order, sampled-mask reconstruction, and composition traversal. A
name-compatible unordered registry is insufficient.

## Current closure and proof evidence

The executable inventory now admits all 34 logical universal rows as exact
typed-AIR components. One compiler-owned adapter factory authenticates all 34
definitions, relation plans, protocol degrees, column geometry, roster
offsets, claimed-sum indices, and semantic identities. Rows 34 and 35 are
authenticated delegations to the sole native Poseidon2 and fixed `(8, 8)`
range-table owners. The allocation-free whole-roster builder seals these as one
ordered 36/36 manifest. This is complete AIR/component authority, not a claim
that all 36 rows already participate in one proof.

The first ordered generic-adapter proof contains rows 29 and 33. It remains a
small all-mode identity gate: 20 preprocessed, 48 main, 28 interaction columns,
21 constraints, and a 5,184-byte estimate with identical transcript output.

The active captured-leaf proof now contains the contiguous rows 18--34. It
commits 347 preprocessed, 760 main, and 276 interaction columns, evaluates 862
constraints, and binds 52,303 consumer permutations to the one authenticated
row-34 Poseidon2 provider at the frozen 2x/193 profile. It independently
verifies at a 66,308-byte estimate and rejects public-boundary, wire-closure,
row-18 value, row-19 claimed-sum, and preprocessing-root mutations. Together
with the separately proven row-0 control adapter, the honest real-proof union
is 18/36. Rows 1--17, row 35, and full global relation closure are not implied by
this partial outer proof. See the
[row-24 evidence note](2026-08-13-pcs-deep-row24-proof.md).

Rows 34 and 35 are deliberately not counted as second logical owners. Their
bridges authenticate and reuse the shared production Poseidon2 provider and
the fixed 2^16 `(8, 8)` range table, respectively. Both bridges close exact
relation tuples while adding zero duplicate direct AIR roots.

Row 34 is now live in the captured-leaf proof. Its typed program identity gates
the specialized byte-exact witness kernel; Tree 2 consumes the 16 output words
retained from those exact committed rows and never replays the permutation.
The assembly audits exact provider/request cancellation before proving. Row 35
is still outside this proof and remains part of the unproved roster remainder.

Rows 1, 13, and 14 close the former shared-hash gap without copying permutation
equations. Each carries a pinned Stark-V source receipt, exact typed direct and
relation programs, sealed schedule and static profile, direct allocation-free
writers, provider cancellation, neighboring-row cancellation, alias/OOM
rejection, and adversarial state/digest mutations. The provider is the exact
general Stark-V Poseidon shell: 430 direct constraints plus two paired LogUp
constraints, one first-row preprocessing selector, and no memory-only activity
selector.

The recursion edit loop is now dependency-isolated from the opcode runner.
`test-recursion-air-core` covers all recursion-local typed AIR; the filtered
`test-recursion-air-edit` is the shortest mutation loop; and
the CPU integration package's `test-recursion-air-proof` step owns the native
PCS/FRI gate through the frontend's public recursion namespace. The frontend
therefore retains no concrete backend dependency or second module identity.
The integrated shared-provider gate currently passes in all three optimization
modes, as does the decoupled core. The whole-roster test additionally verifies
every offset, claimed-sum slot, semantic identity, log size, and final manifest
seal.

## Recursion-reachable inner VM roster

The same Stark-V guard also pins the 27 inner VM owners whose constraints are
replayed by the segment branch:

`auipc`, `base_alu_imm`, `base_alu_reg`, `branch_eq`, `branch_lt`, `div`,
`jal`, `jalr`, `load_store`, `lt_imm`, `lt_reg`, `lui`, `mul`, `mulh`,
`shifts_imm`, `shifts_reg`, `program`, `memory`, `merkle`, `poseidon2`,
`clock_update`, `bitwise`, `range_check_20`, `range_check_8_11`,
`range_check_8_8_4`, `range_check_8_8`, and `range_check_m31`.

At the reference revision all but Poseidon2 are owned by the single
`define_air!` schema; Poseidon2 is owned by one `define_air_fns!` invocation.
Our 17 typed opcode-family migrations are strong input to this boundary, but
R-012 must separately inventory the program, memory, Merkle, clock, bitwise,
range tables, and the exact component/effect replay used by recursion. Their
existence elsewhere in the VM proof does not automatically admit them to a
universal recursive verifier.

## Landed substrate: standalone QM31 multiplication

The first Zig entry is deliberately named
`recursion.qm31_mul.standalone.v1`. It implements the actual standalone-row
mode used by Stark-V's `push_mul`: two QM31 operands, their product, and the
four canonical extension-tower identities for
`QM31 = CM31[u] / (u^2 - (2 + i))`.

Executable evidence:

| Property | Value |
| --- | ---: |
| Physical M31 columns | 12 (`a[4]`, `b[4]`, `c[4]`) |
| Direct constraint roots | 4 unique semantic roots |
| Maximum logical constraint degree | 2 |
| Typed expression DAG | 48 nodes, 72 edges |
| Nodes outside constraint/effect closure | 0 |
| Effects / relation events | 0 / 0 |
| Semantic digest v1 | `03f84e6f279603a554e836fa815d303e16cca5697be263681bd52dbc2934e29e` |
| Static-profile digest v1 | `f38ce9c61b1c94adc1bed03f94efbb47b32ec0e1a891f977c885461da2f7b12a` |
| Witness-binding digest v1 | `f4092277db963c4d69d90f6b928776af54eb84b15c01f8ba5fc7ecececce10cc` |

The cold constructor validates the typed arena and exact physical/constraint
order. The prepared executor binds that semantic identity to all twelve slots.
Its hot path calls the canonical optimized `QM31.mul`, writes caller-owned SoA
storage directly, and uses the shared failure-atomic direct witness executor for
shape and alias preflight plus deterministic zero padding. Tests interpret the
typed DAG itself; they do not carry a second constraint transcription.

The corpus covers zero, one, maximum canonical coordinates, a pinned example,
and 1,024 deterministic random pairs. Adversarial tests alter every output
coordinate independently, alter every input coordinate while retaining the old
product, mutate the witness recipe, and provide malformed destination geometry.
The definition validator is also attacked by detaching its recorded expected
coordinate from the asserted root; the semantic arena remains unchanged, but
validation rejects the inconsistent metadata.

## Landed full logical `qm31_mul`

The second inventory entry, `recursion.qm31_mul.full.v1`, closes the reference
component's logical shape rather than approximating it. A subtle macro fact is
important: `qm31_mul.rs` declares eighteen committed fields, while the reference
component macro prepends its built-in `enabler`. The physical main trace is
therefore nineteen columns, not eighteen. The macro likewise prepends an
enabler-boolean root to the twelve authored roots.

| Property | Compiler-derived value |
| --- | ---: |
| Declared / physical main M31 columns | 18 / 19 |
| Preprocessed schedule columns | 18 (six × segment/binary/empty) |
| Verifier-owned proof-kind inputs | 3 |
| Logical input nodes | 40 |
| Authored / total direct roots | 12 / 13 |
| Typed `wire(6)` effects | 3 (consume, consume, emit) |
| Lookup batches / interaction M31 columns | 2 / 8 |
| Maximum logical value / constraint degree | 3 / 3 |
| Maximum lookup numerator / denominator degree | 2 / 1 |
| Maximum modeled interaction degree | 3 |
| Expression DAG nodes / edges / shared nodes | 124 / 166 / 18 |
| Maximum fanout / nodes outside closure | 10 / 0 |
| Semantic digest v1 | `a4acf0cc0f170b68aeba6b2dd72cd7189a28c78fac16d973f17a6dce63e823d1` |
| Static-profile digest v1 | `b9294600c9939994ccfe35a3d639bd724409aab6e489376f00a25dc5668fe1ca` |
| Witness-binding digest v1 | `c815b4569df6271e85754789f48f0840c97f951c961e805b53c66c0f18bd3ccd` |

The base RISC-V relation registry remains the exact twelve-schema transcript
prefix. `stwo.recursion.wire` is an appended extension with stable ID 12,
version 1, six felt fields, consume/emit roles, forbidden access ordinals, and
role-signed field weights. Thus the recursion ABI is typed without shifting an
existing relation ID or challenge draw.

The same typed arena owns the generated enabler root, the in-circuit and
schedule bindings, the four tower-product identities, and all relation effects.
The `wire` authoring helper appends the two operand consumes and the
`uses * in_circuit` result emit as one failure-atomic group. The authenticated
interaction plan is lowered from those effects. It compiles tuple and weight
projections to fixed main-column indices during cold authentication, then uses
those indices in the row loop; it does not transcribe a second tuple evaluator
or an ad hoc alpha-power denominator. The denominator is the canonical
`RelationElements(6)` implementation.

The interaction generator pairs the two consumes and leaves the weighted emit
as a singleton, matching the reference batch size of two. Its SoA pair buffer
feeds the two canonical cumulative columns directly, eliminating the previous
per-batch allocation and copy. All eight final coordinate columns share one
contiguous owned slab. The measured allocation-shape gate permits at most five
allocations for a generated interaction: one pair buffer, two cumulative
columns, one final slab, and one placement table.

The direct executor writes all nineteen main and all eighteen preprocessing
columns into final caller-owned SoA storage, validates exact geometry and alias
exclusion before mutation, and zero-pads deterministically. Its binding seals
both recipes plus the three proof-kind inputs to the semantic digest.

Adversarial evidence covers selected-schedule field changes, proof-kind
substitution, every arithmetic coordinate class, every scheduled metadata
field, invalid enabler/in-circuit values, tuple/schema/version/role/arity/order
and numerator forgeries, compiled plan projections and weights, batch layout,
interaction columns, claimed sums, geometry, global closure, detached
definition metadata, malformed witness bindings, and both destination shapes.
Construction and interaction generation are swept through every allocation
failure.

## Landed full logical `qm31_inv`

The third inventory entry, `recursion.qm31_inv.full.v1`, follows the same exact
macro expansion rule. Stark-V declares thirteen committed fields; the macro's
implicit enabler makes fourteen physical main columns and adds the twelfth
direct root. The typed component proves `a * inv = enabler` in the canonical
QM31 tower, binds circuit rows to one of three verifier-selected schedules, and
authors both `wire(6)` events in the semantic arena.

| Property | Compiler-derived value |
| --- | ---: |
| Declared / physical main M31 columns | 13 / 14 |
| Preprocessed schedule columns | 15 (five × segment/binary/empty) |
| Verifier-owned proof-kind inputs | 3 |
| Logical input nodes | 32 |
| Authored / total direct roots | 11 / 12 |
| Typed `wire(6)` effects | 2 (consume, emit) |
| Lookup batches / interaction M31 columns | 1 / 4 |
| Maximum logical constraint degree | 3 |
| Maximum lookup numerator / denominator degree | 2 / 1 |
| Maximum modeled interaction degree | 3 |
| Expression DAG nodes / edges / shared nodes | 106 / 146 / 18 |
| Maximum fanout / nodes outside closure | 9 / 0 |
| Semantic digest v1 | `48fd48bbc614bfcbfecf477174144fb122a8a7646b384b0185ca6cc898f8d975` |
| Static-profile digest v1 | `3364955e80cc7bd7c26eae401523d66a75e34dbb34325098b1258a6b95d746ec` |
| Witness-binding digest v1 | `eb85522af69c30945094b2ef3c4c8a39b61a349d1be2252b757e076d03246807` |

The direct writer rejects zero before touching caller storage, computes one
canonical inverse per live row, writes final SoA columns without a staging
table, and zero-pads deterministically. Its interaction is one paired
consume/emit cumulative column. A measured allocation gate permits four
allocations: the pair buffer, cumulative column, contiguous four-coordinate
output slab, and bit-reversal placement table.

Mutation evidence changes every committed column, every selected schedule
field, and the proof kind; tampers with entry order, schema, version, role,
arity, numerator, and tuple; mutates the compiled projection, liveness, and
batch plan; alters interaction coordinates and claims; and attacks witness
bindings and destination geometry. Construction and interaction allocation
failures are exhaustively swept.

## Landed full logical `linear_ops`

The fourth inventory entry, `recursion.linear_ops.full.v1`, is the exact
scheduled add/sub/neg component: twenty declared fields plus the macro
enabler, twenty-seven schedule columns, three proof-kind inputs, and eighteen
direct roots including the implicit enabler boolean.

| Property | Compiler-derived value |
| --- | ---: |
| Declared / physical main M31 columns | 20 / 21 |
| Preprocessed schedule columns | 27 (nine × segment/binary/empty) |
| Verifier-owned proof-kind inputs | 3 |
| Logical input nodes | 51 |
| Authored / total direct roots | 17 / 18 |
| Typed `wire(6)` effects | 3 (lhs consume, conditional rhs consume, emit) |
| Lookup batches / interaction M31 columns | 2 / 8 |
| Maximum logical constraint degree | 3 |
| Maximum lookup numerator / denominator degree | 1 / 1 |
| Maximum modeled interaction degree | 3 |
| Expression DAG nodes / edges / shared nodes | 157 / 210 / 16 |
| Maximum fanout / nodes outside closure | 12 / 0 |
| Semantic digest v1 | `d0a86167125655f56b958d10ee479655165906f57e8fea2dc0904b3d7f3b98f6` |
| Static-profile digest v1 | `0677e7695749be04ef2a9cf280946ed4d0e7366076600c9f8ac670b27c470b51` |
| Witness-binding digest v1 | `02b0efc3707c65e8d59d8e6d784a21594b6d561e9fd8e92e2b2087c57c654453` |

The component derives the right-hand multiplicity as `is_add + is_sub`, so
negation has no RHS relation edge. Its four unused RHS limbs are intentionally
canonicalized to zero by the only admitted writer rather than adding
reference-incompatible constraint roots; the writer rejects noncanonical
negation invocations and schedule metadata before mutation. Add, subtract, and
negate are checked across all proof kinds and a deterministic randomized QM31
corpus.

The three effects lower through the same generic authenticated interaction
compiler as multiplication and inversion. Consecutive batch-two grouping
pairs the two consumes and represents the output as the canonical singleton
second batch. The hot path uses one pair slab, two cumulative columns, one
contiguous eight-coordinate output slab, and one placement table: at most five
allocations. Rows are projected through pointers in the generation loop, so the
21-field main row is not copied once per batch. Tests specifically bind the
conditional RHS numerator and odd final-batch geometry in addition to the
generic mutation fleet.

## Shared effect-to-interaction compiler

`wire_interaction.zig` is now parameterized by physical main width and event
count. Cold authentication verifies the semantic digest and lowered effects,
then compiles each tuple coordinate and supported liveness expression to fixed
physical projections. It derives consecutive batch-two layout, entries,
numerators, denominators, claims, and final interaction placement from that
single plan. Component facades supply only the sealed definition and ordered
effect IDs; there are no component-local denominator transcriptions.

This is an important single-source-of-truth result from the original design,
but its authority currently covers these admitted logical components only. It
must become the production component/evaluator path before the corresponding
universal roster rows can be called migrated.

## Exact remaining gap to a live universal recursive proof

All 36 roster positions now have exact component authority and one sealed
layout. Remaining work is proof and recursive-verifier integration rather than
another copy of their equations:

- install verifier-owned segment/binary/empty preprocessing commitments and
  proof-kind selection in the recursion protocol manifest;
- draw and bind the recursion-wire challenge in the universal transcript;
- instantiate every admitted component and provider in one concrete outer
  STWO prover/verifier proof gate;
- include its claimed sums in statement/global relation closure;
- include every mask reconstruction in the universal composition self-program;
- pass a real outer prove/independent-verify and proof-mutation gate.

No handwritten evaluator or denominator should be added for those steps: the
semantic graph, authenticated witness binding, and interaction plan landed here
are their single source of truth.

## Implementation order from here

1. **Done at the logical boundary:** extend the typed relation registry with
   `wire(6)` and make one compiler-derived plan own effects and interaction
   generation without changing the twelve-relation VM prefix.
2. **Done at the logical boundary:** add all three proof-kind inputs and all
   eighteen schedule columns, then finish the exact 19-physical-column,
   13-root, 3-event `qm31_mul` shape and authenticated direct writers.
3. **Done at the logical boundary:** port exact `qm31_inv` and `linear_ops`
   components against the same typed schedule and `wire(6)` ABI, with direct
   SoA witnesses, compiler-derived interactions, sealed profiles, allocation
   ceilings, and mutation-complete gates.
4. **Done at the component boundary:** install all three arithmetic components
   in the generic universal adapter and fixed roster.
5. Port trusted control and the statement/public-claim/composition input
   adapters. They establish that circuit values cannot float free of transcript
   and manifest authority.
6. Port atomic transcript, payload, state, challenge/randomness, and PoW owners
   around the already pinned Poseidon2 primitive.
7. Port query decomposition/routing, trace and FRI Merkle authentication, DEEP,
   FRI control/input, and Merkle paths.
8. **Done for inventory/layout; composition proof open:** build the fixed
   36-entry manifest from compiled components and authenticated providers.
9. Only then add segment/empty/binary witnesses, child-proof adaptation, real
   outer proofs, tree construction, and the application-supplied root statement
   API.

## Commands and experiment

```sh
zig build --build-file src/frontends/riscv/build.zig \
  test-recursion-air \
  -Doptimize=Debug -j1 --summary all
zig build --build-file src/frontends/riscv/build.zig \
  test-recursion-air \
  -Doptimize=ReleaseSafe -j1 --summary all
zig build --build-file src/frontends/riscv/build.zig \
  test-recursion-air \
  -Doptimize=ReleaseFast -j1 --summary all
zig build --build-file src/frontends/riscv/build.zig \
  test -Doptimize=Debug -j1 --summary all
zig build --build-file src/integrations/riscv_cpu/build.zig \
  test-recursion-air-proof \
  -Doptimize=Debug -j1 --summary all
zig build --build-file src/integrations/riscv_cpu/build.zig \
  test-recursion-air-proof \
  -Doptimize=ReleaseSafe -j1 --summary all
zig build --build-file src/integrations/riscv_cpu/build.zig \
  test-recursion-air-proof \
  -Doptimize=ReleaseFast -j1 --summary all
```

Current pinned-source receipts:

- focused Debug: 254/254 passed;
- focused ReleaseSafe: 254/254 passed;
- focused ReleaseFast: 254/254 passed;
- integrated typed-AIR semantics Debug: 639/639 passed after the concurrent
  inventory and fail-fast fixes;
- frozen recursion protocol Debug: 34/34 passed;

## What this does not establish

- It does not verify a VM proof, recursion proof, Merkle path, FRI fold, or
  proof of work.
- It does not close `wire` against the other universal components or a global
  relation sum; it does generate and validate each admitted component's exact
  local interaction columns and claimed sums.
- It does not provide Stark-V-compatible table geometry or proof bytes.
- It does not yet instantiate all 36 concrete components together in one
  complete prover/verifier proof.
- It does not implement segment, empty, or binary branches.
- It does not change the honest project status: there is no completed
  constant-size application root-proof API here.

## Decisions/tasks affected

R-012 now has exact 36/36 AIR/component authority and a precise finish boundary.
Its status remains active until the recursion-reachable VM roster, universal
relation closure, complete outer proof integration, recursive child-proof
verification, and no-manual-AIR structural guard are complete.
