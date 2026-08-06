# Progress ledger

**Status date:** 2026-08-06
**Branch:** `feat/typed-air-precompiles`
**Current milestone:** M4 — Poseidon compiler pilot
**Active task:** H-009 — cost-aware materialization policy experiment
**Next ready task:** V-006 — CPU/Metal canonical program identity receipt

## Dashboard

| Milestone | State | Evidence |
| --- | --- | --- |
| M0 — engineering dossier | complete | This directory and initial ADRs |
| M1 — validated logical IR | complete | F-001 through F-012 complete and green |
| M2 — shadow compiler | complete | A-001 through A-005 complete and green |
| M3 — compatibility lowering | blocked | [V-008 evidence](receipts/m3-compatibility-v1.json) recorded; broad proof/formal gates open |
| M4 — Poseidon compiler pilot | active | H-001 through H-008 complete; H-009 active and H-010 queued |
| M5 — effect and witness pilot | queued | Requires typed schemas and lowering |
| M6 — guest precompile | queued | Requires Poseidon and ABI ADRs |
| M7 — parallel proving | queued | Requires working component |
| M8 — broad migration | queued | Requires vertical opcode ladder |
| M9 — recursive aggregation | deferred | Requires relation-summary design |

## Completed

- Created local branch `feat/typed-air-precompiles` from clean
  `origin/main` at `385efb9a`.
- Read and analyzed the felt-to-AIR design supplied by the user.
- Inspected Stark-V main and the later compiler/opcode development history.
- Reproduced the pre-revert Stark-V AIR compiler and prover tests.
- Mapped the proposal onto current production constraints, formal extraction,
  witness construction, Poseidon infrastructure, and component scheduler.
- Defined project charter, engineering canon, target architecture, IR,
  precompile model, soundness invariants, implementation phases, task graph,
  validation ladder, performance protocol, and initial ADRs.
- Completed F-001: the isolated `air/lang` module has an explicit logical
  schema version, is named in the test inventory, and is imported by no
  production path. The ReleaseFast RISC-V package suite passed.
- Completed F-002: distinct typed IDs, semantic integer/layout validation,
  owned stable names and sources, checked source spans, and allocation-failure
  cleanup all pass in the ReleaseFast package suite.
- Completed F-003: explicitly hashed structural expression keys, stable
  topological IDs, commutative add/multiply interning, typed operation
  rejection, primary source preservation, deterministic replay, and
  allocation-failure cleanup pass.
- Completed F-004: arena-owned constraints, hints, ordered effects, and
  function signatures pass allocation-failure cleanup and whole-program
  validation. The allocation-free structural validator verifies canonical
  ranges, topological references, interning indexes, hint-output identity,
  selector use, unique access ordinals, stable names, sources, and signatures.
  Each validator error class has a focused named negative test.
- Completed F-005: the versioned `STWAIRL\0` logical encoding writes explicit
  tags and fixed-width little-endian integers after validation. Two separately
  allocated programs remain byte-identical when name and source interning order
  is reversed; reversing semantic effect order changes the bytes. The empty
  encoding is pinned and serialization has allocation-failure coverage.
- Completed F-006: a typed registry covers all twelve production relation
  domains in transcript order. Schemas pin version, field specifications,
  roles, challenge convention, multiplicity, ordinal, padding, public-boundary,
  and coefficient-bound policies. Tests cross-check every production arity and
  reject unknown IDs, wrong roles, arities, types, and ordinals.
- Completed F-007: static calls own typed argument and output pools, preserve
  explicit inline-versus-relation-backed lowering intent, and can target only
  earlier complete functions. Two-phase declarations make dependency order
  canonical and prevent recursion through the public builder; the independent
  validator rejects missing callees, forward/self edges, malformed call
  outputs, arity drift, and type drift. Manifest format 2 records calls and
  lowering strategy. The full ReleaseFast package suite and allocation-failure
  call path pass; all 25 validator error classes have named negative tests.
- Completed F-008: hints use a closed typed recipe registry with pinned
  versions, signatures, honest algorithms, and exceptional-case policies.
  Every output carries a canonical output-first path to a matching-activation
  constraint or effect; unknown recipes, unbound outputs, malformed paths, and
  activation drift reject. Manifest format 3 records all recipe and binding
  metadata. The full ReleaseFast package suite, honest recipe vectors, and
  allocation-failure paths pass; all 28 validator errors have named negatives.
- Completed F-010: semantic digest format 1 streams a validated program into a
  domain-separated SHA-256 identity without allocating. It binds explicit
  types, stable semantic names, declared record order, hint proof metadata,
  effects, functions, and calls while excluding source spans and arena state.
  The empty identity is pinned; source/interner/allocation invariance and
  type/order/call-strategy sensitivity pass in the full ReleaseFast suite.
- Completed F-009: diagnostics render stable codes, escaped component/message
  text, exact source ranges, typed value paths, and explicit expression/gate/
  total/limit degree context. The supporting topological logical-degree pass
  covers every IR operation, treats committed hint/call outputs correctly, and
  rejects overflow. Golden rendering and partial-allocation cleanup pass.
- Completed F-012: `AUTHORING.md` defines the supported module surface,
  lifecycle, ownership rules, static-call discipline, hint proof bindings,
  identity artifacts, and production-isolation boundary. Compiled pure and
  activated hint/effect examples validate and derive degrees, manifests, and
  semantic identities in the ReleaseFast package suite.
- Completed F-011: induced allocation failures sweep function declaration
  finalization, static-call construction, and hint-binding finalization. Tests
  require multi-pool and node-interner rollback, validate reusable completed
  state where possible, and prove allocated/freed byte equality. Together with
  arena, manifest, degree, and diagnostic allocation enumeration, every owning
  foundation object has partial-initialization cleanup evidence.
- Completed A-001: the shipped symbolic polynomial DAG imports through checked
  typed constructors with an explicit source-node map, owned column names,
  canonical M31 constants, and linear replay. Deterministic randomized replay
  agrees at every mapped node for the exact direct-constraint programs of all
  17 opcode families. Malformed schemas, invalid replay buffers, commutative
  node merging, field wraparound, and every partial allocation have focused
  tests. No production consumer imports the adapter.
- Completed A-003: logical degree covers constants, sums, differences,
  products, negation, selections, canonical aliases, hint outputs, call
  outputs, gates, and overflow. An independent recurrence over every shipped
  symbolic node agrees with the typed analysis for every mapped node and every
  production direct-constraint root across all 17 families.
- Completed A-002: the exact complete production builder result imports main
  columns, placement selector, row-active expression, ordered direct roots,
  relation domains and roles, signed numerators, ordered tuple fields, access
  ordinals, and batch size. Same-arena comparisons cover every record of all 17
  families; deterministic random replay additionally covers every lookup-only
  expression node. The owned validator, corruption corpus, deterministic
  reconstruction test, and allocation-failure sweep pass without production
  wiring. Relation shape validation explicitly avoids inventing erased semantic
  field types.
- Completed A-004: the complete protocol pass accounts separately for imported
  direct roots, relation numerators and denominators, shifted cumulative
  columns, `is_first`, claimed sums, one- and two-entry LogUp batches, and
  post-vanishing quotient expansion. Checked arithmetic rejects degree,
  trace-log, and batch-layout failures. All-family tests independently compare
  the resulting minimum bounds to both shipped backend declarations.
- Completed A-005: report format 1 deterministically records all 17 families in
  production order with columns, DAG nodes and canonical merges, direct roots,
  lookups, batches, interaction geometry, roles, relation dependencies, final
  degrees, and expansion bits. Machine TSV and readable Markdown views are
  embedded from `design/typed-air/artifacts` and byte-compared in the
  ReleaseFast suite; structural corruption and every writer allocation failure
  reject cleanly.
- Completed A-006: `compat-v1` maps local preprocessed, main, and interaction
  columns without allocation. Every main `ValueId` carries separate logical and
  physical names, every interaction coordinate records its exact lookup batch
  and row window, and checked offsets resolve into statement-global positions.
  Tests compare all 644 main names to the Sail-authoritative reflected layouts,
  reproduce the existing witness-layout digest, validate all 620 interaction
  positions, and agree with real semantic/lookup backend capability geometry.
  The differential exposed and correctly represented logical/physical aliases
  such as `clock` → `clk` rather than joining namespaces by string equality.
- Completed A-007: the fallible owned direct lowerer validates `compat-v1`,
  emits the exact main-plus-selector column prefix, lowers only the ordered-root
  dependency closure, canonicalizes commutative operands, and deterministically
  expands selection into the production six-operation vocabulary. An
  independent linear-interning oracle establishes exact normalized node and
  ordered-root equality for all 17 families and all 545 roots. Four
  deterministic randomized M31 replays per family agree root by root; repeated
  lowering, structural corruption, malformed buffers, and every induced DIV
  allocation failure pass without leaks.
- Completed A-008: ordered lookup lowering separates unsigned liveness from the
  already-signed production numerator and structurally binds both to the event
  role. It retains schema, tuple order, arity, ordinal, fixed sentinel tails,
  declaration order, batch occupancy, and all four physical QM31 coordinate
  references per batch. Canonical dependency-height relabeling removes node-ID
  drift caused by unrelated direct-section interning. An independent oracle
  establishes exact normalized DAG and flattened-root identity with all 17
  lookup-only runtime programs; randomized replay covers all 242 events and all
  155 batches. Sign mismatch, corruption, determinism, and every induced DIV
  allocation failure reject or clean up as specified.
- Completed A-009: a representation-only runtime exporter revalidates canonical
  direct and lookup programs, checks the six polynomial operation names/tags at
  compile time, initializes ignored lookup tails with deterministic sentinels,
  copies into the prover-owned capability types, and validates the result. All
  17 families match independently normalized production nodes, roots/entries,
  columns, batches, arities, and lookup parameter counts. Malformed inputs
  reject before copying; both full DIV allocation-failure paths clean up.
- Completed A-010: AIR IR v2 lowering applies selector-to-one placement while
  preserving the frozen wire's historical node schedule. The shadow now owns a
  domain-separated-digest-bound raw node copy and exact source IDs for active
  row, selector, direct roots, lookup numerators, and tuple fields; validation
  binds every item back to the canonical typed graph. The pass derives semantic
  column roles and event projections, then uses the existing sole JSON writer.
  LUI and every opcode-manifest entry are byte-identical to production. Source
  orientation corruption and every induced DIV allocation failure reject or
  clean up.
- Completed A-011: one canonical `STWAIRC\0` version-1 receipt for each of the
  17 production families binds authority and source revisions, semantic
  identity, exact physical columns, complete direct and lookup runtime bodies,
  named roots and ordered events/batches, full protocol degree records, hint
  recipes, and every formal opcode export. Typed and production AIR IR v2
  bodies compare byte for byte before their lengths and digests enter the
  receipt. A family-ordered TSV index exposes whole-manifest, source/semantic,
  layout, runtime, degree, and formal digests with geometry, export counts, and
  maximum degrees. The package suite
  regenerates and compares all 18 files exactly; deterministic generation,
  reordered-family rejection, and exhaustive result-allocation failure pass.
  The explicit tool defaults to fail-closed check and reserves atomic update
  for reviewed replacements. The legacy symbolic builder remains on stable
  scratch storage during failure injection, preserving its panic-on-OOM
  contract while testing every new owning boundary.
- Completed A-012: an allocation-free parser validates both generated and
  on-disk `STWAIRC\0` version-1 bodies before comparing them. It rejects
  malformed framing, nested runtime topology, sentinel tails, enum/optional
  tags, UTF-8, and trailing bytes with stable side, path, and offset. The first
  semantic divergence names logical and physical columns, direct roots,
  lookup schemas/roles/events/batches, degree records, hints, or formal export
  identities before duplicated envelope digests. Check mode now reports the
  named difference and fails; update mode reports the same difference before
  atomically replacing a reviewed artifact. All 17 equal receipts, focused
  mutations, malformed inputs, and end-to-end check/update repair pass.
- Completed H-001: statically shaped typed arrays expose deterministic
  map/zip/fold expansion over scalar IR nodes, retain one source span per
  unrolled element through CSE, preflight shape/type/provenance, roll back a
  failed expansion transactionally, and release every partial allocation.
  The eight-test surface is green in Debug, ReleaseSafe, and ReleaseFast.
- Completed H-002: the isolated typed surface now authors the exact width-16
  M31 Poseidon2 permutation as one pure static function. The 2,171-node graph
  imports the pinned production constants, emits no constraints, hints,
  effects, or layout, and matches three full-state vectors plus 128
  deterministic random production differentials. Its degree is explicitly
  `5^22`; deterministic replay, source provenance, late preflight failure, and
  exhaustive allocation failure are pinned before H-003 adds a materializer.
- Completed H-003: the versioned generic degree-three materializer computes
  reachability, structural reuse, logical degree, and cuts only over the
  requested root closure while retaining a whole-program semantic identity.
  For canonical Poseidon2 it deterministically emits exactly 426 boundaries:
  410 degree-required cuts and sixteen declared outputs. Every gated equality
  has final degree three. Eight named tests pin transparent linear operations,
  reuse and `ValueId` tie-breaks, forced outputs, unreachable overflow
  isolation, plan corruption, deterministic replay, and exhaustive allocation
  failure.
- Completed H-004: the separate versioned compatibility adapter reconstructs
  the canonical Poseidon2 function shell and bijectively binds the complete
  authenticated H-003 set to the exact 426-slot legacy lane-major schedule
  within the existing 445-column main trace. The owned result retains semantic,
  policy, activation, plan, and compatibility identities and fully revalidates
  them before use. Fixed full-width input and sixteen deterministic random
  states match production in every physical slot; one-at-a-time mutation of
  every production temporary constraint rejects. Ten named tests also reject
  schedule, dependency, source, role, and complete-triple ordering attacks.
- Completed H-005: an authenticated compiler owns the canonical typed Poseidon
  output closure as 2,171 compact instructions plus reusable M31 scratch. It
  evaluates directly into all 445 caller-owned, bit-reversed final columns,
  zeroes padding, and allocates nothing during execution. Shape, call count,
  address overflow, input/destination aliasing, instruction structure, the
  canonical executable digest, and all input/materialization slots validate
  before mutation. Independent canonical recompilation reauthenticates a
  transported executor. Nine named tests establish exact narrow/wide/I/O and
  randomized production equality, guards, fail-before-mutation corruption
  rejection, and exhaustive construction-allocation cleanup.
- Completed H-006: a separately versioned authenticated relation plan fixes the
  four current Poseidon request events, their signed mode/enabler numerators,
  semantic projections and ABI arities, the exact two batches, eight
  bit-reversed interaction columns, and two claims. Bulk generation
  authenticates once before allocation-free row kernels. Six named tests match
  production entries, pairs, padding, columns, and claims; reject tuple, mode,
  multiplicity, order, role, domain, geometry, column, and claim forgeries; and
  show that a mismatched carried narrow output cannot close against the Merkle
  counterpart or committed row.
- Completed H-008: a canonical 37-field machine projection and concise human
  view trace every one of 426 physical slots to its distinct generic plan ID,
  semantic value/path/source span, dependencies, degrees, policy identities,
  constraint ordinal, and column. Its golden SHA-256 is
  `33eadd080a715fe09d1b3ed3ad8abc18cb35f71e56895e6ac62810a1dfeb0ef2`.
  Four named tests pin complete coverage and field order, deterministic
  cross-allocation replay, corruption-before-output, writer failure, and
  exhaustive validation-allocation cleanup.
- Completed H-007: a test-only real-backend wrapper regenerates all 445
  Poseidon main columns directly into the live Tree-1 commitment buffers,
  derives all eight interaction columns from the live Fiat-Shamir challenges
  into Tree-2, and installs both typed claims at the canonical transcript,
  component, and returned-output boundaries. The focused CPU suite proves and
  verifies one 46-row narrow-only fixture and rejects main, interaction, and
  claim mutations. Full ReleaseFast CPU and authenticated-AOT Metal product
  gates pass; Metal reports resident RISC polynomial execution and zero known
  CPU composition declines. The immutable
  [H-007 receipt](receipts/h007-poseidon-proof-equivalence-v1.json) binds commit
  `f204eb4617330e755598bdc3ef67c0be7441c879`, both reproducible product-closure
  identities, and the 118-export Metal bundle identity while preserving the
  test-security, same-process, narrow-only, and V-006 identity limits.
- Completed V-008: the machine-readable
  [M3 receipt](receipts/m3-compatibility-v1.json) names the clean detached
  `7cdf41d5b246baf845adeb99d02444d9a6090514` snapshot, exact toolchain,
  M2/M3 and formal identities, 657-test package results, all 17 manifest
  checks, workspace and AIR-satisfaction results, and a focused real proof. It
  also records rather than waives the broad prover-core rigidity failures,
  eight baseline source-conformance errors, and five stale artifacts detected
  by the refinement pilot after the 120-job Lean build passed. Compatibility
  implementation is complete; M3 release promotion remains blocked.

## Immediate next actions

1. H-009 — prototype a separately identified cost-aware materialization policy
   with a deterministic manifest and complete symbolic cost vector.
2. V-006 — bind the canonical logical, layout, executable, and backend path
   identities without overstating what the in-memory H-007 receipt proves.
3. H-010 — benchmark compatibility and proposed layouts under the pinned
   performance protocol, including total work and memory rather than wall time
   alone.

No production behavior should change in these tasks.

## Decisions

Accepted:

- Zig-authored canonical typed IR.
- Compatibility before optimization.
- One-proof guest precompiles before independent recursive leaves.
- Acyclic function graph in IR v0.
- Typed hint recipes with explicit proof-binding paths.
- Domain-separated semantic program digest projection.
- Stable diagnostic codes and topological logical-degree analysis.
- Lossless mapped import of the production symbolic DAG in shadow mode.
- Ordered same-source import of the complete production program surface.
- Complete current-protocol degree model and pinned M2 report.
- Explicit local `compat-v1` physical mapping with distinct logical and
  committed names.
- Fallible normalized direct-constraint lowering with structural identity as
  the primary compatibility criterion.
- Role-normalized ordered lookup lowering with cached sign binding and explicit
  physical batches.
- Validated canonical export into existing direct and lookup runtime capability
  owners.
- Digest-bound source-schedule compatibility for selector-specialized AIR IR v2
  with one JSON encoding authority.
- Section-framed `STWAIRC\0` v1 family receipts with exact runtime bodies,
  exact-checked formal identities, and a readable aggregate index.
- Root-scoped degree-bounded materialization with a separately versioned,
  fully revalidated Poseidon compatibility order, as fixed by
  [ADR-0018](decisions/0018-degree-bounded-materialization-and-compatibility-order.md).
- Authenticated, reconstructible compiled witness and relation plans with
  fail-before-mutation final-storage execution, as fixed for shadow
  compatibility by
  [ADR-0019](decisions/0019-authenticated-witness-and-relation-plans.md).

Pending:

- guest invocation ABI;
- guest Poseidon relation schema/version;
- generated witness activation policy;
- cross-proof relation summary;
- recursive verifier field/protocol.

## Risks under watch

| Risk | Current control |
| --- | --- |
| New abstraction drifts from production | Shadow import and exact compatibility lowering |
| Compiler shares wrong semantics with witness | Sail, mutation, formal, and independent runner evidence |
| Layout changes silently | Versioned deterministic manifests |
| Typed DSL becomes stringly or magical | Canon relation/effect rules and constructor validation |
| Poseidon pilot becomes a toy | Exact 445-column production component target |
| Precompile weakens base-RV32IM claim | Pending explicit guest ABI ADR |
| Parallelism hides total cost | Performance vector and critical-path telemetry |
| Recursion balances detached calls | IR v0 rejects recursive function graphs |
| Hint callback or output drifts silently | Closed versioned registry and checked proof paths |
| Broad production proof gate is red | V-008 records exact rigidity findings; no release promotion |
| Formal generated artifacts are stale | Refinement pilot fails closed on five named files; reviewed workflow required |
| Compiled witness drifts after binding | Executable digest, structural preflight, and independent canonical recompilation |
| Shadow equality is mistaken for proof evidence | H-007 requires generated artifacts inside CPU/Metal proofs before promotion |

## Baseline metrics

The [M2 machine report](artifacts/m2-production-shadow-report-v1.tsv) now pins
the current all-family logical node, direct-constraint, lookup, batch,
dependency, interaction-column, and final-degree counts. In aggregate across
independently compiled families it records 3,051 source nodes canonicalized to
3,049 typed nodes, 545 direct constraints, 242 lookup entries, 155 interaction
batches, and maximum direct/interaction degree three.

The canonical Poseidon2 compatibility geometry is now measured as 445 main
columns containing 426 materialized values: 410 degree-required cuts and
sixteen forced outputs. All emitted materialization equalities have maximum
final degree three under their explicit activation context.

The witness compiler evaluates 2,171 owned instructions into those columns
with one reusable scratch vector and no execution allocation. Poseidon relation
geometry is four ordered events in two batches, two QM31 cumulative sums, and
eight committed M31 interaction columns. The H-008 426-record report binds this
surface to the golden SHA-256
`33eadd080a715fe09d1b3ed3ad8abc18cb35f71e56895e6ac62810a1dfeb0ef2`.

The following measurements remain assigned to their later owning milestones;
they are not prerequisites for closing the opcode shadow compiler:

- package/proof durations and CPU/Metal Poseidon timing — H-007/H-010;
- RISC-V structural workloads and proof crossover measurements — C-013/R-006.

## Log

### 2026-08-04 — M0 dossier established

Created the feature branch and this development directory. The architecture
decision is to complete the existing generic/symbolic design through a
canonical typed IR, rather than starting with an external language. Existing
Poseidon call collection and heterogeneous component scheduling make the
precompile path an extension of working machinery.

No production code changed. No soundness claim changed.

The repository-wide pre-commit source-conformance check is already red at the
`385efb9a` main baseline for unrelated Metal and lookup file-size entries.
The dossier passes the staged whitespace check, Zig formatting portion of the
hook, and local Markdown-link validation. This baseline failure must be
resolved separately before the hook can return green; it is not folded into
the typed-AIR scope.

### 2026-08-04 — M1 implementation started

Activated F-001. The first code change is limited to an isolated
`air/lang` module and explicit RISC-V test-inventory wiring. Production AIR,
witness, runner, prover, transcript, and formal-export paths remain unchanged.

F-001 completed with
`zig build test --build-file src/frontends/riscv/build.zig
-Doptimize=ReleaseFast -j2`. The package test-count floor observed the new
test, and the command exited successfully.

F-002 completed with the same ReleaseFast package command. Its focused tests
also run `checkAllAllocationFailures` across name/source ownership and verify
that distinct semantic IDs remain distinct Zig types.

F-003 completed with the same ReleaseFast package command. Structural hashing
uses explicit semantic fields rather than rendered text or object bytes; the
tests rebuild the graph in a second arena and require identical node keys.

F-004 completed with the same ReleaseFast package command. Whole-program
records remain isolated from production code. The validator is allocation-free
and checks all stored semantics independently of constructor success; 22
one-error corruption tests prove every public validator error is reachable and
stable. Allocation-failure enumeration now crosses hint output construction,
constraints, ordered effects, and functions.

F-005 completed with the same ReleaseFast package command. ADR-0005 fixes the
pre-production logical encoding. The serializer validates before output,
resolves names and source paths by content, preserves semantic record order,
and ignores allocator and interning-table accidents. Determinism, semantic
order sensitivity, invalid-program fail-closed behavior, and allocation
rollback each have focused tests.

F-006 completed with the same ReleaseFast package command. The isolated
registry uses enum domains and typed schema IDs instead of string dispatch. A
test-only bridge compares its stable order and arity to the production relation
entry authority; no shipped lookup or transcript behavior changed.

F-007 completed with the same ReleaseFast package command. Calls carry a typed
callee, optional lexical caller, arguments, generated output identities, source
span, and explicit inline or relation-backed strategy. Functions are declared
in dependency-topological order through a two-phase builder, so recursive and
forward edges cannot be constructed; the allocation-free validator rechecks
the complete graph and every call-output identity against raw arena state.
Manifest format 2 and logical schema 1 serialize this semantic distinction.
All 25 validator error classes have focused named rejection tests.

F-008 completed with the same ReleaseFast package command. The string recipe
surface was replaced by `HintRecipeId` and a closed registry whose entries pin
version, exact signature, deterministic algorithm, and exceptional behavior.
Hints carry activation selectors and are sealed with canonical binding lists;
each binding supplies a direct-edge value path from one output to a matching
constraint root or effect value. This keeps validation allocation-free and
source-attributable. Manifest format 3 / logical schema 2 records the complete
contract. Honest inverse-or-zero vectors, malformed bindings, missing recipes,
unbound outputs, semantic serialization, and partial allocation cleanup pass;
all 28 validator errors have named negative tests.

F-010 completed with the same ReleaseFast package command. Digest format 1
streams explicit little-endian tags and widths directly into SHA-256 under the
`stwo-zig/typed-air/semantic` domain after whole-program validation. It includes
semantic names, types, ordered constraints/effects, recipe policies and proof
paths, function signatures, calls, and lowering strategy. It excludes source
paths/spans and arena implementation state. The empty digest is a pinned vector;
separate tests prove source and interning invariance plus type, name, effect
order, and call-strategy sensitivity.

F-009 completed with the same ReleaseFast package command. The renderer pins
machine codes and escaped text while carrying component, exact source range,
typed `ValueId` path, and degree context. A new topological analysis computes
logical value and gated-constraint degree with checked arithmetic; it labels
hint/call outputs as committed degree-one values and explicitly does not claim
the later relation/mask/interaction degree. Golden output, unknown-value
fallback, overflow rejection, and partial allocation cleanup pass.

F-012 completed with the same ReleaseFast package command. `AUTHORING.md` maps
the namespaced API and gives lifecycle, ownership, pure-function, activated
hint/effect, static-call, identity, and diagnostic guidance. The source-backed
examples are tests rather than stale snippets: the pure example validates and
derives a degree report, manifest, and digest; the effectful example seals one
hint output to both a matching-gated constraint and matching-live ordered
effect. The document explicitly labels raw effects and the entire kernel as
pre-production shadow interfaces.

F-011 completed with the same ReleaseFast package command. Dedicated failing-
allocator sweeps cross every allocation boundary in function declaration
sealing, static calls, and hint binding. Failures must restore all correlated
reference pools, generated nodes, interning indexes, open-declaration state,
and optional binding state before deinitialization. Reusable completed states
are revalidated, and each iteration requires allocated bytes to equal freed
bytes. Existing whole-arena, manifest, degree, and diagnostic enumeration
completes the ownership evidence for M1.

### 2026-08-05 — M2 lossless expression import established

A-001 completed with ADR-0009 and the ReleaseFast package suite. The adapter
validates the shipped symbolic arena, owns imported names and mappings, reduces
constants canonically, and replays the typed DAG in one topological pass. A
fixed-seed differential builds the exact production direct program for all 17
opcode families and compares every source node at eight field points. Focused
tests cover commutative ID collapse, wraparound, ambiguous or malformed source
schemas, replay shape failures, and all injected allocation failures.

A-003 completed in the same gate. The typed unit corpus now names every degree
operation and canonical alias behavior. A separately implemented recurrence
over the six production symbolic operations agrees at every mapped node and
every direct-constraint root for all families. This proves logical expression
degree only; row masks, boundary terms, lookup fractions, interaction
recurrences, and backend degree remain explicitly unclaimed until A-004.

No production AIR, witness, prover, verifier, transcript, runtime export, or
formal-extraction path changed. A-002 is active to import the ordered program
surface rather than infer it from expression reachability.

### 2026-08-05 — M2 ordered program boundary established

A-002 completed with ADR-0010 and the ReleaseFast package suite. One complete
production builder invocation now supplies the shadow compiler's columns,
placement selector, row-active expression, ordered constraints, and ordered
lookup records. Tests compare the source and imported records from the same
arena for every family, including domain, role, signed numerator, every tuple
field, access ordinal, and batching. Four fixed-seed replay points per family
cover the full DAG, including expressions constructed only by lookup emission.

The compatibility record intentionally preserves lookup polynomials rather
than presenting them as authored typed effects. Production extraction does not
carry the semantic byte/clock/address types required for full relation-event
validation, and its numerators already encode signs. Shape-only validation is
therefore named and separate; effect normalization remains explicit A-008 work.
Deterministic rebuild, corrupted-state rejection, and induced allocation
failure coverage pass. A-004 is active to distinguish logical root degree from
the complete constraint, row-mask, and interaction degree required by a
backend.

### 2026-08-05 — M2 complete protocol geometry pinned

A-004 completed with `protocol_degree.zig` and ADR-0011. The pass traverses the
validated imported program and retains every direct, lookup, and interaction
degree record. It models the exact shipped pairs-batched recurrence, including
current/previous cumulative masks, the degree-one `is_first` boundary term,
degree-zero transcript claims, nonlinear relation fields, single-entry
sentinels, and quotient expansion after vanishing-polynomial division. Focused
tests cover nonlinear pairs and singletons, numerator-dominating terms,
expansion thresholds, trace-log overflow, and induced allocation failures.

The all-family differential finds maximum direct degree three in ten families
and degree two in seven. Every current lookup interaction is degree three. At a
representative trace log size, the computed direct bound never exceeds the
shipped semantic component's declaration, while every computed interaction
bound exactly equals the real opcode lookup component's declaration. “Degree
three” is algebraic constraint degree and does not imply cubic-time proving.

A-005 completed in the same ReleaseFast gate. Report format 1 pins 17 families,
644 independently summed main columns, 3,051 source nodes, 3,049 canonical
typed nodes, 545 direct roots, 242 ordered lookups, 155 interaction batches,
620 M31 interaction-coordinate columns, role counts, and all twelve relation
dependencies. Its TSV and Markdown renderings are checked byte-for-byte from
the design artifact module. The report validator rejects corrupt order,
geometry, role/dependency totals, expansion values, and overflow, and both
writers pass allocation-failure enumeration.

The expanded full ReleaseFast RISC-V package suite passes; its two printed
register-boundary diagnostics are expected negative-test evidence. No
production AIR, witness, prover, verifier, transcript, runtime export, or
formal-extraction path changed. M2 is complete and A-006 activates M3 by
defining the exact `compat-v1` physical column mapping.

### 2026-08-05 — M3 `compat-v1` physical mapping established

A-006 completed with `compat_layout.zig` and ADR-0012. The mapping fixes the
three production tree indices, local selector positions, main input positions,
batch-major QM31 interaction coordinates, row windows, batch occupancy, and
checked global-offset resolution. It is allocation-free, uses canonical
sentinels for every inactive fixed-capacity slot, and independently revalidates
the imported program and its own stored state.

The first exact name comparison caught an important namespace distinction:
logical semantic paths are not the committed witness schema. For example,
`clock` maps positionally to physical `clk`. The accepted descriptor therefore
retains both names, sources committed names directly from `witness_layout`, and
never uses name equality to discover the value mapping.

All 17 families compare every mapped main index/name to reflected production
fields and reconstruct the existing Sail-authoritative witness-layout digest.
The test also covers all interaction positions and resolves deliberately
nonzero offsets into the exact tree/index/count fields advertised by the real
semantic and opcode-lookup backend capabilities. Corrupted family, selector,
main, hidden-tail, batch, coordinate, and lookup mappings reject; global index
overflow rejects. The ReleaseFast package gate and package-boundary audit pass.

No production consumer imports `air/lang`; at this point A-007 became active to
lower the LUI direct roots through this mapping and compare normalized
structure.

### 2026-08-05 — M3 direct constraints lower exactly

A-007 completed with `lower_constraint.zig` and ADR-0013. The pass validates
the imported shadow and `compat-v1` layout, emits physical main inputs followed
by the active selector, marks only the ordered direct-root dependency closure,
and lowers it into an owned copy of the production six-operation node
vocabulary. Addition and multiplication operands are canonical; selection has
one deterministic expansion. Construction is fallible and does not depend on
the production extractor's global panic-on-allocation-failure arena.

The LUI acceptance check was strengthened to every current opcode family. An
independent normalizer using linear interning produces the exact same node
slices and 545 ordered roots as the hash-consed lowerer across all 17 families.
Deterministic randomized replay additionally agrees at every root. Repeated
LUI construction is byte-structurally stable; malformed programs and replay
buffers fail closed; allocation-failure enumeration over DIV frees every
partial owner.

The full ReleaseFast package suite and package-workspace audit pass. The two
printed register-boundary diagnostics remain expected negative-test evidence.
No production consumer or proof artifact changed. At this point A-008 became
active to reproduce LUI's ordered lookup effects and batch boundaries through
the same mapping.

### 2026-08-05 — M3 ordered lookups and role signs reproduced

A-008 completed with `lower_lookup.zig` and ADR-0014. Request and consume
entries must expose a syntactic negative numerator and retain its operand as
normalized liveness; emit liveness equals its positive numerator. The owned
event keeps the signed numerator as a cache that validation binds back to role,
preventing both sign loss and double negation. Schema, role, tuple roots,
access ordinal, event order, sentinel tail, batch occupancy, and all four
physical interaction-coordinate references are checked without allocation.

The first lookup-only structural differential exposed incidental node ordering:
the complete builder may intern a constant while constructing direct roots
before the lookup-only builder encounters it. The shared lowerer now relabels
reachable nodes by dependency height and stable structural key. A separately
implemented linear-interning oracle performs the documented canonical ordering
without sharing lowerer code. Exact canonical nodes and flattened roots now
match the production lookup-only runtime program across all 17 families.

Four deterministic randomized assignments per family agree for every one of
the 242 numerators and every tuple field, and separately recheck each role-sign
identity. All 155 batches match `compat-v1`. LUI reconstruction, corruption,
malformed sign, and DIV allocation-failure tests pass in both ReleaseFast and
ReleaseSafe package suites. The package workspace audit remains green. This is
still an erased compatibility record, not semantic field-type evidence for an
authored effect. No production behavior changed; at this point A-009 became
active.

### 2026-08-05 — M3 canonical runtime owners reproduced

A-009 completed with `lower_runtime.zig` and ADR-0015. The pass performs no
algebra or layout selection: it revalidates a lowered owner, copies each node
and ordered root or entry into the prover's backend-neutral capability type,
initializes ignored lookup tuple tails with a deterministic invalid-node
sentinel, and validates the returned owner. Compile-time checks pin all six
operation names and integer tags across the language and prover ABIs.

All 17 direct exports match the independent production normalization node for
node, root for root, and column for column. All 17 lookup exports additionally
match every numerator and tuple root, arity, batch count, and parameter count.
Malformed direct and role-sign state rejects before output allocation. Induced
allocation-failure enumeration over both complete DIV build-and-export paths
frees all partial typed and runtime owners.

ReleaseFast remains green with the two expected register-boundary negative-test
diagnostics. No capability callback imports the new exporter, so production
evaluation order and proof artifacts remain unchanged. At this point A-010
became active to emit the LUI AIR IR v2 projection from the canonical program.

### 2026-08-05 — M3 AIR IR v2 reproduced byte for byte

A-010 completed with `lower_air_ir.zig` and ADR-0016. The work makes an explicit
distinction between canonical typed semantic identity and AIR IR v2's frozen
source-schedule identity. The shadow importer now owns an exact raw node copy
under a domain-separated SHA-256 receipt, validates every copied node against
its typed value, and retains source IDs for selector, active row, direct roots,
signed numerators, and tuple fields.

Formal lowering emits semantic main columns, seeds constant one, substitutes
the runtime selector, and replays the checked raw schedule through fallible
exact interning. It independently derives column roles and program/state/source/
destination projections from ordered relation metadata. The existing production
JSON writer remains the only authority for schema version, compact key order,
escaping, and fixed-table metadata.

The typed compatibility output is byte-identical to production for LUI and for
every opcode-manifest entry. A commutative-orientation mutation fails the source
receipt before export, and induced DIV allocation failures free the reconstructed
arena. ReleaseFast and ReleaseSafe package suites are green with expected
negative diagnostics. No formal artifact or production consumer changed. A-011
is active to package complete all-family identities and receipts.

### 2026-08-05 — M3 all-family compatibility receipts pinned

A-011 completed with `compat_manifest.zig` and ADR-0017. Each production-family
enum value now owns one canonical `STWAIRC\0` version-1 binary. Seven ordered,
length-framed sections bind authority revisions and source schedule, exact
preprocessed/main/interaction layout, embedded direct and lookup runtime
programs, named roots and ordered relation events/batches, complete protocol
degree records, hint recipes, and every opcode's formal export identity.
Runtime programs are validated against the typed lowerings. Every formal body
is compared byte for byte with the production AIR IR v2 emitter before its
length and SHA-256 are recorded.

The checked artifact set contains 17 family binaries and one enum-ordered TSV
index exposing whole-manifest, source/semantic, layout, runtime, degree, and
formal digests with geometry, export count, and maximum direct/interaction
degree. Package tests regenerate and compare every
file exactly, reject reordered family summaries, and prove deterministic DIV
generation. A dedicated allocation-failure sweep holds the legacy production
symbolic builder on stable scratch storage while failing every allocation in
the new runtime and receipt result boundary. The standalone
`typed-air-manifest` build step defaults to fail-closed check; explicit update
publishes replacements atomically.

This receipt is compatibility evidence only: it changes no production consumer,
proof protocol, witness authority, or formal artifact.

### 2026-08-05 — M3 semantic artifact review is field-aware

A-012 completed with `compat_manifest_diff.zig` and direct integration into the
`typed-air-manifest` command. The allocation-free parser validates the generated
and on-disk v1 envelopes independently, including every framed section and
nested runtime program. It returns one borrowed, structured result: equality,
the first named semantic difference, or a fail-closed malformed-artifact
diagnostic with explicit side, path, and byte offset.

Detailed layout, root, relation, degree, hint, and formal fields compare before
their duplicate identity digests, so review output explains the changed object.
Check mode exits unsuccessfully after rendering it. Explicit update mode renders
the same generated-versus-on-disk difference before atomic replacement. An
end-to-end temporary-artifact test changed `lui`'s `rd_nonzero` physical name,
observed `layout.main[16].physical_name`, repaired it through update, and then
passed check; invalid magic reported `actual/on-disk` at `header.magic`.

In parallel, H-001 and H-002 established the first M4 authoring surface without
changing production. Fixed typed arrays/maps/folds and a pure width-16 M31
Poseidon2 definition are separately committed and ReleaseFast package-green.
The pure graph matches pinned and randomized production vectors while retaining
materialization and layout as explicit later-pass decisions. V-008 is active to
close M3 with a clean-tree evidence receipt; H-003/H-004 may continue in
dependency-safe, isolated lanes.

### 2026-08-05 — M3 clean-snapshot evidence recorded without gate inflation

V-008 records evidence for immutable revision
`7cdf41d5b246baf845adeb99d02444d9a6090514` and tree
`24a6e49b3acce11163a3f94107ae5d9d95c8fd83`. ReleaseFast and ReleaseSafe
package suites compiled 657 tests each (656 passed, one skipped), all 17
compatibility manifests matched, the 21-package workspace audit and 29-test AIR
satisfaction gate passed, and the focused end-to-end proof verified. Artifact
hashes and aggregate geometry are pinned in the machine receipt.

The receipt is intentionally not green overall. The broad prover-core gate has
two witness-rigidity failures, and the refinement pilot—after a complete
120-job Lean build—reports drift in five committed generated artifacts. Source
conformance also retains eight existing repository-baseline errors. No
authority artifact was regenerated, no failure was waived, and no production
consumer changed. V-008 is complete as an evidence task; M3 release promotion
remains blocked while isolated M4 work proceeds.

### 2026-08-05 — M4 degree-bounded Poseidon layout reproduced

H-003 and H-004 complete the first compiler-to-physical-layout bridge without
activating it in production. The generic `degree-bounded-v1` materializer
selects exactly 410 required cuts plus sixteen outputs from the canonical typed
Poseidon2 graph, guarantees degree-three gated equalities, ignores unreachable
degree overflow when selecting the root-local plan, and deterministically
authenticates every boundary. The component-specific compatibility adapter then
reconstructs the trusted function shell and maps that complete set bijectively
onto all 426 historical lane-major slots in the 445-column trace.

The adapter's owned binding retains and revalidates the program digest, policy,
gate, plan identity, semantic source, and physical slot for every entry. Full
fixed and randomized state differentials agree slot by slot with the production
witness schedule; every individual production temporary constraint is also
mutated and observed to fail. Debug, ReleaseSafe, and ReleaseFast package
evidence, workspace validation, allocation-failure sweeps, and an independent
adversarial audit guard the integration.

This is still shadow evidence. It does not generate production witness rows,
activate generated constraints, close Poseidon relations, prove CPU/Metal
equivalence, or establish any proving-time improvement. Those obligations begin
with H-005 and H-006.

### 2026-08-05 — M4 witness, relations, and diagnostics reproduced

H-005, H-006, and H-008 complete the remaining shadow data path from the pure
typed graph to the current Poseidon main and interaction geometry. The witness
compiler owns an authenticated 2,171-instruction closure and reusable scratch,
then writes all 445 bit-reversed columns directly into final storage with zero
padding and no execution allocation. Every fallible structural, digest, shape,
and alias check precedes mutation; canonical recompilation detects a transported
executor whose instructions or 426-slot mapping changed.

The relation plan independently fixes four signed request events, two batches,
eight interaction columns, and two claims. Honest narrow, wide, I/O, padding,
and carried-output cases agree exactly with production. Targeted tuple, mode,
multiplicity, ordering, geometry, column, and claim forgeries reject, and a
wrong carried output cannot close against the honest Merkle counterpart. The
canonical diagnostic stream exposes 37 ordered fields for all 426 slots and is
pinned by SHA-256
`33eadd080a715fe09d1b3ed3ad8abc18cb35f71e56895e6ac62810a1dfeb0ef2`.

The RISC-V package now compiles 694 tests: 693 pass and one is intentionally
skipped. All nineteen new H-005/H-006/H-008 named tests pass in Debug,
ReleaseSafe, and ReleaseFast, with only the two expected register-boundary
negative diagnostics. This remains non-production evidence. H-007 must commit
the generated artifacts inside real CPU and Metal proofs and independently
verify them before the pilot can claim proof-path equivalence.

### 2026-08-06 — generated Poseidon artifacts proved on CPU and Metal

H-007 now closes the compatibility pilot's real-proof boundary. The prover
first discovers the canonical Poseidon windows, then independently
reauthenticates H-005/H-006 and overwrites the actual caller-owned Tree-1 and
Tree-2 buffers before their real backend commitments. The typed total enters
the live transcript at the exact Poseidon component ordinal; both sums enter
the component before composition, and the returned output claim is reconciled
to the typed sums after proving.

At clean commit `f204eb4617330e755598bdc3ef67c0be7441c879`, the focused
ReleaseFast CPU suite passes both the honest proof and all generated-artifact
mutation cases with 46 active narrow rows and no wide or I/O rows. The full CPU
product gate passes with a 474-source closure. The full Metal product gate
passes after authenticated admission of the 118-export, zero-function-constant
AOT bundle, reports resident RISC polynomial execution with zero known CPU
composition declines, and closes a 531-source product graph. Both verify
through a fresh unchanged production verifier specialization.

The evidence is deliberately bounded: the PCS configuration is test-security,
verification is fresh-state but same-process, claims are transcript/AIR-bound
rather than separate Merkle columns, and V-006 has not yet attested canonical
logical/layout identities across backends. No production authority changed.
The [machine receipt](receipts/h007-poseidon-proof-equivalence-v1.json) records
those facts and exclusions; H-009 is now the sole active task.

## Update protocol

Every progress update changes:

- status date;
- current milestone and active task;
- dashboard state;
- completed evidence;
- next three actions;
- new risks or decisions; and
- one dated log entry.

At most one task is marked active. A task becomes done only when its acceptance
evidence is named.
