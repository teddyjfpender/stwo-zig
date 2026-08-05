# Progress ledger

**Status date:** 2026-08-05
**Branch:** `feat/typed-air-precompiles`
**Current milestone:** M3 — compatibility lowering
**Active task:** A-011 — round-trip every current family
**Next queued task:** A-012 — add layout diff helper

## Dashboard

| Milestone | State | Evidence |
| --- | --- | --- |
| M0 — engineering dossier | complete | This directory and initial ADRs |
| M1 — validated logical IR | complete | F-001 through F-012 complete and green |
| M2 — shadow compiler | complete | A-001 through A-005 complete and green |
| M3 — compatibility lowering | active | A-006 through A-010 complete; A-011 active |
| M4 — Poseidon compiler pilot | queued | Requires degree/layout passes |
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

## Immediate next actions

1. A-011 — package all-family compatibility identities and round-trip receipts.
2. A-012 — add the first-difference layout/report helper.
3. V-008 — record a clean-tree M3 milestone receipt once both are complete.

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

Pending:

- guest invocation ABI;
- guest Poseidon relation schema/version;
- canonical physical-layout manifest format;
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

## Baseline metrics

The [M2 machine report](artifacts/m2-production-shadow-report-v1.tsv) now pins
the current all-family logical node, direct-constraint, lookup, batch,
dependency, interaction-column, and final-degree counts. In aggregate across
independently compiled families it records 3,051 source nodes canonicalized to
3,049 typed nodes, 545 direct constraints, 242 lookup entries, 155 interaction
batches, and maximum direct/interaction degree three.

The following measurements remain assigned to their later owning milestones;
they are not prerequisites for closing the opcode shadow compiler:

- Poseidon2 main/interaction geometry and materializations — H-004;
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
