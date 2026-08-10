# Progress ledger

**Status date:** 2026-08-10
**Branch:** `feat/typed-air-precompiles`
**Current milestone:** M7 — parallel proving
**Active task:** R-001 — prepared composition scheduler slice
**Next ready task:** C-009 — one-proof guest integration
**Current acceptance gate:** full-security frozen-corpus proof differential,
production Tree-1 execution, exact request-bound R-005 telemetry, and a
normative R-006 receipt
**Known formal blocker:** the M3 refinement pilot still has the five stale
generated artifacts recorded in the M3 receipt; no reviewed regeneration or
current-HEAD receipt closes that blocker

## Dashboard

| Milestone | State | Evidence |
| --- | --- | --- |
| M0 — engineering dossier | complete | This directory and initial ADRs |
| M1 — validated logical IR | complete | F-001 through F-012 complete and green |
| M2 — shadow compiler | complete | A-001 through A-005 complete and green |
| M3 — compatibility lowering | blocked | [V-008 evidence](receipts/m3-compatibility-v1.json) recorded; broad proof/formal gates open |
| M4 — Poseidon compiler pilot | complete | H-001 through H-010 and V-006 complete; no layout selected |
| M5 — effect and witness pilot | ready | E-001 through E-004 complete; typed LUI has exact 18-column/9-root/7-event parity, while generated witness equality, proof authority, and further opcode families remain open |
| M6 — guest precompile | ready | C-001 through C-008 complete; C-009 now has profile-authenticated retirement admission and exact mixed-stream program commitment, while proof components, transcript integration, and independent one-proof verification remain open |
| M7 — parallel proving | active | Production RISC-V CPU composition is scheduled and emits a flat bounded-task profile with exact semantic contributions for fused lanes; selected prepared domains are row-sharded, profiled samples bind a coarse verified-request duration, and a pure Tree-1 plan closes deterministic ranges and finite host classes. Production Tree-1 execution, full-security parity, the exact R-005 partition, and normative R-006 evidence remain open |
| M8 — broad migration | queued | No opcode family has switched generated-witness authority; E-014/E-015 remain open |
| M9 — recursive aggregation | deferred | ADR-0030 and a native reference exist only as proposed/test authority; no recursive proof or verifier exists |

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
- Completed H-009: a separately identified bounded search validates each
  candidate cut from the typed semantic DAG, lowers an authenticated fixed
  prefix, all materialization equalities, and fixed suffix into one globally
  hash-consed direct DAG, and retains a deterministic Pareto frontier. The
  checked canonical `STWAIRM\0` artifact and exact TSV/Markdown review views
  record all 1,124 one-pass edits, 430 feasible and 694 infeasible results, and
  126 retained non-seed cuts. A canonical test pins the 410 removal, 304
  addition, and 410 swap edits. Every retained cut is exactly cost-equivalent
  to the compatibility seed across the complete vector and five log-size scenarios,
  so the result is a local plateau rather than a performance claim. Embedded
  tests regenerate both views byte for byte; `typed-air-frontier` defaults to
  fail-closed check and reserves atomic replacement for explicit update. The
  proposal surface has no `air/lang/mod.zig` re-export, H-009 embeds are
  isolated, and source conformance rejects unreviewed production consumers.
- Completed V-006: one canonical backend-neutral receipt binds the Poseidon
  semantic program, 445-column physical layout, authenticated witness
  executor, and relation plan under five reviewed SHA-256 digests. The CPU and
  Metal product paths reconstruct and return the same combined identity after
  honest proofs verify through the unchanged production verifier. The clean
  [V-006 receipt](receipts/v006-poseidon-program-identity-v1.json) records both
  product closures and the authenticated 118-export Metal AOT bundle. This is
  local proof-path co-attestation only: the identity is not in the transcript,
  public statement, proof bytes, or production verifier contract.
- Completed V-008: the machine-readable
  [M3 receipt](receipts/m3-compatibility-v1.json) names the clean detached
  `7cdf41d5b246baf845adeb99d02444d9a6090514` snapshot, exact toolchain,
  M2/M3 and formal identities, 657-test package results, all 17 manifest
  checks, workspace and AIR-satisfaction results, and a focused real proof. It
  also records rather than waives the broad prover-core rigidity failures,
  eight baseline source-conformance errors, and five stale artifacts detected
  by the refinement pilot after the 120-job Lean build passed. Compatibility
  implementation is complete; M3 release promotion remains blocked.
- Completed H-010: clean implementation commit
  `82bf6b9cd5eb1ab48edd6fb7c0c88a3be687e8c6`, tree
  `8cbb9300fa9b820baa079eeb94addf71db97f130`, authenticates four
  H-009-derived arms, checked log-10/log-14 vectors and their readable index,
  one prepared allocation-free retained evaluator, independent expected
  outputs, all 430 roots, the complete materialization/fixed-role mutation
  matrix, and strict fresh-child timing/RSS orchestration. Two independently
  valid complete reports retained locally as ignored evidence contain all 112
  required children with zero failures, retries, or drops: `v2`, 337,144 bytes
  with SHA-256
  `98abdf472818e21e43ff0e3cc3d509598558a6df6c1c215ea789a997fb5bc25d`,
  and `v3-confirm`, 337,146 bytes with SHA-256
  `eabeba5d67b26574dbe4246f8924411fe7c1df252452d078688ae6a0bcb5682a`.
  Candidate-versus-seed movement is not meaningful or repeatable across the
  two cohorts, so no layout is selected and all proof, Metal-candidate,
  production, and promotion exclusions remain in force. The
  [H-010 receipt](receipts/h010-authenticated-poseidon-layout-benchmark-v1.json)
  names the exact evidence and bounded conclusion.

## Current implementation evidence

- M5 foundations advanced without completing a vertical opcode slice.
  Commit `a3150a5c` supplies relation-bound program fetch and adjacent state
  consume/produce effects (E-001), `6cd0d64c` supplies typed register access
  groups with strict subclocks and alias validation (E-002), and `768d2972`
  supplies fixed register/memory access plans including the distinct load
  relation-order and physical-phase rules (E-003). LUI authoring, witness
  generation, proof differentials, and any authority switch remain open.
- M6 foundations advanced through C-006 without constructing a provable guest
  trace. Commit `3ee82e98` accepts the profile-scoped CUSTOM-0 ABI and adds the
  owned transactional call buffer and runner/host boundary; `ecfdbe2c` adds the
  guest relation registry, challenges, and events; and `2aa5701b` adds the
  profile component registry, statement geometry, manifest, and artifact
  identity. C-007 through C-009 remain the minimum path to a one-proof claim.
- The R-001 scheduler core at `24cb7f0f` has exact-capacity planning, explicit
  worker leases, joined cancellation, canonical error selection, nested-submit
  rejection, resource reservation accounting, and focused `N = 1/2/4` tests.
  Commit `78fb94fc` carries admitted production RISC-V CPU composition lanes and
  prepared fallbacks through that graph. This is production-path evidence, not
  by itself R-001 completion or a performance-promotion verdict.
- The active M7 slice at `46e3ca26` adds coordinator-prepared composition tasks,
  canonical coefficient-range ownership, and allocation-free leaf execution.
  Commit `eb6728a3` supplies prepared evaluators for generic memory, semantic,
  clock-update, opcode lookup, lookup-table, and memory-hash components. The row
  evaluators admit a 128 KiB worker stack, poll cancellation at bounded tiles no
  larger than 4,096 rows, validate geometry before execution, and keep fallible
  allocation on the coordinator. Focused generic-memory and semantic roots pass
  ReleaseSafe and ReleaseFast with 277/277 and 220/220 tests respectively,
  including independent pre-change row traversals for source order, previous
  rows, denominators, random powers, and final output bytes.
- Commit `683af21b` finalizes mixed-domain composition directly into prepared
  result storage. Commits `72527052` and `245a593f` subdivide large prepared
  memory-hash, lookup-table, and opcode-lookup domains into aligned row ranges
  under pool-exclusive leases. The bounded cancellation and disjoint-write
  rules preserve canonical output while allowing within-component scaling.
- Commit `c6b82ece` threads an explicit worker/contention/host-budget request
  through the public proof transaction. Commit `4e6e00e1` reserves fixed
  lease-owned submission envelopes and includes them in graph admission;
  structured waves perform no backing allocation. Commit `b84bd6c0` applies a
  hard live-byte allocator to finite generic and specialized RISC-V prepared
  plans, after first charging helper stacks and submission envelopes.
- Commit `035db833` adds opt-in post-verification canonical proof length and
  SHA-256 reporting. Reduced-security development checks establish identical
  proof bytes across current `N = 1/2/4` and against an instrumented predecessor
  at `N = 1` for `multi_shard_addi` and Poseidon field16. The exact identities
  and the separate controlled timing checkpoint are recorded in
  [the M7 development note](performance/m7-composition-checkpoint-2026-08-09.md).
- Commits `dc8617f3`, `0d5c4a26`, and `5f4dc56c` define and render a stable flat
  task-profile schema that distinguishes exact outer-task activity from
  physical-worker activity that is unobservable inside pool-exclusive child
  waves. Commit `e73c5e8b` captures exact-capacity task graphs with prelaunch
  reservation, unique event-slot writes, canonical post-join publication,
  checked accounting, and a timestamp-ready cancellation handshake. Commit
  `a1fc6786` propagates the existing proof recorder through generic and RISC-V
  CPU composition without changing the public proof request.
- Commit `4f8dbfb3` makes the RISC-V main-trace stage scopes structurally close
  after opcode-helper join on success, allocation failure, generation failure,
  and repeated cleanup. The focused failure fleet passes 26/26 in Debug,
  ReleaseSafe, and ReleaseFast.
- Commit `f0504be0` gives profiled benchmark samples their own closed schemas
  and binds every verified sample index to checked monotonic raw integers plus
  a deep-owned flat task profile. Guest execution, proving including witness,
  and native verification sum exactly; proof serialization and all subsequent
  snapshots, telemetry, artifact, and report work are excluded. The schema is
  deliberately marked development-coarse and protocol-incomplete until the
  non-overlapping witness/proving meter lands. The unprofiled `riscv_prove_v1`
  and `riscv_proof_v2` field sets remain exact, and the adapter's obsolete
  file-size exception is retired after its extraction to 831 lines.
- Commit `3b7606bb` introduces a pure, pointer-free Tree-1 coordinator plan. It
  derives exact descriptor prefixes, 65,536-row opcode and 4,096-row Poseidon
  partitions, deterministic strict/compatibility worker admission, finite
  named host-resource classes, private-counter chunk reduction, stable task
  keys, and 1,024-task wave limits. The plan is capped at 4,096 bytes and
  executes or commits nothing; backend commitment scratch, allocator metadata,
  and executor/profile storage remain explicit integration obligations.
- The final development-profile `multi_shard_addi` proof remains exactly
  161,274 canonical bytes with SHA-256
  `f367ca04d554a9d00d32c9279795b8e26032f4211a453074daa91211a9084293`
  at one, two, and four workers. A profiled four-worker proof verifies and
  publishes one 15-event graph with exact closed task accounting. The focused
  prover API, prover, CPU, and benchmark CLI suites pass in Debug,
  ReleaseSafe, and ReleaseFast.
- Commit `a928c9fa` implements a native serialization and tree reference for
  ADR-0030. The ADR remains proposed and the code is test authority only: no
  leaf proof authenticates the summary, no recursive verifier consumes it, and
  M9 remains deferred.

### Open gates for the active scheduler slice

- The specialized RISC-V CPU hook now uses the bounded graph for admitted
  composition lanes and prepared fallbacks. Other backend hooks and unprepared
  compatibility fallbacks retain fail-closed resource limitations.
- Reduced-security development checks cover two workloads across current
  `N = 1/2/4` and an instrumented predecessor at `N = 1`; the full-security,
  frozen-corpus ADR-0027 differential remains open.
- Within-component sharding is limited to large prepared memory-hash,
  lookup-table, and opcode-lookup domains. Other dominant components and the
  main/interaction construction stages are not yet covered. The new Tree-1
  module is planning authority only; no worker consumes it and commitment
  publication remains serial.
- Finite budgets are enforced for secure recurrence and closed prepared
  generic/RISC-V plans, including coordinator heap and reserved helper stacks
  and submission envelopes. Unprepared and non-heap scratch/device plans reject
  finite caps.
- The bounded composition graph now reports canonical task events, dependency
  readiness, admission/queue/resource wait, outer-task run time, declared byte
  classes, coarse completed rows/tiles, cancellation, and closed summary
  accounting. Profiled verified samples now bind a coarse monotonic request
  partition to that graph, but R-005 remains open because witness and proving
  are not yet separated, fused lanes lack semantic attribution, nested
  physical-worker work is not exact, and broader prover-stage coverage is not
  available. Serialization is intentionally outside the measured partition;
  the R-006 receipt remains open.
- The independent M3 release blocker remains: the refinement pilot recorded
  drift in five committed generated artifacts after a successful 120-job Lean
  build. This ledger update neither regenerates nor accepts those artifacts.

## Immediate next actions

1. R-001/R-002 — execute the pure Tree-1 plan through coordinator-prepared,
   allocation-free leaves and prove exact serial differential behavior across
   success, cancellation, and injected failure.
2. R-005/R-006 — land the non-overlapping witness/proving phase meter, then
   capture the authenticated fresh-process attempt bundle and
   validator-recomputed normative receipt under the frozen M5--M9 protocol.
3. C-009/E-005 — add the guest caller/provider proof-component adapters and
   profile transcript while completing exact LUI shadow-witness column
   equality without changing base production authority.

C-009 and E-005/E-006/E-010 remain dependency-safe tracks, but none is marked
active while the prepared scheduler slice owns the primary task. C-009's
pre-transcript admission and program-authority slice is complete; its task
status remains ready until the proof-component boundary is integrated.

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
- A canonical backend-neutral Poseidon identity over semantic, layout,
  executor, and relation identities, co-attested beside verified CPU and Metal
  proofs without claiming transcript or production-verifier binding, as fixed
  by
  [ADR-0021](decisions/0021-backend-neutral-poseidon-program-identity.md).
- Cost-frontier proposals remain separately identified, test-only evidence;
  an equal structural neighbourhood is a benchmark input rather than an
  activation decision, as fixed by
  [ADR-0020](decisions/0020-cost-frontier-materialization-proposals.md).
- H-010 closes the authenticated retained-evaluator experiment without
  selecting a materialization layout. Its two complete default cohorts are
  diagnostic CPU evidence only; proof, Metal-candidate, production-layout, and
  promotion authority remain false.
- Relation-bound state effects, strict register subclocks, and the distinct
  load/store access-phase plan are fixed by ADR-0023, ADR-0026, and ADR-0028.
- The profile-scoped guest Poseidon2 ABI, relation/subclock rules, and separate
  component/statement/artifact identity are fixed by ADR-0024, ADR-0025, and
  ADR-0029. These decisions do not claim a completed guest proof.
- Guest program authority is profile-separated: the closed RV32IM decoder is
  unchanged, canonical CUSTOM-0 maps to appended protocol opcode 46, and the
  declared-program commitment consumes base, guest, and completion fetches as
  borrowed streams without allocating a concatenated execution trace.
- The bounded component task graph and its migration constraints are fixed by
  ADR-0027. Acceptance of the design does not mark R-001 or M7 complete.

Proposed:

- ADR-0030 defines a session-bound cross-proof relation-summary design and has
  a native test reference. It has no production or recursive-verifier
  authority.

Pending:

- generated witness activation policy;
- review and acceptance of ADR-0030;
- recursive verifier field/protocol.

## Risks under watch

| Risk | Current control |
| --- | --- |
| New abstraction drifts from production | Shadow import and exact compatibility lowering |
| Compiler shares wrong semantics with witness | Sail, mutation, formal, and independent runner evidence |
| Layout changes silently | Versioned deterministic manifests |
| Typed DSL becomes stringly or magical | Canon relation/effect rules and constructor validation |
| Poseidon pilot becomes a toy | Exact 445-column production component target |
| Precompile weakens base-RV32IM claim | Base validation and decoding remain closed; the extension has independent pre-transcript admission and program authority, while C-009 must still close the proof and fresh-process verifier path |
| Parallelism hides total cost | Frozen M5--M9 performance protocol; flat composition telemetry is graph-local and excludes unobserved nested-worker/profile-allocation cost, so no M7 verdict exists until R-005 closes and a protocol-complete R-006 capture passes |
| Prepared tests are mistaken for production scheduling | Ledger requires a full-security frozen-corpus proof differential and separates the controlled production-path checkpoint from a normative receipt |
| Recursion balances detached calls | ADR-0030 remains proposed and requires shared session challenges plus authenticated leaf summaries |
| Hint callback or output drifts silently | Closed versioned registry and checked proof paths |
| Broad production proof gate is red | V-008 records exact rigidity findings; no release promotion |
| Formal generated artifacts are stale | Refinement pilot fails closed on five named files; reviewed workflow required |
| Compiled witness drifts after binding | Executable digest, structural preflight, and independent canonical recompilation |
| Shadow equality is mistaken for proof evidence | H-007 requires generated artifacts inside CPU/Metal proofs before promotion |
| Local identity co-attestation is mistaken for protocol binding | V-006 states that the transcript, public statement, proof bytes, and production verifier are unchanged |
| Noisy microbenchmark movement is mistaken for a layout winner | H-010 has two complete independent cohorts; q0/q100 log-14 witness directions flip within MAD/noise, so no layout is selected |
| Native aggregation reference is mistaken for M9 evidence | Reference serialization/tree tests are explicitly unauthenticated by leaf proofs and unused by a recursive verifier |

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

H-010 now adds two complete common-evaluator cohorts at logs 10 and 14. Each
contains 112 fresh child samples with no failures, retries, or drops. Across
both reports, candidate witness, direct, and RSS deltas remain small and
inconsistent; q0/q100 log-14 witness directions reverse between runs. The
authoritative interpretation is no meaningful repeatable layout regression
and no selected layout, not a zero-cost or proving-speed claim. Exact ranges
and report identities are recorded in [PERFORMANCE.md](PERFORMANCE.md).

The active M7 structural baseline has a 1,024-task graph bound and prepared AIR
row evaluators with a 128 KiB admitted worker stack and cancellation tiles no
larger than 4,096 rows. Fixed submission envelopes make structured leased waves
backing-allocation-free. Large prepared memory-hash, lookup-table, and
opcode-lookup domains split into aligned row ranges, and finite closed plans
charge coordinator heap plus reserved helper stacks and submission envelopes.
Those are implementation bounds, not a promotion verdict.

The bounded graph now also has an opt-in, allocation-before-launch flat profile.
It reports exact task accounting and canonical events without a shared worker
append. `graph_elapsed_ns` is deliberately graph-local; task peak/run metrics
remain exact while physical-worker peak/busy metrics are absent for graphs
containing uninstrumented pool-exclusive child work. Declared task-resource
peaks exclude recorder storage and are not RSS evidence. These boundaries are
part of the schema contract, not presentation caveats.

A controlled development comparison at clean candidate `72527052` versus
`4232cc55` used 12 excluded warmups, 60 measured samples, five interleaved
samples per workload/revision/worker cell, reduced security (`pow_bits=0`,
`n_queries=3`), and 94/94 verified proof-bearing runs. At two workers,
`multi_shard_addi` proving improved 11.92% and composition 44.14%; Poseidon
field16 proving improved 13.22% and composition 46.11%. One-worker performance
was near-flat, four-worker proving improved about 5%, and median RSS was flat;
one Poseidon four-worker RSS spike did not reproduce in three extra pairs.
Exact binary identities, ranges, and proof hashes appear in
[the checkpoint note](performance/m7-composition-checkpoint-2026-08-09.md).
This is not a digest-bound M7 attempt bundle or receipt and makes no
full-security verdict. R-005/R-006 must use the frozen
[M5--M9 protocol](performance/m5-m9-protocol-v1.json); H-010 diagnostic cohorts
cannot be reused as M7 evidence.

The following measurements remain assigned to their later owning milestones;
they are not prerequisites for closing the opcode shadow compiler:

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
those facts and exclusions; the later H-009 record below supersedes its task
queue statement without changing that H-007 evidence.

### 2026-08-06 — bounded Poseidon materialization frontier pinned

H-009 now has a deterministic proposal pipeline and reviewed evidence without
changing production. The cost model authenticates the materialization tree and
physical interval, the enabler/wide/io fixed columns, eleven-node fixed SSA,
four fixed roots, and prefix/equality/suffix schedule. Explicit node-birth and
root-fold events make the canonical streaming-liveness coordinate sound even
when a later root reuses an earlier interned node. Fixed columns cannot alias
the candidate block, both lowering phases must use one emitter, ordered root
multiplicity remains representable, and randomized root-by-root differentials
tie all four fixed formulas to the production Poseidon AIR.

The complete one-pass neighbourhood contains 1,124 edits. It admits 430 unique
feasible candidates, rejects 694, sees no duplicates, and retains 126
untruncated non-seed cuts. All 126 match the seed at every structural and
scenario coordinate: 426 materializations, 445 main columns, 430 roots, 3,460
canonical direct nodes, 1,346 additions, 429 subtractions, 1,080
multiplications, 445 committed reads, theoretical streaming peak 39, and 2,171
semantic witness nodes. The 3,460-node value is the modeled proposal DAG, not
observed backend scratch. Production Poseidon uses a separate static evaluator,
alternative H-009 layouts do not yet execute on CPU or Metal, and Poseidon
composition has no Metal capability. The 39-node schedule is therefore an
implementation hypothesis, not an observed memory saving.

The canonical complete binary and exact TSV/Markdown review projections are
checked under `artifacts/h009-poseidon2-cost-v1/`. Package tests decode the
binary and regenerate both views exactly; the standalone check/update command
generated and then rechecked all three files. The ReleaseFast frontend suite
now compiles 763 tests (762 pass, one intentionally skipped). H-009 is complete
as a prototype and negative structural result. Exact proposal-consumer
isolation is enforced by source conformance. It makes no global-optimality,
proving-speed, proof-size, or production-activation claim. The clean immutable
[H-009 receipt](receipts/h009-poseidon2-cost-frontier-v1.json) pins commit
`ee14cc8b9bed1a20dfd8dfce7f6c7f112ccee850`, the complete search and artifact
identities, the calibrated evaluator boundary, and the unchanged CPU/Metal
product gates. The calibration leaves the canonical binary and TSV unchanged;
only the human projection and explanatory sources change. At this checkpoint
H-010 became active; the closure entry below completes it.

### 2026-08-06 — backend-neutral Poseidon identity co-attested

V-006 closes the identity ambiguity left deliberately open by H-007. The
authenticated typed semantic program, 445-column layout, 2,171-instruction
executor, and four-event/two-batch relation plan now each have a canonical
child digest. Their reviewed combined digest is
`594c88bfe11d6c8cb65918a7bfcf72257a79b61674997dbed24151ea3fb88a65`.
The proof authority reconstructs the owned H-003 through H-006 chain before
backend work, reconstructs it again after proof construction and claim
installation, and rejects lifecycle drift or a self-consistent noncanonical
receipt.

At clean commit `4a020b85a5b0c5c566c2e09cbec5cf083753e3e7`, both the CPU
and authenticated-AOT Metal product gates pass and return that exact identity
beside independently verified honest proofs. The CPU closure contains 507
transitive Zig sources; the Metal closure contains 564 and admits the exact
118-export, zero-function-constant AOT bundle with resident RISC polynomial
execution and zero CPU polynomial-composition declines. ReleaseFast and
ReleaseSafe frontend suites each compile 763 tests, with 762 passing and one
intentional skip. Package-workspace, artifact, proposal-isolation, and product
closure gates pass; source conformance adds no H-009 or V-006 finding and
retains only the recorded unrelated repository baseline.

The [V-006 receipt](receipts/v006-poseidon-program-identity-v1.json) is final
for this test-only scope. It does not place the identity in the Fiat-Shamir
transcript, public statement, proof commitment, or production verifier, and
therefore makes no cryptographic inseparability or production-activation
claim. At this checkpoint H-010 owned the remaining compiler-pilot performance
decision; the closure entry below completes it.

### 2026-08-06 — authenticated Poseidon layout benchmark closed without promotion

H-010 closes the M4 compiler pilot on clean implementation commit
`82bf6b9cd5eb1ab48edd6fb7c0c88a3be687e8c6`, tree
`8cbb9300fa9b820baa079eeb94addf71db97f130`. The isolated runner
authenticates the exact H-009 artifact and four deterministic cuts, checked
log-10/log-14 `STWAIRB\0` vectors and readable index, fixed program, prepared
allocation-free retained witness/direct evaluators, independent expected
outputs, all 430 roots on every admitted row, and the complete 426-cell and
fixed-role mutation matrix. Candidate trace digests remain regression-only and
log 18 remains generated, opt-in, and non-receiptable.

Two independently collected reports are valid and complete under declared
power state `AC/100%/powermode0`. Both use executable SHA-256
`65cc075bea26b731ce50093cc1fffa06ef7fd2ddb9979370b40f2e9398ab96bf`
and the 301-source closure SHA-256
`b23fea8136f4791b60196a2c21b15afad5274e45bd29f672657a992dfc48d983`.
The locally retained ignored `v2` bytes are 337,144 bytes with SHA-256
`98abdf472818e21e43ff0e3cc3d509598558a6df6c1c215ea789a997fb5bc25d`;
`v3-confirm` is 337,146 bytes with SHA-256
`eabeba5d67b26574dbe4246f8924411fe7c1df252452d078688ae6a0bcb5682a`.
Each contains all 112 required fresh sample children with zero failures,
retries, or drops.

In `v2`, candidate-versus-seed log-10 deltas span +0.123% to +1.009% for
witness, -0.415% to +0.384% for direct, and 0.000% to +0.209% for RSS. Log-14
deltas span -2.557% to +2.242%, -0.124% to +0.214%, and -0.128% to -0.043%
respectively. In `v3-confirm`, log-10 spans -1.121% to +0.924%, -0.872% to
+0.940%, and -0.416% to -0.208%; log-14 spans -1.589% to +0.271%, +0.004% to
+0.796%, and +0.043% for every candidate arm. q0 and q100 log-14 witness
directions flip between runs, and the movement remains within MAD/noise. The
bounded conclusion is no meaningful repeatable layout regression and no
selected layout.

Clean reruns pass ReleaseFast and ReleaseSafe frontend suites with 792 of 793
tests passing and one intentional skip; aggregate, CPU, and Metal product
closures contain 567, 520, and 577 sources with SHA-256 identities
`5137a2f7e587f2b80af44950f545ca70e003bdf4de71944aa71f47fba5ac11d0`,
`a64b61790c33988efc7ad1b5f14b5910b6fe830ff20980a735645b7ba0001ad8`,
and `e4f0fd05906e062c61030b4ac7d5340c306981c1a441aef58ae501fdc8a507b7`.
Metal admits 118 authenticated AOT exports. Package workspace checks cover 21
packages and 70 edges; H-010/isolation Python tests pass 14 of 14 and
source-conformance unit tests pass 35 of 35. The repository conformance scan
retains the exact inherited three warnings and eight errors with no H-010
finding.

The [H-010 receipt](receipts/h010-authenticated-poseidon-layout-benchmark-v1.json)
records the immutable implementation, both report identities, clean gates, and
exclusions. Proof, verification, Metal-candidate, production-layout, and
promotion claims remain false. M4 and H-010 are complete; C-001 is now the sole
active task and must decide the guest ABI before any precompile implementation.

### 2026-08-09 — prepared composition scheduler slice is active

The ledger catches up through implementation commit `4232cc55`. M5 now has the
relation-bound state, register, and memory access foundations required by
E-001 through E-003, but none of the LUI/ADDI/load/JALR/DIV vertical witness
slices is complete. M6 has an accepted profile-separated ABI and relation,
transactional guest calls, and authenticated component/statement geometry
through C-006, but no guest main trace, interaction trace, proof, or verifier
evidence. Both milestones therefore remain incomplete and ready rather than
active.

M7 owns the sole active task. The bounded scheduler core and prepared
composition interface now enforce exact-capacity planning, worker leases,
joined cancellation, canonical failure selection, coordinator-owned
allocation, declared resource geometry, and allocation-free row loops. The
RISC-V memory, semantic, clock-update, opcode lookup, lookup-table, and hash
components expose prepared capabilities. Independent generic-memory and
semantic references pass their focused ReleaseSafe/ReleaseFast roots at
277/277 and 220/220 tests.

This is deliberately not an R-001 or M7 completion claim. Production CPU
composition still selects its specialized backend before the generic graph;
there is no complete predecessor/graph `N = 1` proof-byte differential; large
components are not row-sharded; and the compatibility entrypoint supplies no
finite request byte budget or performance telemetry. Consequently no M7
capture or performance verdict exists. The next implementation must close
those exact gates before R-002 through R-006 or any throughput claim advances.

ADR-0030 and its native reference establish only a proposed M9 serialization
and aggregation-tree model. They authenticate no leaf proof and drive no
recursive verifier, so M9 remains deferred. Separately, the five generated
formal artifacts named by the M3 receipt remain stale; no formal regeneration
or acceptance occurred in this interval.

### 2026-08-09 — production composition path is bounded and measured

The ledger advances from `4232cc55` through clean head `b84bd6c0`. Production
RISC-V CPU composition now executes its admitted packed lanes and prepared
fallbacks through the bounded graph. Large prepared memory-hash, lookup-table,
and opcode-lookup domains use aligned row sharding under pool-exclusive leases.
Mixed-domain finalization writes into prepared output storage, structured task
waves reserve fixed submission envelopes with no backing allocation, and an
explicit per-proof worker/contention/host-budget request reaches both the
execution-aware CPU backend and generic prepared path.

Finite host caps now charge reserved helper stacks and submission envelopes
before enforcing a hard live-byte limit over coordinator-owned preparation and
result storage. Secure recurrence and closed prepared generic/RISC-V plans are
covered. Unprepared fallback and declared non-heap scratch/device residency
reject finite caps rather than silently escaping accounting. Focused generic,
specialized RISC-V, scheduler, allocator, prover API, CPU, and frontend tests
pass in the exercised ReleaseSafe/ReleaseFast lanes. The full RISC-V CPU product
lane reached 1,205/1,212 with seven expected Sail skips; its sole failure is the
already-recorded stale canonical production-AIR source binding.

The controlled development timing checkpoint compares clean `72527052` with
`4232cc55` under reduced security. It closes the previously observed
two-worker composition regression for both checked workloads: two-worker
proving improves 11.92% for `multi_shard_addi` and 13.22% for Poseidon field16,
with composition-stage improvements of 44.14% and 46.11% respectively.
One-worker controls remain near-flat, four-worker proving improves about 5%,
and median RSS is flat. A separate final-head correctness check reports exact
canonical proof identity across `N = 1/2/4` and against an instrumented
predecessor at `N = 1` for both workloads.

This remains non-promotional development evidence. R-001 and M7 stay active
because the full-security frozen corpus, broader component/stage coverage,
R-005 queue/run/wait/memory telemetry, authenticated raw attempts, and the
validator-recomputed R-006 receipt remain open. The five stale M3 formal
artifacts also remain an independent release blocker.

### 2026-08-09 — bounded composition task profiles are live

The ledger advances through implementation head `a1fc6786`. Commits
`dc8617f3`, `0d5c4a26`, and `5f4dc56c` establish the public flat task-profile
schema and deterministic renderer. Commit `e73c5e8b` adds exact-capacity graph
capture with allocation before launch, preassigned event slots, canonical
post-join publication, checked accounting, and a timestamp-ready cancellation
handshake. Commit `a1fc6786` carries the recorder through generic prepared and
specialized RISC-V CPU composition while leaving the public proof request and
proof protocol unchanged.

The focused prover API, prover, CPU backend, and benchmark suites pass in
Debug, ReleaseSafe, and ReleaseFast; the 21-package/70-edge workspace check and
diff hygiene pass. A ReleaseFast `multi_shard_addi` proof at reduced security
verifies with exactly 161,274 canonical bytes and SHA-256
`f367ca04d554a9d00d32c9279795b8e26032f4211a453074daa91211a9084293`
at `N = 1/2/4`. Its profiled four-worker run publishes one canonical 15-event
graph with 15 planned, submitted, and completed tasks, zero failed, cancelled,
unsubmitted, or duplicate terminals, 12 component aggregates, and four peak
active outer tasks. Pool-exclusive nested work makes physical-worker peak and
busy time correctly absent rather than estimated. The full RISC-V CPU product
lane remains at 1,205/1,212 with seven expected Sail skips and only the known
stale canonical production-AIR source binding failure.

A five-pair, alternating-order ReleaseFast regression screen against clean
predecessor `5f4dc56c`, with profiling disabled, is directionally flat. Median
prove/total deltas are -0.031%/+0.056% at `N = 1` and +0.346%/+0.255% at
`N = 4`. On the candidate, enabling the optional recorder changes median
prove/total time by +0.098%/+0.082% at `N = 1` and +1.240%/+1.895% at `N = 4`.
These timings are diagnostic only: they have no A/A calibration, full-security
corpus, retained raw bundle, CI isolation, RSS, or hardware-counter evidence.

R-001 and M7 remain active, and R-005/R-006 remain open. At this checkpoint the
profile did not yet cover an exact verified-request partition, physical
activity inside pool-exclusive child waves, semantic attribution within fused
RISC-V lanes, recurrence/device/legacy work, or every dominant prover stage.
Recorder memory was also excluded from declared task-resource peaks. Those
boundaries, the full-security frozen corpus, and a validator-recomputed
normative receipt must close before any promotion or completion claim.

### 2026-08-09 — verified samples are bound and Tree-1 planning is explicit

The ledger advances through clean implementation head `f0504be0`. Commit
`4f8dbfb3` first closes main-trace profile scopes through the joined opcode
helper on every tested exit. Commit `f0504be0` then separates the internal and
outer profiled schemas from their unprofiled compatibility envelopes. Every
profiled, successfully verified sample retains checked raw monotonic guest,
proving-including-witness, and native-verification nanoseconds beside its
deep-owned flat task profile and sample index. Their sum is exact, proof
serialization is excluded, and post-verification telemetry, snapshots,
artifact publication, and report rendering cannot contaminate the authority.

That timing is intentionally labelled development-coarse and
protocol-incomplete. The exact R-005 contract uses five non-overlapping
materialization regions and computes proving as the checked complement of the
proof boundary; existing nested stage totals cannot be summed because opcode
and infrastructure generation overlap. Until that meter is wired, no receipt
may relabel the coarse field as normative witness or proving time.

Commit `3b7606bb` independently lands the pure Tree-1 planning seam. It retains
no statement pointer, allocates nothing, and fixes exact descriptor coverage,
aligned row partitions, stable task identities, deterministic admission,
private-counter budget reduction, named host resources, and per-wave capacity.
Its focused planner suite passes 9/9 in Debug, ReleaseSafe, and ReleaseFast;
the adapter suite passes 30/30 in all three modes. The 21-package/70-edge
workspace check and diff hygiene pass. A full Debug frontend run compiled the
new inventory and reached 918/921 with three expected Sail skips before the
known inherited signal-6 failure in the opcode prepared-parallel cancellation
test. Source conformance remains nonzero only for the six recorded inherited
Metal/source-ingest size findings; the adapter's former exception is gone.

Neither seam executes production Tree-1 work, supplies semantic contributions,
separates witness from proving, captures a fresh-process attempt bundle, or
changes the proof protocol. R-001 and M7 therefore remain active, R-002 remains
queued, and R-005/R-006 remain open.

### 2026-08-10 — typed LUI authorship is compatibility-exact

E-004 is complete. ADR-0031 fixes closed `pc + 4` and `clock + 1` retirement,
the exact `range_check_8_8_4@1` constructor, and a new canonical capability
boundary: manifest format 7/logical schema 6 and semantic digest format 5.
Formats 5/6 and digests 3/4 reject the new sequential derivations instead of
silently expanding their grammars.

The native typed LUI definition reproduces all 18 production main columns,
nine direct roots, and seven ordered relation events. Canonical fingerprints
match every production root and relation field; maximum direct degree remains
two. Its defensive validator binds the complete source-independent semantic
digest and rejects coordinated opcode, immediate, root, result, state,
relation, and destination substitutions. Closed-use, partial-pair, allocation
failure, and rollback adversaries are inventoried separately from the parity
fleet to preserve source-size headroom. The focused instruction AIR suite
passes 216/216 in Debug, ReleaseSafe, and ReleaseFast. Production witness,
component selection, commitment geometry, transcript, and proof authority are
unchanged; E-005 remains the next LUI gate.

### 2026-08-10 — guest main and interaction traces close exactly

C-007 and C-008 are complete. The profile-scoped caller and compatibility
provider main traces are constructed transactionally from the two frozen
execution authorities in one committed-order allocation. Active rows are a
contiguous prefix, padding is inactive, provider outputs are recomputed before
allocation, and the exact 286-column caller plus 445-column provider layouts
remain authenticated by the accepted component registry.

The interaction generator reconstructs every tuple only from those committed
columns under the one appended guest challenge pair. Its fixed plan contains
153 caller events in 77 batches and four provider events in two batches,
producing exactly 308 plus eight interaction columns. Authenticated
`BatchPlan.interaction_column_start` values are the sole output-placement
authority and are compile-time checked for bounds, overlap, order, and complete
ownership. Static event specialization removes schema/arity dispatch from the
row loop; the three coefficient-zero legacy provider events perform no
denominator work. Generation writes normalized caller terms directly into a
bounded 256-row inversion scratch, retains one output allocation, allocates
nothing per row, and extends the zero-padding prefix without inversions.

Eleven named C-008 tests are inventoried and pass in Debug, ReleaseSafe, and
ReleaseFast. They cover independent offset authority, exact 255-to-256 chunk
rollover at 257 active rows, every active/padding/cyclic boundary equation,
zero calls, omission, duplication, committed-column mutation, malformed
zero-coefficient entries, zero denominators, allocation rollback, and exact
caller/provider guest cancellation. A local ReleaseFast development probe
measured roughly 2.89 microseconds per row at 4,096 rows and 3.25 microseconds
per row at 16,384 rows, versus the earlier 4.2--4.3 microsecond implementation.
This is directional kernel evidence only, not a protocol-complete benchmark or
proof-speed claim. C-009 still owns the guest AIR components, transcript and
claim integration, global cancellation at the proof boundary, and independent
fresh-process verification.

### 2026-08-10 — guest admission and program authority are profile-exact

C-009's first pre-transcript slice is complete without widening either base
statement validation or the base RV32IM decoder. An authenticated retirement
supplement composes base opcode rows with guest rows and checks the exact
memory-relation coefficient budget before any channel state is consumed. The
guest boundary independently reconstructs component constructions and the
canonical artifact identity; malformed row counts, coefficient certificates,
and decoded identities fail closed. The zero-call profile is canonical, while
the unchanged base validator continues to require every base retirement to
occupy an ordinary opcode-family row.

The profile decoder admits only the exact reserved-bit-clean CUSTOM-0
Poseidon2 encoding and maps it to `{46, 0, rs1, 0}` after all 46 base protocol
IDs. Program commitment now counts base execution rows, frozen guest rows, and
the optional completion fetch through heterogeneous borrowed streams. It does
not concatenate retirement logs, performs no per-retirement allocation, and
decodes every declared nonzero word under the selected profile before building
the existing sorted sparse-Merkle authority. The legacy base construction and
public base API remain byte-exact and reject CUSTOM-0.

Thirteen new tests are inventoried: three admission tests, eight guest program
tests, and two decoder tests in the existing program module. The program
slice's zero-versus-1,024-row
allocation probe records identical allocation count and bytes for fixed ROM
geometry; exact rows, root, leaves, and nodes match the independent legacy
path for ordinary programs. The focused guest suite passes in Debug,
ReleaseSafe, and ReleaseFast, and the package workspace remains 21 packages,
21 public modules, and 70 dependency edges. This is not C-009 completion: the
caller/provider AIR adapters, shared-tree ownership, lookup multiplicities,
profile transcript, global cancellation, and fresh-process verifier remain
open.

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
