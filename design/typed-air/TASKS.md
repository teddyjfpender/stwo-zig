# Task graph

**Status:** active backlog
**Last updated:** 2026-08-20

## Status vocabulary

- **done** — acceptance evidence exists on this branch.
- **active** — exactly one primary task is being implemented.
- **ready** — dependencies are complete and acceptance is defined.
- **queued** — valid work, dependency not complete.
- **blocked** — external decision or repeated technical blocker is recorded.
- **deferred** — intentionally outside the current delivery.

Priority `P0` protects correctness or the critical path. `P1` completes the
first production milestone. `P2` improves breadth or optimization.

## Milestones

| Milestone | Result | Exit condition | Status |
| --- | --- | --- | --- |
| M0 | Engineering dossier | Branch, canon, architecture, tasks, validation, progress | done |
| M1 | Validated logical IR | Deterministic IR kernel and negative tests | done |
| M2 | Shadow compiler | All 17 current families imported and degree-reported | done |
| M3 | Compatibility lowering | LUI and then all families round-trip exactly | ready (current gates green; clean immutable receipt open) |
| M4 | Pure compiler pilot | Poseidon2 compatibility path verified; H-010 default cohort reviewed | done |
| M5 | Effect/witness pilot | LUI, ADDI, signed load/JALR, DIV vertical slices | ready |
| M6 | Guest precompile | Poseidon2 calls close in one proof | ready |
| M7 | Parallel proving | Component stages scheduled and measured | active |
| M8 | Broad migration | Handwritten witness duplication retired | done |
| M9 | Recursive aggregation | Bound leaf summaries aggregate through a canonical multi-level tree | active |

M3's state refers to the current checkout: the workspace is `21/21` packages
and 70 edges, compatibility manifests are `17/17`, frontend Debug is 2,149
passes plus one intentional skip, recursion is `583/583` in all three modes,
the relocated native proof is exact at 5,184 bytes with the same transcript in
all modes, and RISC-V CPU integration is `17/17` in ReleaseFast. The final
formal reseal is green `59/59`, with digest
`375b77cc4c11c2af324b3d66a989fd1e69a58c809dbb68e444d6b6a25fdeba86`
and source closure
`c9bc6c362663ce20aac44b9a004a4d86e71f9888bf2a809512116733db0a8bb2`.
A clean top-level receipt has not been minted, so M3 is `ready`, not `done`.
Historical V-008 remains unchanged and is not evidence for this tree.
Those M3 gates alone do not establish an outer proof, whole-frontend
verification, or proof-system soundness. Separate current evidence below does
establish the complete SegmentV2 leaf and first temporal parent within its
explicitly narrower claim boundary.

## Immediate queue

| ID | Task | Depends | Acceptance | Status |
| --- | --- | --- | --- | --- |
| F-001 | Add `air/lang` package skeleton and test inventory wiring | M0 | Package tests execute new focused tests; no production imports | done |
| F-002 | Implement typed IDs, semantic types, source spans, and arena ownership | F-001 | Construction/deinit tests; invalid cross-ID use impossible at compile time | done |
| F-003 | Implement expression nodes and structural interning | F-002 | Stable topological IDs; equivalent expressions intern; order-independent test corpus | done |
| F-004 | Implement constraints, hints, effects, functions, and structural validator | F-003 | Named negative test for every validator error class | done |
| F-005 | Implement canonical logical manifest serialization | F-004 | Two clean builds and insertion-order perturbations produce identical bytes | done |

## Foundation tasks

| ID | Priority | Task | Depends | Acceptance | Status |
| --- | --- | --- | --- | --- | --- |
| F-006 | P0 | Define typed relation schema registry | F-002 | Existing relation domains represented without strings; invalid roles/arity reject | done |
| F-007 | P0 | Define acyclic function graph and static call validation | F-004 | Recursive cycle and missing callee tests reject deterministically | done |
| F-008 | P0 | Define hint recipe registry and binding metadata | F-004 | Unbound output and unknown recipe reject | done |
| F-009 | P1 | Add stable diagnostic renderer | F-003 | Diagnostics include component, source span, value path, type, and degree | done |
| F-010 | P1 | Add canonical program digest | F-005 | Digest changes for semantic order/type changes and not allocator/address changes | done |
| F-011 | P1 | Add allocation-failure tests for arena finalization | F-004 | All partially initialized owners deinit cleanly | done |
| F-012 | P1 | Document public authoring interface | F-004 | One minimal pure and one effectful example compile in tests | done |
| F-013 | P0 | Compile Cairo-style frames and activation events | F-007, F-010 | Declared-input isolation, write-once locals, hint ownership, deterministic tuple ABI, canonical consume/emit/public events, digest and allocation gates | done |
| F-014 | P0 | Lower function activations into the live LogUp protocol | F-013, A-014 | Prover/verifier draw bound per-function challenges; calls and public roots balance; omission, duplication, collision, and transcript mutations reject | done (compiler-owned degree-2 lowering under authenticated degree-3 bound; verifier-owned public-root recomputation; 21/21 Debug and ReleaseFast; dormant at zero protocol cost until a production component owns a relation-backed function) |
| F-015 | P0 | Bind complete function bodies and inline substitution | F-013, A-007 | Constraints/effects/hints/calls have one frame owner; inline call outputs lower and execute without an unconstrained committed cell | done |

## Shadow analysis and lowering

| ID | Priority | Task | Depends | Acceptance | Status |
| --- | --- | --- | --- | --- | --- |
| A-001 | P0 | Import current symbolic polynomial DAG | F-004 | Random replay equals `symbolic.replay` | done |
| A-002 | P0 | Import columns, constraints, selector, and ordered lookups | A-001, F-006 | Counts and order match all 17 families | done |
| A-003 | P0 | Implement logical degree propagation | A-001 | Unit corpus covers constants, sums, products, selections, aliases | done |
| A-004 | P0 | Model gates, row windows, boundaries, and interaction degree | A-002, A-003 | Report includes complete final degree, not only root degree | done |
| A-005 | P0 | Emit all-family degree and dependency report | A-004 | Golden machine report and readable summary for 17 families | done |
| A-006 | P0 | Define `compat-v1` physical column mapping | F-005, A-002 | Current column count/name/order reproduced | done |
| A-007 | P0 | Lower direct constraints to current `ConstraintProgram` | A-006 | LUI exact normalized DAG comparison | done |
| A-008 | P0 | Lower typed effects to current ordered lookup entries | A-007, F-006 | LUI event fields and batch order exact | done |
| A-009 | P0 | Reproduce runtime polynomial program | A-007 | Node/root/column identity test | done |
| A-010 | P0 | Reproduce AIR IR v2 projection | A-008 | Byte-identical canonical export for LUI | done |
| A-011 | P1 | Round-trip every current family | A-009, A-010 | 17 compatibility manifests and exports exact | done |
| A-012 | P1 | Add layout diff command/test helper | A-006 | Diff identifies first semantic/layout divergence with names | done |
| A-013 | P0 | Add typed masks, shifted columns, and row-window ownership | A-004, A-006 | Boundary and ownership validation, degree lowering, PCS mask emission, and cross-row forgeries pass | active, performance-only (correctness and production activation complete: 17/17 generated semantic/lookup pairs, exact 51,581-byte proof and transcript parity in Debug/ReleaseFast, independent verification; paired global P-004 evidence remains) |
| A-014 | P1 | Select lookup batches under degree and cost bounds | A-013, P-003 | Deterministic partition is manifest-bound; singleton/pair proof differential and collision negatives pass | active (explicit authenticated CPU V2 proves all 17 families: Tree 2 688 -> 616, proof 51,863 -> 50,256 bytes, independent verification and reciprocal replay rejection; compatibility V1 remains default; native Metal/no-fallback and normative performance remain) |

## Poseidon2 compiler pilot

| ID | Priority | Task | Depends | Acceptance | Status |
| --- | --- | --- | --- | --- | --- |
| H-001 | P0 | Add typed fixed-size arrays, maps, and folds | F-007 | Static shape and source-span tests | done |
| H-002 | P0 | Author pure M31 Poseidon2 permutation | H-001, A-003 | Output matches current permutation vectors | done |
| H-003 | P0 | Implement deterministic degree-three materializer | H-002, A-006 | Every lowered constraint within bound; stable allocation | done |
| H-004 | P0 | Reproduce 426 existing materializations | H-003 | Current 445-column layout and constraint order exact | done |
| H-005 | P0 | Generate direct-to-final-storage witness | H-004, F-008 | Byte-identical rows; no per-row allocation | done |
| H-006 | P0 | Reproduce Poseidon relations and claims | H-004, F-006 | Honest and forged relation tests match current behavior | done |
| H-007 | P0 | Run real CPU and Metal proof equivalence | H-005, H-006 | Independent verification succeeds on both admitted backends | done |
| H-008 | P1 | Add source-to-materialization diagnostics | H-003, F-009 | All 426 columns trace to semantic source paths | done |
| H-009 | P2 | Prototype cost-aware materialization policy | H-007 | Separate manifest and cost report; no production activation | done |
| H-010 | P2 | Benchmark compatibility and proposed layouts | H-009 | Complete authenticated four-arm log-10/log-14 cohort under PERFORMANCE.md; no production/proof claim | done |

### H-010 completion evidence

The isolated harness and its admission prerequisites are complete:

- exact H-009 artifact, fixed-program, four-arm, proposal, and cut
  authentication;
- checked log-10/log-14 `STWAIRB\0` vectors and a byte-regenerated readable
  index, with log 18 generated only as a non-receiptable opt-in;
- one common retained CPU evaluator with prepared witness/direct capabilities
  and no per-row allocation;
- independent expected-output comparison, all 430 roots on every admitted row,
  and one-at-a-time mutations for all 426 materializations and fixed roles;
- regression-only candidate trace pins, explicit timer boundaries, normalized
  high-water RSS, strict child/report schemas, and serial rotated orchestration;
  and
- source/build isolation from production CPU/Metal executables and explicit
  negative proof, PCS, verifier, Metal-candidate, and promotion capabilities.

Clean implementation commit `82bf6b9cd5eb1ab48edd6fb7c0c88a3be687e8c6`
with tree `8cbb9300fa9b820baa079eeb94addf71db97f130` produced two
independently valid and complete default reports. The locally retained ignored
`v2` report is 337,144 bytes with SHA-256
`98abdf472818e21e43ff0e3cc3d509598558a6df6c1c215ea789a997fb5bc25d`;
`v3-confirm` is 337,146 bytes with SHA-256
`eabeba5d67b26574dbe4246f8924411fe7c1df252452d078688ae6a0bcb5682a`.
Each report records 112 fresh sample children with zero failures, retries, or
drops under the same executable and source closure. Candidate deltas remain
inside run-to-run noise, including q0/q100 log-14 witness directions that flip
between reports, so H-010 selects no layout. Proof, Metal-candidate, and
production claims remain false. Any future promotion still requires a separate
accepted decision and full proof-path evidence.

## Typed effects and opcode migration

| ID | Priority | Task | Depends | Acceptance | Status |
| --- | --- | --- | --- | --- | --- |
| E-001 | P0 | Implement program fetch and state consume/produce effects | F-006, A-008 | Current schemas/order reproduced | done |
| E-002 | P0 | Implement register read/write with strict subclocks | E-001 | Alias and historical self-loop negatives reject | done |
| E-003 | P0 | Implement memory read/write and range effects | E-002 | Load/store masks, gaps, and address bounds represented | done |
| E-004 | P0 | Author LUI in typed surface | E-001, A-010 | Full compatibility and proof gates exact | done |
| E-005 | P0 | Generate LUI witness in shadow mode | E-004, F-008 | Column equality across corpus | done |
| E-006 | P0 | Author ADDI | E-002, E-004 | x0, aliases, overflow, carries, Sail differential | done |
| E-007 | P0 | Generate ADDI witness in shadow mode | E-006 | Column/event equality and forged carry rejection | done |
| E-008 | P1 | Author signed-load pilot | E-003, E-007 | Sign hint, memory mask, and bound mutations reject | done |
| E-009 | P1 | Author JALR pilot | E-003, E-007 | Target, bit zero, range, state transition exact | done |
| E-010 | P0 | Define quotient/remainder hint recipes | F-008, E-003 | All RISC-V exceptional classes specified | done |
| E-011 | P0 | Author DIV-family pilot | E-010 | 292 operand-class corpus and adversarial tests pass | done |
| E-012 | P1 | Add generic direct-to-column witness executor | E-005, H-005 | Preplanned storage, bounded dispatch, deterministic errors | done |
| E-013 | P1 | Switch one family witness to generated authority | E-012 | Old writer test-only; full clean-tree gates green | done |
| E-014 | P1 | Migrate remaining families in reviewed groups | E-013 | Per-family checklist complete | done (17/17 production-typed) |
| E-015 | P1 | Retire redundant witness writers | E-014 | No production imports; retained history documented | done |
| E-016 | P2 | Evaluate generated concrete executor | E-014 | Sail/Spike differential and ADR; no authority change | queued |
| E-017 | P0 | Generate failure-atomic register/memory access transactions | E-014, A-013 | x0, aliases, clocks, gaps, masks, and misalignment resolve before typed-row publication with no hot-loop allocation | done |
| E-018 | P0 | Migrate LUI execution, witness, and production AIR to one typed authority | E-017, P-002 | Delete the LUI runner case and handwritten AIR authority after exact Sail/formal/proof/performance parity | done |
| E-019 | P0 | Migrate FENCE as the second end-to-end SSOT family | E-018 | Generated dispatch and empty-effect edge cases pass; replaced authorities deleted | done |
| E-020 | P1 | Migrate the remaining fifteen execution/AIR families | E-019 | Each family deletes its runner and handwritten AIR authorities under the complete per-family gate | done (15/15; 17/17 live) |
| E-021 | P1 | Generate family metadata and dispatch from the typed registry | E-018 | Compile-time exhaustive decode-to-family calls; unsupported opcodes fail closed; no runtime name lookup | done (17/17; 46 proof-bearing opcodes) |
| E-022 | P1 | Retire handwritten opcode composition machinery | E-020, E-021, A-014 | Claims, masks, geometry, offsets, adapters, and assembly derive from compiled manifests | done (one shared manifest authority assembles all 17 opcode and 11 infrastructure components for prover and verifier; O(1) offsets and failure-atomic drift rejection; 324/324 Debug and ReleaseFast) |

## Guest precompile

| ID | Priority | Task | Depends | Acceptance | Status |
| --- | --- | --- | --- | --- | --- |
| C-001 | P0 | Accept guest ABI ADR | H-007 | Explicit extension semantics and failure policy | done |
| C-002 | P0 | Accept guest relation/version ADR | C-001, F-006 | Domain separation and multiplicity policy fixed | done |
| C-003 | P0 | Implement owned typed call buffer | C-002 | Stable order, duplicates, empty case, allocation failure tests | done |
| C-004 | P0 | Implement runner/host invocation boundary | C-003 | Invalid calls reject before mutation; output corpus matches | done |
| C-005 | P0 | Add guest Poseidon component registry entry | C-003 | Stable kind/version and verifier construction | done |
| C-006 | P0 | Extend statement geometry and artifact identity | C-005 | Call count/columns/log size bound and malformed artifacts reject | done |
| C-007 | P0 | Generate guest precompile main trace | C-004, C-006 | Calls map exactly to active rows; padding inactive | done |
| C-008 | P0 | Generate shared-challenge relation interactions | C-007 | Source/supply sums close; omission/duplication fail | done |
| C-009 | P0 | Prove and independently verify one guest program | C-008 | CPU proof and new-process verifier green | done |
| C-010 | P1 | Add Metal component admission | C-009 | Authenticated AOT or reviewed generic path; no CPU fallback | done |
| C-011 | P0 | Add native-versus-precompile semantic corpus | C-009 | Same advertised outputs; extension labelled | done |
| C-012 | P1 | Add precompile mutation fleet | C-009 | Input, output, mode, multiplicity, padding, count forgeries reject | done |
| C-013 | P1 | Benchmark crossover and total work | C-011, C-012 | Complete report under PERFORMANCE.md | ready |

C-013's frozen CPU controller and independently recomputed lane reduction are
implemented and tested. The task remains `ready`, not `done`: the shared
checkout is not a clean immutable capture source, and the required secure CPU
cohort, Metal cohort, cross-lane evidence, and normative promotion receipt do
not yet exist. See the
[CPU capture readiness audit](notes/2026-08-12-c013-cpu-capture-readiness.md).

## Parallelism and recursion

| ID | Priority | Task | Depends | Acceptance | Status |
| --- | --- | --- | --- | --- | --- |
| R-001 | P1 | Model component build stages as bounded tasks | C-009 | Explicit dependencies, ownership, cancellation | done |
| R-002 | P1 | Parallelize independent main-trace construction | R-001 | Live final destinations; exact predecessor/`N=1/2/4` statement, claim, transcript, proof, cancellation, and resource evidence | done |
| R-003 | P1 | Parallelize independent interaction construction | R-002 | Shared challenges, allocation-free joined epoch, canonical claims, and exact full-proof parity | done |
| R-004 | P1 | Integrate with heterogeneous quotient scheduler | R-003 | No nested oversubscription; failure propagation | done |
| R-005 | P1 | Add component critical-path telemetry | R-004 | queue/run/wait/memory metrics in report | done (five non-overlapping witness-materialization regions, checked proving complement, exact verified-request partition, and owned task/resource profile pass a real independently verified proof in Debug and ReleaseFast) |
| R-006 | P1 | Thread-count and workload scaling study | R-005 | verified 1/N-worker sweep and resource disclosure | active (strict fresh-process plan/capture/bundle validator and 1,040-attempt per-lane schedule pass; capture-plan and paired-plan V3 bind and live-recompute P-003's CPU/Metal/joint 16/16 matrix, schema-9/23-site inventory, and versioned M7 geometry: balanced 8 calls, dominant 4096. Fsynced intent/prepared/commit, host-boundary, lane, and pair journals enforce no retry, guarded resume, and byte-idempotent finalization; a complete simulated 2,080-attempt crash/replay passes. Post-capture quieting retries fresh unchanged-threshold preflights for a bounded 15 minutes and preserves durable journals on timeout. The normative scaling receipt is absent/null. A clean reviewable commit, installed V4 CPU/Metal smoke, admitted preflight, and immutable 2,080-attempt paired capture remain. M6's balanced-4096 row is unchanged and remains open pending segmented/recursive proving) |
| R-007 | P0 | Specify and encode session-bound cross-proof relation summaries | C-012 | ADR accepted; fixed codec/digests and swapped/omitted/duplicate/cross-session negatives pass | active |
| R-011 | P0 | Select and bind the recursive field, hash, PCS, and verifier protocol | R-007 | Security review fixes leaf public inputs and recursive verifier statement | queued |
| R-012 | P0 | Express every recursion-local component in the typed compiler | R-011, A-013 | Verifier arithmetic, hash, wire, Merkle, and transcript components have no handwritten escape hatch | done as protocol substrate (36/36 universal AIR authority; complete 39-component SegmentV2 leaf outer proof independently verifies all 47 domains from verifier-owned capture. This implementation work completed ahead of R-011; R-011 remains the production protocol-selection and activation gate) |
| R-008 | P0 | Implement one core/precompile recursive leaf-pair prototype | R-007, R-011 | Native/in-circuit verifier parity; swapped/omitted/cross-transcript/session negatives reject | queued |
| R-009 | P1 | Implement the canonical two-to-one aggregation tree | R-008, R-012 | Final verifier binds every ordered leaf, relation summary, statement, and session | active as pre-activation substrate (the first real temporal node is complete ahead of R-008's production leaf-pair closure: two distinct independently verified SegmentV2 leaves feed exact rows 0--35, authenticated verifier-input and statement boundaries close globally, and the 94,740-byte ReleaseFast parent independently verifies with proof SHA `a43d756e…203b`. Coherently resealed mutations cover every row 20--35 and the pair/statement/context boundary; the lean path reproduces all identities with zero hot pair hashes/permutations. R-008/R-011 activation and multi-level tree construction remain before task completion; `temporal_parent_verified = true`) |
| R-010 | P1 | Measure recursion crossover | R-009 | Proof size, verifier, memory, total work, wall time, and security bits | queued |

### R-001 completion and R-002 production boundary

The exact-capacity scheduler, preallocated leased submission envelopes, joined
cancellation, deterministic failure selection, resource reservations,
coordinator-prepared composition, and explicit per-proof execution request now
reach the production CPU composition boundary. The specialized RISC-V backend
schedules admitted tile lanes and prepared fallbacks through the bounded graph.
Large prepared memory-hash, lookup-table, and opcode-lookup domains subdivide
into aligned row ranges under pool-exclusive leases. Closed prepared plans
enforce finite host budgets across coordinator heap plus reserved helper stacks
and submission envelopes.

The bounded graph also has an opt-in flat task capture. It reserves exact event
and component-work storage only after lease admission, gives each worker one
preassigned event slot, joins all work before canonical `TaskKey` publication,
and validates the published terminal counts against the scheduler's
cancellation/accounting handshake. Each event carries exact
ready-to-submission admission wait, submission-to-start queue wait, callback run
time, resource wait, completed rows or tiles, and the five declared memory
classes. The graph summary retains requested, admitted, and pool-capacity
widths, exact terminal and duplicate counts, graph-local elapsed and DAG
critical-path time, and declared peak-reserved bytes. It does not relabel that
graph-local interval as verified-request duration. Physical-worker peak and
busy time remain nullable when a `pool_exclusive` callback launches child work
that is not yet instrumented exactly.

R-001 is complete at the bounded scheduler/model boundary. A retained lease now
owns admitted worker capacity across all dependent waves, closes exactly once,
and cannot be reused after release. The pointer-free Tree-1 executor consumes
the complete seven-wave plan through fixed callbacks, validates every declared
range and destination ownership, preserves deterministic cancellation and
failure selection, and passes serial/one/two/four-worker structural
differentials in Debug, ReleaseSafe, and ReleaseFast.

R-002, R-003, and R-004 are complete at the production proof boundary. The
Tree-1 and Tree-2 epochs write live final destinations, and the same
proof-scoped pool continues through heterogeneous quotient composition and PCS
openings. The guarded `test-riscv-proof-pool-parity` target runs the real
predecessor/current `N = 1/2/4` proof differential plus stage-by-stage injected
failure and recovery. Its ReleaseFast result fixes a 56,385-byte proof,
SHA-256 `605bb8af62f3e4b1c1b59a6be7e2714e0c92f65ef0248d21b1c04c447a4c8f7b`,
transcript digest
`69d6160da376ceff44733dea25c0b8c5e05e4fbcd0bcb9fee27aeba5061018b3`,
and one draw across every admitted worker count. A minimum-two-test build guard
prevents this focused target from succeeding with a stale empty filter.

R-005 is complete at the report-level telemetry boundary:

- the opt-in proof-identity reporter establishes exact predecessor/current
  `N = 1` and current `N = 1/2/4` equality for two development-profile
  workloads, but the frozen corpus and full-security differential remain open;
- generic prepared-composition correctness covers `N = 1/2/4`, its exact flat
  profile covers `N = 1/4`, and its compatibility-contention test proves that a
  declined parallel lease publishes only the admitted serial retry while
  preserving request identity. The specialized RISC-V flat profile covers
  `N = 1/2/4` plus the same compatibility handshake;
- row sharding currently covers memory-hash, lookup-table, and opcode-lookup
  prepared domains, not every dominant component or prover stage;
- the pointer-free Tree-1 plan and executor cover exact columns, aligned
  opcode/Poseidon ranges, checked finite-resource classes, deterministic worker
  admission, and per-wave capacity bounds. Its callbacks now invoke production
  generators into committed final destinations, and the whole-proof gate pins
  the resulting statement, claims, transcript, and proof bytes;
- fused RISC-V pair lanes retain their semantic attribution and nested physical
  worker accounting in the same owned task profile;
- the profiled schema binds checked monotonic guest, exact five-region witness
  materialization, cryptographic-proving complement, and native-verification
  nanoseconds. Their checked sum is `verified_request_ns`; serialization and
  receipt rendering are explicitly outside the boundary;
- the focused product gate exercises the complete state machine, schema,
  report custody, disabled-path neutrality, and one real independently verified
  proof in Debug and ReleaseFast; and
- full-corpus fresh-process capture and the normative R-006 attempt bundle and
  validator-recomputed scaling receipt remain open;
- finite budgets fail closed for unprepared fallbacks and non-heap scratch or
  device-resident plans, so broader resource closure remains open.

## Cross-cutting validation and tooling

### AIR profiling and cost authority

| ID | Priority | Task | Depends | Acceptance | Status |
| --- | --- | --- | --- | --- | --- |
| P-001 | P0 | Add a deterministic static typed-AIR profile | A-003, A-004 | Versioned digest and JSON/TSV cover columns, DAG/CSE/closure, roots, effects, batches, degrees, and materialization facts | done |
| P-002 | P0 | Profile the complete native typed-family inventory | P-001, E-014 | Family-ordered report covers all 17 production witness families and cross-checks layout/batch authorities | done |
| P-003 | P1 | Join static AIR facts with runtime proof telemetry | P-002, R-005 | Stable records bind witness/prove/verify time, field/FFT work, memory, proof bytes, total work, and critical path | done (producer-exhaustive CPU/Metal/joint 16/16 closure over schema 9's 23 typed sites; canonical matrix SHA `b1eef5cc…24d1`, inventory SHA `13807efb…982f`; CPU authority/receipt `df914f…b14` / `9e99cc…f68`, shell receipt `864d55…46f`. The authenticated-AOT real-device Metal 3/3 gate independently verifies with 118 exports and exact-once producers but emitted no separate canonical IDs. R-006 separately owns installed-binary smoke and scaling capture) |
| P-004 | P1 | Enforce multidimensional performance regression budgets | P-003, R-006 | Frozen A/A-calibrated gates reject meaningful global regressions without promoting noisy local wins | queued |

| ID | Priority | Task | Depends | Acceptance |
| --- | --- | --- | --- | --- |
| V-001 | P0 | Wire every new test file into RISC-V inventory | Each code task | Inventory test and count floor updated deliberately |
| V-002 | P0 | Add golden manifest regeneration/check mode | F-005 | Check is fail-closed; regeneration explicit |
| V-003 | P0 | Add root-by-root production differential helper | A-007 | First mismatch names constraint and source path |
| V-004 | P0 | Add hint/column mutation generator | F-008, E-012 | One-at-a-time mutation report with attribution |
| V-005 | P0 | Bind formal regeneration to logical/layout identity | A-010 | Drift fails existing refinement workflow |
| V-006 | P1 | Add CPU/Metal canonical program identity receipt (done) | H-007 | Backend reports same logical/layout digest |
| V-007 | P1 | Add documentation link and task-state checker | M0 | Broken local links and multiple active tasks fail |
| V-008 | P1 | Add clean-tree milestone receipt (done) | M3 | Commit, tool versions, manifests, tests, and digests recorded |
| V-009 | P0 | Mint and replay the current clean immutable M3 receipt (ready) | V-008, E-021 | Frozen source and generated artifacts bind the green `21/21/70`, `17/17`, frontend, recursion, native-proof, CPU-integration, and final formal gates without inflating the claim boundary |

V-008 is complete only as historical evidence for its named detached snapshot;
its recorded red findings remain part of the audit trail. With the final formal
reseal green, V-009 supersedes it only for a future clean revision after the
new receipt is minted and replayed.
The receipt must preserve the historical `2/46` Level-1 pilot label and record
the complete 36/36-universal, 39-component SegmentV2 leaf proof separately from
the independently verified first temporal parent. It must explicitly retain
`temporal_parent_verified = true`, `whole_frontend_verified = false`, and
`proof_system_soundness = false`.

## Critical path

```text
F-001..F-005
      |
      +--> A-001..A-010 --> H-001..H-007 --> C-001..C-009 --> R-001..R-006
      |                         |
      +--> F-006..F-008 --> E-001..E-013
```

The Poseidon and opcode-effect tracks may proceed in parallel after the shared
IR and relation foundations are stable. Broad migration does not block the
first guest precompile.
