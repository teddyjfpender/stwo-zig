# Original felt-to-AIR scope

**Status:** normative delivery map
**Source:** user-supplied `idea.txt`, reviewed 2026-08-04 and 2026-08-11
**Last reconciled:** 2026-08-20

This file prevents milestone completion from narrowing the original proposal.
It translates every material capability in the source document, plus the
parallel-proof and two-to-one recursion goals discussed with Clement, into a
production exit. The implementation may arrive in independently reviewable
tranches, but the project is not complete until every row below is either
accepted or deliberately removed by an ADR.

`Complete` means the production path has independent correctness, soundness,
ownership, all-mode, and performance evidence. A validated shadow, test-only
adapter, authenticated plan, or native reference is useful substrate, not
production completion.

## Delivery map

| Capability from the proposal | Current state | Production exit |
| --- | --- | --- |
| Felt-valued single-assignment language | Production-live for all 17 opcode families; recursion AIR closure 36/36 (34 typed logical + 2 authenticated providers) | One typed definition is the production authority for constraints, relations, witness construction, formal export, and the selected concrete machine effects of every migrated component. |
| Maximum constraint degree as a compiler parameter | Core and function activation complete | The compiler owns degree propagation and deterministic inline/materialize choices for production components; every emitted direct and LogUp polynomial is revalidated against the bound. |
| Reuse-aware materialization | Experimental | A versioned cost policy accounts for commitment, FFT/FRI, composition, memory, and reuse; a candidate is activated only after verified end-to-end evidence, never from a local expression-count win. |
| Same program as witness generator | Partial | Every materialized value is filled directly into final preallocated storage from the authenticated program with no per-row allocation, string dispatch, or second handwritten formula. |
| Static loops, maps, folds, and compile-time selection | Core complete | Production Poseidon2 and every later component use the typed static surface; handwritten flattened round/intermediate source is retired after exact proof parity. |
| Functions and Cairo-style frames | Compiler frame plan and complete body lowering | The authenticated plan enforces declared-input visibility, topological write-once locals, exclusive hint ownership, deterministic relation returns, and frame-owned constraints/effects/hints/calls. No current production RISC-V component declares an owned relation-backed function, so activation remains a zero-byte transcript no-op until the first such component is authored. |
| Function activation through LogUp | Live compiler/prover/verifier lowering complete | Canonical callee-consume, caller-emit, and public-emit records, per-function challenge draws and ABI identities, verifier-recomputed public roots, exact multiplicity/provenance, degree certificates, and omission/duplication/collision/transcript negatives are one authenticated protocol. |
| External relation statements | Core complete; authoring integration partial | Opcode and recursion definitions author typed `emit`/`consume` statements for the actual zkVM relation registry, with compiler-owned role signs, ordinals, order, and batching. |
| Witness hints | Core complete | Every production hint has a closed recipe, explicit proof dependency, failure-atomic witness evaluation, and a mutation that independently causes verification failure. |
| Witness-side register/memory access resolution | Compiler complete; all 17 production families integrated | Generated transactions resolve reads, writes, previous clocks, aliases, x0, memory masks, and gap rows before publishing a typed row; the corresponding handwritten runner/access path is deleted. |
| One opcode function for execution, witness, and AIR | Implemented for all 17/17 families; current gates and final formal reseal green; clean receipt open | A family closes only after the typed program replaces its `runner/execute.zig` case, production `air/semantics` authority, witness recipe, relations, and formal/runtime export under Sail and malicious-proof gates. |
| Opcode dispatch generated from the typed registry | Complete for 17/17 families and 46 proof-bearing opcodes | Decode remains architectural; family metadata and calls into generated execution/witness/AIR backends are compile-time exhaustive and fail closed without runtime name lookup. |
| All opcode families migrated | Production execution/witness/AIR 17/17 | Execution and production AIR authority migrate family by family; test-only legacy oracles disappear when independent evidence no longer needs them. |
| Component-composition retirement | Complete for the 17 opcode and 11 infrastructure components | Claims, masks, geometry, component adapters, O(1) column offsets, prover/verifier placement, and assembly derive from one compiled manifest authority; width/order drift rejects before publication. |
| Compiler-owned masks and row windows | Correctness and production activation complete; paired global performance open | Typed shifted-column/window nodes carry ownership and boundary rules through degree analysis, allocation-free materialization, PCS mask emission, manifests, and cross-row forgery tests. Both live opcode adapters derive geometry from the same pinned row-window plan; the generated CPU composition path admits 17/17 pairs and preserves exact 51,581-byte proof and transcript identity in Debug and ReleaseFast with independent verification. |
| Compiler-selected lookup batching | Explicit authenticated CPU V2 production protocol; compatibility default, native Metal and normative performance open | A deterministic degree- and cost-constrained partition is recorded in protocol identity and drives interaction columns, claims, and verifier order. The real 17-family CPU path independently verifies, rejects reciprocal protocol replay, reduces Tree 2 from 688 to 616 columns and proof size from 51,863 to 50,256 bytes; singleton/pair differentials and denominator-collision tests pass. |
| AIR-generation profiler and cost model | Producer-exhaustive CPU/Metal/joint 16/16 closure over schema 9's 23 typed sites; normative scaling receipt absent | Stable static and runtime profiles expose columns, DAG/CSE/dead work, roots, batches, degrees, field/FFT/FRI/Merkle work, memory, proof bytes, total work, and critical path. Exact-once OODS and Blake2s PCS-shell receipts pass real CPU `N=1/2/4` and authenticated-AOT Metal proofs; coverage bits distinguish observed zero from unwired data. The canonical matrix/inventory are `b1eef5cc…24d1` / `13807efb…982f`; CPU authority/receipt are `df914f…b14` / `9e99cc…f68`, and the shell receipt is `864d55…46f`. The Metal gate emitted no separate canonical IDs. R-006 plan V2 binds and live-recomputes the matrix and inventory before capture. |
| Parallel core trace and precompile proving | Production proof pool, exact telemetry, and exhaustive work producers complete; normative scaling receipt absent | One bounded pool spans Tree 1, Tree 2, heterogeneous quotient composition, and PCS openings with ownership, cancellation, budgets, no nested oversubscription, exact predecessor/`N=1/2/4` proof identity, and staged recovery. The exact five-region verified-request partition and queue/run/wait/memory custody pass a real proof in Debug and ReleaseFast. R-006's matrix-bound V2 plan is complete, but installed V4 CPU/Metal smoke and the frozen fresh-process 1/2/4/max-worker scaling receipt remain; the current host preflight fails only its median-idle threshold. |
| Every recursion-local component uses the typed compiler | AIR/component authority closed 36/36; the append-only SegmentV2 cohort proves all 36 universal rows plus two boundary sources and one committed verifier-input provider | Its verifier arithmetic, hash, wire, transcript, and Merkle components must use the typed language with no handwritten component escape hatch. The complete 39-component leaf proof independently verifies all 47 relation domains from verifier-owned capture, with exact 102,099-tuple closure and no unmatched tuple. This closes the recursive leaf AIR/component authority, not the temporal parent proof. |
| Session-bound two-to-one recursion | First real canonical parent complete and publication-hardened; multi-level tree and crossover receipt open | Two distinct native SegmentV2 proofs independently verify before capture. Append-only temporal V3 carries their verifier-owned authority through exact rows 0--35, closes the statement/verifier-input and all global relation boundaries, produces a 94,740-byte parent with proof SHA `a43d756e…203b`, and independently verifies it. Coherently resealed mutations cover every suffix row/provider plus pair, statement, ordering, and context authority. The prepared authenticated pair path performs zero hot Poseidon hashes/permutations after cold preparation. Multi-level aggregation and the frozen security/size/time/memory/total-work crossover receipt remain production exits. |

## Current release-evidence boundary

The mutable checkout is green at the present M3 gate set: package workspace
`21/21` with 70 dependency edges, compatibility manifests `17/17`, frontend
Debug 2,149 passes plus one intentional skip, recursion `583/583` in Debug,
ReleaseSafe, and ReleaseFast, the relocated native recursion proof exact at
5,184 bytes with identical transcript output in all three modes, and RISC-V CPU
integration `17/17` in ReleaseFast. The final formal reseal is green `59/59`,
with formal digest
`375b77cc4c11c2af324b3d66a989fd1e69a58c809dbb68e444d6b6a25fdeba86`
and source closure
`c9bc6c362663ce20aac44b9a004a4d86e71f9888bf2a809512116733db0a8bb2`.

This makes M3 ready for a clean immutable receipt. It does not itself provide
that receipt: no clean top-level capture exists for the current tree, and the
historical V-008 receipt remains an immutable record of its earlier red
snapshot. The historical Level-1 LUI/ADDI pilot remains `2/46`. Recursion now
has a complete independently verified SegmentV2 leaf outer proof covering all
36 universal rows plus its three append-only components and all 47 relation
domains. The first real temporal `2 -> 1` parent now independently verifies;
multi-level aggregation remains open. Accordingly
`temporal_parent_verified = true`, `whole_frontend_verified = false`, and
`proof_system_soundness = false` remain part of the normative claim.
The parent receipt pins 36 rows and 94,740 bytes with proof identity
`a43d756e…203b`; rows 18--19 come from the real binary pair computation and
rows 20--35 retain authenticated suffix/provider authority. Publication,
cohort, audit, and closure identities are preserved in the canonical artifact,
and the prepared pair path reports zero hot Poseidon permutations.

## Dependency order

1. Accept the production Tree-1 and Tree-2 bounded execution paths without
   changing proof meaning.
2. Establish profiler facts and the exact execution/witness/AIR compiler
   boundary before choosing optimizations.
3. Migrate LUI end to end as the first true single-source family, then FENCE,
   then expand by family while deleting replaced authorities.
4. Add compiler-owned frame/call relations, access transactions, masks, and
   lookup batching; use them to generate composition metadata.
5. Lift core and precompile work into one bounded proving graph and close its
   scaling/resource evidence.
6. Freeze the leaf-summary protocol, implement recursive verification and the
   two-to-one node, then migrate every recursion-local component to the same
   typed compiler.

These steps are ordered by proof authority, not by visual completeness. In
particular, recursion must not fossilize a second handwritten component system,
and layout optimization must not precede a profiler capable of measuring its
global proof cost.

## Non-negotiable acceptance properties

- Sail and protocol verification remain independent oracles; shared generation
  is not evidence against correlated bugs.
- Compatibility changes preserve exact statement, claims, transcript draw
  order, serialized proof bytes, and independent verification unless an ADR
  explicitly versions the protocol.
- Hot row loops are allocation-free, branch-bounded, and free of dynamic
  strings, hash maps, and indirect semantic dispatch.
- Parallel completion order never determines protocol order. Publication is a
  deterministic joined epoch with one owner per destination.
- Every optimization reports wall time, total work, peak resident/device
  memory, proof size, and verifier cost. A local AIR/DAG reduction is not called
  a win when it regresses the whole proof.
- Cancellation and allocation failure are transactional: no partially
  published columns, claims, counters, summaries, or commitments survive.
- Stable manifests and digests bind semantic programs, physical layouts,
  materialization, masks, relation order/batching, witness recipes, and public
  recursion/session data at their appropriate protocol boundaries.

## Ledger rule

`TASKS.md` owns executable task state and `PROGRESS.md` owns chronological
evidence. Both must link back to this map when a task changes one of these
capabilities. Milestone M8 closes opcode execution, witness, AIR, and generated
dispatch SSOT for all 17 families; it does not close handwritten component
composition, whole-frontend verification, proof-system soundness, or the full
recursive proof.
