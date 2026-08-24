# Progress ledger

**Status date:** 2026-08-20
**Branch:** `feat/typed-air-precompiles`
**Current milestones:** M7 — parallel proving; M9 — recursive aggregation
**Active tasks:** A-013 — paired global performance only; A-014 — native
Metal/no-fallback and normative performance evidence; R-006 — installed V4
smoke and scaling evidence; R-009/R-010 — multi-level aggregation and
crossover evidence
**Next ready task:** freeze a reviewable commit, build and smoke the installed
V4 CPU/Metal candidates, capture the 1/2/4/max-worker scaling cohort on an
admitted quiet host, then compare the independently verified temporal parent
against the old-system ETHProof CSP benchmark
**Current acceptance gate:** exact statement/claim/transcript/proof identity,
independent verification, fail-closed protocol identities, ownership and
allocation safety, plus whole-proof performance/resource evidence
**Known formal state:** the final reseal is green `59/59`, with formal digest
`375b77cc4c11c2af324b3d66a989fd1e69a58c809dbb68e444d6b6a25fdeba86`
and source closure
`c9bc6c362663ce20aac44b9a004a4d86e71f9888bf2a809512116733db0a8bb2`.
No clean top-level receipt has yet been minted for this checkout, and the
formal result does not set `whole_frontend_verified` or
`proof_system_soundness` true

## Dashboard

| Milestone | State | Evidence |
| --- | --- | --- |
| M0 — engineering dossier | complete | This directory and initial ADRs |
| M1 — validated logical IR | complete | F-001 through F-015 complete and green; live activation lowering carries compiler-owned degree/provenance and verifier-owned public-root claims, while programs with no owned relation-backed function remain a zero-cost compatibility no-op |
| M2 — shadow compiler | complete | A-001 through A-005 complete and green |
| M3 — compatibility lowering | ready | Current checkout gates are green and ready for a clean immutable receipt. [V-008](receipts/m3-compatibility-v1.json) remains the immutable historical red snapshot; it is not the receipt for this tree. This milestone does not claim a full proof or whole-frontend verification |
| M4 — Poseidon compiler pilot | complete | H-001 through H-010 and V-006 complete; no layout selected |
| M5 — effect and witness pilot | ready | E-001 through E-015 complete. All seventeen opcode families use authenticated typed production witnesses with exact legacy proof parity and per-family non-regression gates. The frozen M5 performance receipt remains open |
| M6 — guest precompile | ready | C-001 through C-012 complete: one CPU proof closes caller/provider components in the same STARK and verifies in a fresh process; the semantic pair and mutation fleet pass; the authenticated-AOT Metal product route proves on-device and verifies device-independently with zero backend CPU fallback. C-013 now has a fail-closed CPU controller and reducer; its clean secure CPU/Metal crossover receipt remains open |
| M7 — parallel proving | active | R-002/R-003/R-004 are closed: production Tree-1 and Tree-2 construction, heterogeneous quotient composition, and PCS openings share one bounded proof pool and preserve exact predecessor/`N=1/2/4` proof identity with staged failure recovery. R-005 is closed. P-003 is producer-exhaustive at CPU/Metal/joint 16/16 across schema-9's 23 typed sites, with real CPU `N=1/2/4` and authenticated-AOT Metal proofs. R-006 plan V4 binds that matrix and inventory plus versioned per-workload M7 geometry: balanced at 8 calls and dominant at 4096. Power source is machine-observed, disclosure-bound, and stable during a capture; Battery Power is admissible when Low Power Mode is off and the unchanged quiet/thermal gates pass. A clean installed V4 smoke and immutable CPU/Metal scaling capture remain open |
| M8 — broad migration | complete | All 17 family witness writers and all 17 execution/AIR families are production-typed. All 46 proof-bearing opcodes dispatch through the typed registry; one shared manifest now assembles all 17 opcode and 11 infrastructure components for both prover and verifier. Exact generated-versus-legacy proof/transcript A/B passes for every family with one draw, fail-closed legacy execution passes 17/17, and fresh formal extraction validates all 17 families. The final formal reseal is green `59/59`; a clean top-level receipt remains open |
| M9 — recursive aggregation | active | Universal AIR authority is closed 36/36 and the capture-backed SegmentV2 leaf proves the complete append-only 39-component cohort. The temporal source consumes two distinct, independently verified native SegmentV2 proofs, carries verifier-owned authority through rows 0--35, and closes the exact global relation boundary. The frozen ReleaseFast test executes coherent context plus every-row-20--35 authority mutations before independently accepting the 94,740-byte parent; the lean path measured 6.778 s proving / 6.209 s verification and reproduced proof SHA `a43d756e…203b`. The prepared pair path performs zero hot Poseidon permutations. Multi-level aggregation, R-010 crossover evidence, whole-frontend verification, and proof-system soundness remain open. `temporal_parent_verified = true`, `whole_frontend_verified = false`, and `proof_system_soundness = false` |

## Current release-candidate gates

These results describe the current shared checkout. They are green readiness
evidence, not an immutable release receipt:

| Gate | Current result |
| --- | --- |
| Package workspace | `21/21` packages and 70 dependency edges pass |
| M3 compatibility manifests | `17/17` regenerate and compare exactly |
| A-013 generated composition | Separate reference/generated proofs admit 17/17 generated pairs with exact 51,581-byte proof and terminal-transcript parity in Debug and ReleaseFast; both independently verify; V1 Tree 2 remains 688 columns |
| A-014 selected lookup V2 | Real 17-family CPU proofs independently verify and reject reciprocal protocol replay; Tree 2 is 688 -> 616 columns (-10.47% total, -11.61% opcode) and proof size is 51,863 -> 50,256 bytes (-3.10%); native Metal/no-fallback remains open |
| RISC-V frontend Debug | 2,149 pass; one intentional skip |
| Recursion AIR | `583/583` pass in Debug, ReleaseSafe, and ReleaseFast |
| Relocated native recursion proof | CPU-integration-owned gate passes in all three modes with exact 5,184-byte proof estimate and identical transcript |
| Active captured-leaf outer proof | Contiguous rows 18--34 prove and independently verify; frozen V1 is 66,308 bytes; 18/36 honest proof union including row 0; five mutations reject |
| SegmentV2 complete leaf outer proof | All 39 components and 47 relation domains prove and independently verify from verifier-owned capture; 91,722 canonical bytes; one-worker ReleaseFast development observation 1.155 s prove / 0.831 s verify; composition differential 39/39 |
| P-003 exact-work closure | CPU/Metal/joint `16/16`, schema 9 / 23 typed sites; matrix SHA `b1eef5cc…24d1`, inventory SHA `13807efb…982f`; real CPU `N=1/2/4` and real-device Metal proofs independently verify with exact-once OODS and PCS-shell receipts. CPU authority/receipt are `df914f…b14` / `9e99cc…f68`; shell receipt is `864d55…46f`. The Metal gate emitted no separate canonical identity |
| Temporal `2 -> 1` parent | Current-tree ReleaseFast mutation and lean gates independently verify the same 94,740-byte proof; proof SHA `a43d756e…203b`; rows 20--35 and coherent context mutations reject; `pair_poseidon=0` |
| RISC-V CPU integration | `17/17` pass in ReleaseFast |
| Formal | Final reseal green `59/59`; digest `375b77cc4c11c2af324b3d66a989fd1e69a58c809dbb68e444d6b6a25fdeba86`; source closure `c9bc6c362663ce20aac44b9a004a4d86e71f9888bf2a809512116733db0a8bb2` |
| Immutable promotion receipt | Open; no clean top-level receipt exists for this checkout |

The current M3 gates are therefore green and the milestone is ready for a
clean immutable capture. SegmentV2 supplies the complete recursive leaf and
the temporal V3 path now proves and independently verifies the first canonical
ordered `2 -> 1` parent. This is not yet a multi-level aggregation tree, an
accepted-proof-to-whole-trace theorem, or a proof-system soundness result. The
historical Level-1 LUI/ADDI pilot remains `2/46`; SegmentV2 leaf proof coverage
is 36/36 universal rows plus its three append-only components.
`temporal_parent_verified = true`, `whole_frontend_verified = false`, and
`proof_system_soundness = false`.

## Completed

### 2026-08-20 — producer-exhaustive profiling and the hardened real parent close

P-003 now closes all sixteen reviewed prover-work families on CPU and Metal.
The deletion-resistant inventory is schema 9 with 23 ordered sites; the matrix
recomputes to 16 complete / 0 partial / 0 absent for CPU, Metal, and joint
coverage. Real CPU `N=1/2/4` proofs publish byte-identical exact-once OODS and
PCS-shell receipts and independently verify. The authenticated-AOT Metal gate
accepts 118 exact exports, exercises the resident/fused FRI path, publishes the
same required sites exactly once, and independently verifies. The canonical
matrix SHA is `b1eef5ccf8405de9373c11b8fe9bd505a331add0601ab1904a1b038df0ee24d1`;
the inventory SHA is
`13807efba664c2abc49325a80d8bc67c15896e7250ea48416e0d58e0f029982f`.
The CPU work authority and receipt SHA-256 values are respectively
`df914f214597393737a7795fc988680df17ca0e5ba09d9d577930260cb703b14`
and `9e99ccedbe8302548ef7c95babd445b48f270b355a26090badcec64388350f68`;
the Blake2s shell receipt is
`864d550670c284c36dd79fc8521852504b2dd6221410d47cfffceeb56473b46f`.
The real-device Metal gate did not print a separate proof, transcript, work,
or shell identity, so none is inferred from the CPU values. Its evidence is
the green 3/3 product gate, 118 authenticated AOT exports with AOT/JIT parity,
exact-once producer completion, independent verification, 305.58 s wall time,
and 4,967,989,248-byte maximum RSS.
Ordinary row/SIMD/Metal kernels contain no profiler callback or branch; bounded
cold null/root checks remain, so no measured zero-overhead claim is made.

The R-006 plan schema is now V4 and fail-closed over that exact global closure
and a versioned generated-input geometry. Plan build, load, and capture
recompute the matrix and inventory authority, and paired plans require
identical CPU/Metal closure. M7 freezes `balanced_core_and_poseidon2` at 8 calls
and `poseidon2_dominant` at 4096. The exact balanced recurrence
`S(n) = 58,018n + 40` yields 464,184 retired guest instructions at 8 calls:
8 CUSTOM instructions and 464,176 core rows. The exact dominant-4096 execution
count remains pending the clean smoke. V4 records the machine-observed power
source and requires it to remain stable, but does not privilege AC over Battery
Power. Low Power Mode off, load, idle, and thermal thresholds remain blocking.
A plan-bound post-capture phase retries fresh host samples every 30 seconds for
at most 15 minutes without weakening any of those thresholds. Attempt
intent/preparation/commit,
per-invocation host boundaries, and lane/pair publication are fsynced and
independently replayed; an unresolved launch intent fails closed rather than
retrying, while a fully durable prefix finalizes byte-idempotently without a
new host sample. Timeout preserves the durable journals for resume. The
74-test R-006 suite and a complete simulated 2,080-attempt crash/replay pass.
Installed V4 smoke and the immutable
2,080-attempt scaling receipt remain open.

This M7 geometry does not revise M6. Its frozen common
`0/1/8/64/512/4096` corpus remains unchanged. Balanced has one-call total
`S(1) = 58,058` and recurrence delta 58,018, so `S(4096) = 237,641,768`
exceeds the current one-shot `2^24` AIR limit. That M6 row has no completion
claim and remains blocked on segmented/recursive proving.

The temporal parent publication boundary is also hardened. After native proof
verification, one complete verifier replay reconstructs every row, both public
boundaries, provider authority, and closure before an opaque stack-scoped
success capability can be minted. Coherently resealed mutations cover every
row 20--34, row 35's separate provider, pair context, statement context, and
child ordering. The ReleaseFast mutation gate and lean runner accept the same
94,740-byte proof and five identities. The proof SHA is
`a43d756e1b1832105922579ccef1df55b73e9cd861c8e9dfcf7ea87845b7203b`;
the lean development observation was 6.778 s prove / 6.209 s verify with zero
hot pair-authentication Poseidon permutations. Multi-level recursion and
normative performance receipts remain explicitly open.

- Closed the two remaining single-source boundaries in parallel. Temporal
  parent rows 0--9 now come from one exact `RecordingChannel` replay:
  binary control, sponge-call/provider emission, call binding, digest-state
  transitions, versioned payload classification, checked PCS-PoW frames, and
  semantically annotated composition/OODS/DEEP/FRI/query draws retain compact
  operation/frame metadata once and write typed SoA columns allocation-free
  and fail-atomically. The versioned packed-QM31 row-8 authority represents
  both challenges without changing frozen V2, and the honest typed mask is
  now exactly `0x3ff`. In the execution frontend, a pointer-free
  zero-allocation opcode-composition manifest now derives exact geometry,
  claim order, semantic/lookup masks, trace widths, maximum width, and witness
  receipt order for all 17 typed authorities. One shared authority now
  assembles those 17 opcode and all 11 infrastructure components for both
  prover and verifier with O(1) offsets and fail-atomic drift rejection.
  Debug and ReleaseFast pass 324/324, maximum-width cold allocation counts are
  unchanged, and the semantic/row-window performance gates are green.
- Repaired the M7 proof-pool development gate. Its pinned filter still named
  the retired structural Tree-1 test and could therefore exit green after
  selecting no named test. Both compatibility and the new explicit
  `test-riscv-proof-pool-parity` target now select the real predecessor versus
  `N=1/2/4` full-proof identity and failure-recovery tests, covering Tree 1,
  Tree 2, quotient composition, PCS openings, independent verification, and
  scoped-pool unwind. A minimum-two-test build guard makes future stale pinned
  filters fail closed. The real ReleaseFast gate is green with a 56,385-byte
  proof, SHA-256
  `605bb8af62f3e4b1c1b59a6be7e2714e0c92f65ef0248d21b1c04c447a4c8f7b`,
  transcript digest
  `69d6160da376ceff44733dea25c0b8c5e05e4fbcd0bcb9fee27aeba5061018b3`,
  and one draw for every worker count. This closes R-002, R-003, and R-004;
  R-006 remains the M7 scaling and promotion-evidence boundary.
- Added the proof-kind-aware V3 heterogeneous graph-construction substrate.
  One max-sized sampled-value ABI is derived from separate verifier-owned
  SegmentV2 and universal capture layouts; the exact 39-row Segment program
  and independently initialized 36-row binary/empty programs replay through
  one private transaction with separate quotient-denominator caches, fixed
  41-claim policy constraints, parent/child selector equations, and global
  LogUp closure. Binary verifier custody now has a pointer-free V3 sidecar that
  binds every dynamic capture field, statement/claim/relation data, provider
  partials, manifest, and selected program descriptor, and its allocation-free
  recorder handoff is green. Production `CircuitAuthorityV3` minting remains
  deliberately unavailable until a real canonical empty cohort joins the
  already-real Segment and binary lanes in the same graph.
- Crossed two downstream recursion handoffs against one real, successfully
  verified SegmentV2 artifact. `TemporalChildTranscriptReplayV2` reconstructs
  Tree 0/1, the exact source-specific authority prefix, all 94 relation draws,
  39 claims, the public-wire boundary, Tree 2/composition, PCS/FRI/PoW, and
  every query through the verifier-published transcript identity; prefix and
  terminal-state mutations reject. `SegmentV2RecorderBridgeV3` independently
  joins the exact 39+2 claim profile to the V3 descriptor, derives its sampled
  layout from the capture, and retains the 41 claims, 47 relations,
  composition randomness, and OODS input for an allocation-free 39-row
  symbolic recorder handoff. The combined real 39-row/47-domain proof gate is
  green. At this earlier checkpoint temporal rows 0--9 still needed their
  typed parent AIR, and the V3 binary/empty programs still needed one shared
  heterogeneous graph authority; the later temporal-parent entry below
  supersedes the first of those two limitations.
- Extended the verifier-minted SegmentV2 recursive witness with the exact
  source-specific transcript prefix required to rebuild temporal rows 0--9:
  non-core/core authority identities, core layout and call-buffer identities,
  exact core call count, and the relation-dependent public-wire boundary. The
  pointer-free schema is independently sealed, linked into the witness and
  publication identities, and covered by version, padding, zero-identity,
  count-bound, canonicity, field, and identity mutations. The ordinary
  temporal-child harness now has its complete prover imports and passes as a
  focused ReleaseFast gate. A real SegmentV2 prove/verify/publication run with
  this schema remained green at 39 components and 47 domains, producing
  91,722 canonical bytes in 1.486 s proving, 0.931 s verification, and 3.76 ms
  publication on the development host. These are engineering observations,
  not a normative performance receipt.
- Closed the native temporal V2 prepared-authentication optimization with
  executed-path evidence. Cold preparation now executes 13 hashes / 281
  scalar Poseidon permutations versus 499 in the historical duplicate call
  tree, eliminating 218 permutations (43.7%). A 4,096-iteration successful
  prepared loop plus a mutation rejection executes zero hashes and zero
  permutations. One ReleaseFast ABBA observation measured 170,764 ns for the
  cold convenience path and 764 ns for prepared-hot authentication. The
  legacy V1 authority remains a distinct 94/55/38-permutation path, and none
  of these native measurements claim a temporal parent proof speedup.
- Closed the complete capture-backed SegmentV2 recursive leaf transaction.
  The independently reconstructed prover and verifier cohorts bind all 39
  component claims and all 47 relation domains, including the two V2 boundary
  sources and row 38's committed verifier-input provider. Exact tuple closure
  contains 102,099 contributions and no unmatched tuple. The real one-worker
  ReleaseFast gate reports 91,722 canonical proof bytes, 1.155 s proving, and
  0.831 s verification; these are development observations, not a normative
  performance receipt. The composition differential agrees for all 39
  components. Its diagnosis first isolated row 38 and then alpha-zero isolated
  its final LogUp constraint: main/preprocessed values had been copied in
  logical order while Tree 2 was already in circle-domain commitment order.
  Tree 0/1 now scatter exactly once through `committedRow`; Tree 2 remains an
  exact copy, with a focused order regression test. The resulting publication
  was ready as a temporal child. At that checkpoint no parent proof existed;
  the independently verified parent recorded later in this 2026-08-20 entry
  supersedes that historical boundary.
- Closed F-015 with opt-in, sealed per-function ownership of constraints,
  effects, hints, and calls. Owned bodies select semantic identity v11 and
  manifest v13 while every legacy identity and manifest remains byte-stable.
  Frame plans bind exact owned record ranges and body-only dependencies;
  `compileOwnedBody` expands all inline calls, instantiates direct constraints
  per invocation, and never lowers an unsupported proof-aware value into an
  unconstrained committed cell. Prepared execution allocates nothing and
  checks every constraint before publishing outputs. The new ownership suite,
  legacy lowering suite, function-frame suite, and full frontend package pass
  independently in Debug and ReleaseFast.
- Added row 18's production VM AIR-composition input to the same active outer
  proof as rows 19--34. Its prepared graph is derived from the exact native VM
  component evaluation, validates all 19,352 graph nodes and 4,589 input
  bindings allocation-free, and binds 4,805 scheduled input rows into the
  shared arithmetic wire closure. The resulting 17-component proof commits
  347 preprocessing, 760 main, and 276 interaction columns, evaluates 862
  constraints, and closes 52,303 Poseidon2 calls. The frozen 2x/193 proof has
  a 66,308-byte estimate, proves in 30.954 s and independently verifies in
  10.779 s with eight workers; all five mutations reject. Retaining one small
  authenticated binary-mode capacity anchor while removing four redundant
  inactive child graphs reduced proof time by 32.5%, assembly by 31.1%, the
  STARK body by 45.8%, and verification by 31.0% against the first sound row-18
  run. These are single-run engineering measurements, not a normative M9
  benchmark receipt.
- Added row 19's verifier-owned AIR-composition control slice to the outer
  proof, making rows 19--34 contiguous and raising the honest union with row 0
  to 17/36. The component has zero main columns: its nine fixed schedule
  columns are rebuilt from authenticated VM/recursion plans, and its claimed
  sum is recomputed independently before the verifier consumes proof bytes.
  Frozen V1 proves at a 66,360-byte estimate in 55.499 s and verifies in
  18.161 s; measured 4x/97 proves at 64,760 bytes in 28.137 s and verifies in
  9.251 s. A dedicated claimed-sum forgery joins the existing mutation fleet,
  which now rejects 4/4 outer mutations failure-atomically. The arithmetic
  graph and its active row counts are unchanged, and the timing delta is
  favorable within run noise rather than evidence of a speedup.
- Added row 24's exact PCS/DEEP verifier circuit to the same captured-leaf
  outer proof, making rows 20--34 contiguous. The 15-component proof commits
  307 preprocessing, 758 main, and 252 interaction columns and evaluates 848
  constraints. Frozen V1 (2x/193) lowers a 764,768-node PCS graph into
  540,626 multiply, 16,021 inverse, and 470,147 linear active rows; its
  64,476-byte proof estimate independently verifies in 57.974 s with four
  workers, and all three mutations reject. The measured 4x/97 candidate
  independently verifies at 62,908 bytes in 28.766 s. Its 26,675 Poseidon2
  requests close exactly against the sole row-34 provider. Together with the
  separate row-0 gate, honest real-proof coverage is now 16/36.
- Preserved the local query-bit, position, route, and active-row constraints
  after profiling an apparently faster variant. Those constraints cannot be
  delegated to lookup cancellation until the full outer proves the relevant
  global relation claims. The accepted PCS optimization instead uses exact
  batch factorization, denominator-coefficient caching, and constant folding.
  Against the first sound row-24 V1 run it reduces proof time by 17.4%,
  assembly by 20.0%, verification by 25.3%, and proof estimate by 3.3%, while
  preserving proof geometry, all local constraints, and mutation outcomes.
- The captured proof values remain verifier-owned: trace siblings, query
  coordinates, column logs, composition randomness, OODS randomness, and FRI
  randomness all come from the transactionally successful native verifier
  capture. Exact local wire and Poseidon request/provider claims cancel before
  proof assembly; full cross-domain global cancellation remains a completion
  gate for the 36-row proof.
- Removed an accidental quadratic recursive-assembly path. Rows 23 and 25--28
  previously rebuilt stateful Merkle witnesses and SHA-256-authenticated their
  complete preprocessing schedule once per interaction row. Interaction rows
  are now captured directly from the exact logical Tree-1 columns before those
  columns move into PCS ownership, eliminating both redundant computation and
  a second witness implementation. On the same 4x/97 ReleaseSafe leaf, the
  verified outer prove fell from 650.480 s to 14.086 s at one worker (46.2x),
  and to 12.608 s at four workers (51.6x versus the predecessor). Assembly fell
  from 647.176 s to 10.819 s at one worker (59.8x); four workers additionally
  reduced the STARK body from 3.261 s to 1.577 s. Geometry, constraints, proof
  estimate, verifier result, provider-call count, transcript draws, and all
  three mutations stayed fixed. These are single-run engineering measurements,
  not a normative M9 benchmark receipt.
- Promoted the typed Poseidon2 proof authority into a production module and
  installed it as the sole row-34 provider. Its identity-gated specialized
  writer remains byte-exact with the typed interpreter, retains the 16 output
  words needed by Tree 2, and prevents interaction generation from replaying
  26,675 scalar permutations. The outer assembly locally audits exact
  `poseidon2_io` cancellation; the verifier binds the provider claims and AIR.
- Relocated ownership of the rows-29/33 real native PCS/FRI proof gate from the
  frontend package to the RISC-V CPU integration package, where the concrete
  CPU backend and prover engine belong. The frontend retains the backend-free
  manifest, adapter, witness, relation, and verifier construction authority.
  The integration gate proves and independently verifies in Debug,
  ReleaseSafe, and ReleaseFast; all modes report the exact 5,184-byte estimate
  and the same transcript. ReleaseFast integration closes `17/17`. This raises
  no recursion coverage count at that checkpoint: rows 0, 29, and 33 remained
  the same `3/36` proof-bearing rows before the later captured-leaf outer proof.
- Landed the A2/A3 authenticated pair-node shadow substrate without promoting
  R-009. Its fixed 752-byte canonical record binds ordered core-request and
  Poseidon-provider claims to exact expected child-verifier outputs and a
  verifier-rederived session, challenge, full authority context, public-call
  commitment, event count, power-of-two session leaf count, and aggregator VK.
  Root authentication pins the injected VK and returns a distinct authorized
  type; checked first-layer folding requires exact relation closure and rejects
  count padding above `kappa <= 1024`. Versioned identity domains and separate
  statement/proof/transcript/summary folds and node identity are pinned; the
  record hash is diagnostic rather than part of the mandatory recursive node
  path. The allocation-free codec is alias-safe and failure-atomic. After
  protocol audit and expanded authority/cardinality negatives, the current
  focused build passes 259 tests with one intentional environment-gated
  benchmark skip in Debug, ReleaseSafe, and ReleaseFast; its directly declared
  R-009 surface passes 18/18 non-benchmark tests. The module cannot establish
  the provenance of caller-supplied verifier results, inspect child proof
  bytes, execute the outer AIR, or verify/produce a parent proof, so R-009 and
  the temporal parent remain active. The historical 229-permutation audit
  maps to 94 through the compatibility API and 55 with suite preparation. A
  by-value prepared authority context moves another exact 17 permutations to
  the cold path, leaving 38 on repeated hot authentication. Golden outputs,
  independent mutation rejection, and the zero-allocation ledger are pinned;
  no 55-to-38 wall-time speedup is claimed pending quiet AC evidence. This
  closes the known duplicate-validation optimization without promoting the
  shadow to recursive-proof evidence.
- Closed the universal recursion AIR roster at 36/36 without duplicating
  shared primitive equations: 34 exact typed-logical rows use one generic
  adapter, and authenticated native providers own Poseidon2 and the fixed
  `(8, 8)` range table. Rows 1, 13, and 14 now carry exact Stark-V source,
  semantic, witness-binding, schedule, cancellation, allocation, alias, and
  adversarial evidence. A single allocation-free manifest fixes every row,
  log size, column offset, claimed-sum index, protocol degree, and semantic
  identity in roster order. The integrated core and aggregate recursion gates
  pass in Debug, ReleaseSafe, and ReleaseFast. At that checkpoint this closed
  AIR/component authority, not the then-open outer proof or recursive `2 -> 1`
  node; the complete SegmentV2 leaf and first parent are recorded above.
- Added a non-promotional, allocation-free FRI profile frontier. It preserves
  V1's exact 209-bit configured query-plus-PoW ledger while exposing the
  blowup/query trade from `(1,193)` through `(6,33)` with fixed-schedule upper
  bounds for trace paths, FRI authentication digests, fold values, and domain
  expansion. Protocol V1 remains unchanged pending real proof measurements
  and security review.
- Admitted universal recursion rows 3 (`transcript_state`) and 5
  (`transcript_payload`) through the same compiler-owned generic adapter,
  moving the exact typed-logical and adapter closure to 31/36. Row-3
  preprocessing is derived from authenticated row-2 call
  schedules; row-2 frame outputs/words, internal digest-state multiplicities,
  and row-8 draw consumers cancel exactly. Row 5 binds every fixed protocol
  and PCS constant plus indexed statement/proof-word ownership to row-4 word
  events. Each owned cold snapshot uses one allocation, all hot writers are
  failure-atomic and allocation-free, and the integrated core passes 351/351
  in Debug, ReleaseSafe, and ReleaseFast.
- Removed an aggregate semantic-evaluator Debug stack regression without
  widening the reviewed 128 KiB worker-stack envelope. Exhaustive fixed-family
  direct dispatch now reaches each typed recipe without materializing the
  aggregate switch frame; the focused semantic-component gate passes 200/200
  in all three modes and preserves independent reference equality.
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
- Completed F-013: `function_frames.zig` compiles the global logical DAG into
  Cairo-style per-function frames. It rejects transitive undeclared-input
  reads, duplicate arguments, cross-frame hint ownership, hinted/non-field
  relation returns, and malformed activation geometry. Canonical write-once
  locals, exact `(args..., rets...)` tuples, per-function ABI digests, and
  callee/caller/public consume/emit events are authenticated by a pinned plan
  digest. The owned validator allocates nothing, strong validation regenerates
  from the full arena, allocation failures are exhaustive, and all 7 focused
  tests pass in Debug, ReleaseSafe, and ReleaseFast. Live LogUp lowering,
  inline substitution, and complete constraint/effect ownership remain
  F-014/F-015 rather than being implied by the plan.
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
  implementation was complete, but M3 release promotion remained blocked at
  that historical snapshot.
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
  ADR-0030. At that checkpoint the code was test authority only. The current
  SegmentV2 transaction now verifies a complete leaf outer proof and mints a
  temporal-child-ready publication from verifier-owned values. The current
  temporal V3 path consumes two such publications and independently verifies
  their ordered 94,740-byte parent. M9 remains active for multi-level
  aggregation, crossover evidence, whole-frontend verification, and
  proof-system soundness.

### Open gates for the active scheduler slice

- The specialized RISC-V CPU hook now uses the bounded graph for admitted
  composition lanes and prepared fallbacks. Other backend hooks and unprepared
  compatibility fallbacks retain fail-closed resource limitations.
- Reduced-security development checks cover two workloads across current
  `N = 1/2/4` and an instrumented predecessor at `N = 1`; the full-security,
  frozen-corpus ADR-0027 differential remains open.
- Within-component sharding is limited to large prepared memory-hash,
  lookup-table, and opcode-lookup domains. Other dominant components and the
  main/interaction construction stages are not yet covered. The Tree-1
  structural executor now consumes the complete seven-wave plan, but its
  callbacks are not yet bound to production generators or final commitment
  destinations.
- Finite budgets are enforced for secure recurrence and closed prepared
  generic/RISC-V plans, including coordinator heap and reserved helper stacks
  and submission envelopes. Unprepared and non-heap scratch/device plans reject
  finite caps.
- The bounded composition graph now reports canonical task events, dependency
  readiness, admission/queue/resource wait, outer-task run time, declared byte
  classes, coarse completed rows/tiles, cancellation, and closed summary
  accounting. Profiled verified samples now bind an exact five-region witness
  materialization partition and compute cryptographic proving as its checked
  complement inside one monotonic verified-request boundary. Queue/run/wait,
  declared memory, semantic fused-lane attribution, and nested physical-worker
  accounting are retained in the same owned task profile. A real proof has
  passed this boundary and independent verification in Debug; current-source
  ReleaseFast confirmation remains the final R-005 gate. Serialization is
  intentionally outside the measured partition, and the fresh-process R-006
  attempt bundle and validator-recomputed scaling receipt remain open.
- Historical V-008 continues to record the five generated-artifact drifts and
  broad-gate findings at its detached snapshot. Those findings are not erased.
  Current gates, including the final formal reseal, are green; the remaining
  M3 promotion boundary is a clean immutable V-009 receipt.

## Immediate next actions

1. R-006 — freeze the reviewable source revision, pass installed V4 CPU/Metal
   smoke, then mint the independently replayed 1/2/4/max-worker scaling receipt
   on a quiet, AC-powered host. P-003 producer closure is already 16/16.
2. R-009 — extend the verified first `2 -> 1` parent into a multi-level tree
   while preserving ordered statement/session/authority custody at each level.
3. R-010 — freeze a quiet-host receipt and compare the completed leaf and
   temporal parent against the old-system ETHProof CSP RISC-V benchmark across
   proof bytes, prove/verify time, peak memory, total work, and security bits.
4. V-009 — after the implementation revision is frozen, mint and replay a
   clean immutable M3 receipt without rewriting historical V-008.

The opcode, split-proof, and recursion lanes own disjoint source regions. Shared
manifest regeneration happens only after each lane reports a stable identity;
in-progress source drift is never promoted into a golden artifact.

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
- The typed LUI generated writer executes only an authenticated, versioned
  numeric row-source recipe. It owns no authored-arena pointers or mutable
  scratch, writes final SoA storage directly, and was the first production
  witness authority. ADR-0038 has since promoted the complete fixed LUI and
  FENCE execution/witness/AIR authorities and fail-closed generated dispatch.
- Guest program authority is profile-separated: the closed RV32IM decoder is
  unchanged, canonical CUSTOM-0 maps to appended protocol opcode 46, and the
  declared-program commitment consumes base, guest, and completion fetches as
  borrowed streams without allocating a concatenated execution trace.
- Guest direct AIR preserves the accepted component identities: the caller
  has 417 ordered constraints, the provider has 875, both remain degree at
  most three, and the provider reuses all 430 compatibility Poseidon2
  constraints without the Merkle-only narrow-mode shell.
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
| A generated path is compared to itself | Retired formulas remain explicit test-only oracles; Sail and independent proof verification are mandatory production gates |
| Layout changes silently | Versioned deterministic manifests |
| Typed DSL becomes stringly or magical | Canon relation/effect rules and constructor validation |
| Poseidon pilot becomes a toy | Exact 445-column production component target |
| Precompile weakens base-RV32IM claim | Base validation and decoding remain closed; the extension has separate artifact/profile authority, a fresh-process CPU verifier, and authenticated-AOT Metal admission with zero backend CPU fallback |
| Direct guest equations are mistaken for standalone range proofs | Tests distinguish polynomial equalities from their authenticated fixed-table premises; noncanonical words and wrapped pointers require both surfaces exactly as ADR-0025 specifies |
| Parallelism hides total cost | Frozen M5--M9 performance protocol; flat composition telemetry is graph-local and excludes unobserved nested-worker/profile-allocation cost, so no M7 verdict exists until R-005 closes and a protocol-complete R-006 capture passes |
| Prepared tests are mistaken for production scheduling | Ledger requires a full-security frozen-corpus proof differential and separates the controlled production-path checkpoint from a normative receipt |
| Recursion balances detached calls | ADR-0030 remains proposed and requires shared session challenges plus authenticated leaf summaries |
| Hint callback or output drifts silently | Closed versioned registry and checked proof paths |
| Historical V-008 failures are mistaken for current gate state | V-008 remains immutable and red at its recorded snapshot; current gates are separately green, and promotion waits for a new clean receipt |
| A prior formal seal is mistaken for the final source-freeze seal | The final `59/59` result binds formal digest `375b77cc...ba86` and source closure `c9bc6c36...8bb2`; the earlier `59/59/24/46` evidence remains historical |
| Parallel artifact generation captures an in-progress family | Golden updates are serialized after semantic/layout identity stabilizes; check mode must fail on transient drift |
| Compiled witness drifts after binding | Pinned binding digest over exact physical IDs, names, types, and row sources; failure-atomic preflight and production-corpus differential |
| DIV/load lookup parity is mistaken for native typed effects | ADR-0033 names the inline shadow record and requires constraint-proven range refinement before canonical lowering or authority |
| Structural Tree-1 callbacks are mistaken for production parallelism | R-002 remains active until final production destinations, committed columns, and proof bytes pass serial/`N=1/2/4` differentials |
| Shadow equality is mistaken for proof evidence | H-007 requires generated artifacts inside CPU/Metal proofs before promotion |
| Local identity co-attestation is mistaken for protocol binding | V-006 states that the transcript, public statement, proof bytes, and production verifier are unchanged |
| Noisy microbenchmark movement is mistaken for a layout winner | H-010 has two complete independent cohorts; q0/q100 log-14 witness directions flip within MAD/noise, so no layout is selected |
| Native aggregation reference is mistaken for M9 evidence | Reference serialization/tree tests are explicitly unauthenticated by leaf proofs and unused by a recursive verifier |
| A complete SegmentV2 leaf is mistaken for temporal recursion | The verified publication is pinned `temporalChildReady() == true` and `completeParentReady() == false`; `temporal_parent_verified`, `whole_frontend_verified`, and `proof_system_soundness` remain false until a real ordered parent proof verifies |

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
unchanged; at this authorship checkpoint E-005 remained the next LUI gate.

### 2026-08-10 — typed LUI shadow witness became production-exact

E-005 is complete. The shadow writer authenticates a pointer-free version-1
binding over the typed LUI semantic digest, opcode, all 18 physical value IDs,
their exact names and types, and a stable numeric row-source recipe. The
resulting immutable executor remains valid after the authored arena is
released. It owns no allocator or mutable scratch and writes caller-owned
column-major M31 storage directly, with no allocation or runtime recipe
dispatch in the row loop.

All shapes, opcodes, address arithmetic, destination overlap, input/output
overlap, and protected-object overlap are preflighted before the first byte is
changed. Accepted calls write exact production row order and zero only final
padding. Rejected calls are failure-atomic. The eight focused tests cover every
destination register, immediate limb boundaries, x0 and repeated-register
chains, 96 deterministic random rows, malformed binding dimensions, aliases,
guards, overflow, padding, and the complete allocation-failure sweep. Every
cell is compared byte-for-byte with `Trace.columnsForFamily(.lui)`.

The same executor additionally passes every sampled LUI row in the shared
RISC-V rigidity corpus: 1,097 rows under the exhaustive profile on this tree,
compared across the complete power-of-two domain including padding. The
focused AIR-semantics root passes in Debug, ReleaseSafe, and ReleaseFast. At
this E-005 checkpoint the evidence was shadow-only: production witness
selection, commitment geometry, transcript bytes, and proof authority were
unchanged. E-013 has since promoted this exact LUI witness recipe, as recorded
in the current checkpoint above; the typed constraint surface remains shadow.

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

### 2026-08-10 — guest direct AIR is fixed-shape and degree-bounded

The pure direct-constraint half of C-009 is complete. The allocation-free
caller evaluator maps 286 main values plus the authenticated activity column
to 417 constraints in a public fixed order: selector booleanity and binding,
285 inactive-row zero constraints, two pointer geometry equations, and four
canonical-field gadget equations for each of 16 inputs and 16 outputs. Its
maximum algebraic degree is three. Padding is fully closed and the active hot
path uses only fixed stack values and field operations.

The provider evaluator maps the exact 445-column compatibility witness to 875
constraints. It retains all 430 pinned Poseidon2 equations unchanged, binds
enabler and atomic-I/O mode to activity, forces wide mode to zero, and closes
all 442 non-mode padding cells. It deliberately does not reuse the legacy
Merkle narrow-mode wrapper, which rejects the guest's honest atomic-I/O rows.

Ten named tests cover every honest active and padding row, the zero-call
profile, all caller and provider padding cells, every canonical byte and
materialization, pointer composition and span, every Poseidon input,
temporary, and output, non-base secure-field points, exact order/count/degree,
and the canonical field boundary. The evidence explicitly separates direct
polynomial rejection from authenticated lookup premises: the direct gadget
rejects `p`, while `p+1`, `2p`, `u32::max`, and self-consistent pointer wrap
violate the high-limb table requests required by ADR-0025. Debug, ReleaseSafe,
and ReleaseFast focused suites pass. The next C-009 boundary is the pair of
Stwo adapters that combine these equations with the already-generated lookup
interactions.

### 2026-08-10 — opcode, one-proof, Metal, and Tree-1 closure checkpoint

ADRs 0032 and 0033 record the new typed-opcode boundaries. E-006 reproduces the
shared ALU-immediate component's exact 35 columns, 22 roots, and 16 ordered
events with maximum direct degree three. Its bounded arithmetic derives carries
without columns and its fixed lookup requests are typed, versioned effects.
E-007 authenticates the complete ADDI row recipe, arithmetic/carry policy,
inverse hint metadata, slots, and event bindings under digest
`402a9f967e68d9a1f33efd9c646b6bdd51952ce89f9aa477c6de9c470f234595`.
All 35 columns and 16 events match production over boundary, alias, x0,
overflow, padding, and deterministic 512-row cases. The accepted row loop
writes final SoA storage directly with no allocation; 253 focused tests pass in
Debug, ReleaseSafe, and ReleaseFast. Production authority is unchanged.

E-010 fixes one `rv32_divrem@1` recipe for unsigned and truncation-toward-zero
signed quotient/remainder plus exact zero-divisor and `INT_MIN / -1` classes.
E-011 independently reproduces the DIV family's 67 columns, 79 direct roots,
25 ordered lookups, batch size one, and maximum degree three. Every root and
native effect matches production over exactly 292 operand/opcode rows. Fourteen
proof-carrying refinements and eleven fixed-request ownership records bind the
derived carry, quotient, sign, and comparison ranges without trace columns or
casts. Manifest v9/logical schema 8 and semantic digest v7 authenticate the
proof pools; the DIV identity is
`a33fd73890a391f954566eac75c54111c3ab5da54f20554ce095f7083b9e3ec2`.
The former lookup sidecar is gone. Coordinated proof-premise edits, direct-root
forgeries, wrong gates, ranges, ordering, liveness, aligned targets, and all
allocation failures reject. The full AIR-semantics suite passes in all three
modes with unchanged columns, effects, degree, and lowering polynomials.

E-009 uses the same closed capability boundary for JALR. It exactly reproduces
41 physical columns, 23 roots, all 18 ordered native effects, batch size two,
and maximum direct degree two. The target's cleared low bit, 20/8-bit split,
M31 range, immediate `8/8/4` refinement, result range, aligned arbitrary-PC
production, register phases, clocks, x0, aliases, and padding are proof-bound.
Normalized roots and every effect field/liveness/schema/ordinal match
production over 8,192 exhaustive immediate/low-bit rows plus boundary cases.
Its identity is
`9e374e33bcc65926240d5181eac52bad8b57b699097a211425715ba372a86f28`;
224 Debug and 12 focused ReleaseSafe/ReleaseFast tests pass. At this E-009
checkpoint the production writer and proof authority remained unchanged;
the later E-020 promotion is recorded below.

E-008 closes the full eight-opcode load/store family at the native typed-effect
boundary. All 16 ordered lookup records now live in `Arena.effects`; the old
shadow records remain only as an exact test oracle. The component preserves 48
physical columns, 63 direct roots, maximum degree three, batch size two, and
every production tuple polynomial, role, schema, ordinal, and liveness rule.
Proof-carrying selector, range, address, and conditional-access evidence closes
coordinated liveness and alias-target forgeries without adding trace columns.
The 48-row LB corpus, all eight opcodes, phase/gap mutations, inactive padding,
identity changes, and allocation failures pass in Debug, ReleaseSafe, and
ReleaseFast. Manifest v10/logical schema v9 pins semantic digest
`ec8aefea7299e84a480524c3848c1ccc73241caea4e89f983f7c2605e6b04e90`.
The production prover remains unchanged; this is native typed constraint/effect
authority, not yet a witness-writer switch.

E-013 makes LUI the first generated production-witness authority without
changing its production constraints, column geometry, statement, transcript,
or proof protocol. `runner/trace.zig` dispatches active LUI rows directly to
the authenticated 18-column recipe; the former handwritten writer is reachable
only through a test oracle. The hot path is compile-time unrolled direct SoA
stores with no allocator, runtime recipe loop, tag/string dispatch, scratch
buffer, or copy. A serial generated-versus-legacy proof test rewrites complete
LUI shards before lookup ingestion, proves and independently verifies both
arms, then requires exact descriptors, public data, interaction claims,
terminal transcript state, and postcard proof bytes. Debug, ReleaseSafe, and
ReleaseFast AIR, corpus, allocation, hook, and proof differentials pass. The
ReleaseFast proof is 53,233 bytes with SHA-256
`d08ac8bcd6c43294dda3807e7de07cc3188d8ba691a40f2d2896eccb7576a504`;
its transcript digest is
`cdf8ab815ed2448389b1f7a56f993d4c603cf6c33a0796d9642856be9303017d`.
Nine alternating ReleaseFast samples are flat to slightly favorable at logs
10/14/18 (generated/legacy ratios 1.0000/1.0121/1.0164), and row scaling stays
below the frozen linear-plus-ten-percent bound.

C-009 now closes one caller/provider profile in the same CPU STARK, serializes
the complete bounded artifact in one process, and independently decodes,
admits, and verifies it in a second process. C-012 reuses one immutable honest
proof across eleven freshly decoded one-at-a-time forgeries covering public
I/O authority, profile and semantic identity, counts, padding, descriptors,
caller/provider multiplicity, detailed claims, and a proof opening. Structural
and proof-level failures are asserted at distinct boundaries. C-011/C-013 add
one source-identical portable-versus-`CUSTOM-0` guest pair. At eight calls both
arms return identical bytes while VM steps fall from 464,096 to 448.

The first opt-in one-call functional CPU proof comparison independently
verifies both arms. Software/precompile main cells are
9,346,976/3,457,792, interaction cells are 14,441,344/11,957,632, and this
single prove boundary is 604,949,709/479,975,417 ns. The precompile proof is
larger, 114,188 versus 83,052 bytes. This is useful directional evidence, not
C-013 promotion: it is one in-process functional-security attempt without A/A,
RSS, confidence intervals, secure call-count/shape sweeps, or a validated
receipt. ADR-0034 now closes the previously undefined shape authority with one
source and six feature-selected ELFs: zero, one, or fifteen identical portable
background permutations per compared call for dominant, balanced, and
core-dominated cohorts. One-call semantic checks produce identical outputs at
58,054/84, 116,096/58,058, and 927,079/868,707 software/precompile VM steps.
The exact allocation-free global launch schedule starts with an 80-attempt
A/A admission gate and proceeds to the 1,440 M6 attempts only after it passes;
it is pinned by digest
`20153896cdcc903d6784499fba267f0ff5c8e532573b9b415b28121352775dd4`.
The v3 fresh Poseidon child and v2 A/A child bind every non-diagnostic request
to that schedule, clean source/tree, and exact executable and ELF digests. A
create-only canonical plan, append-and-fsync attempt journal, retained raw
streams, and fail-closed serial executor independently replay all 1,520
attempts and stop before M6 unless the digest-pinned A/A gate passes. A pinned
host-native corpus manifest covers 0/1/8/64/512/4096 calls. Darwin process CPU
is converted from Mach absolute-time ticks with the host timebase and wide
arithmetic; peak footprint, energy, instructions, and cycles are captured in
the same fresh child. Diagnostic proof-child and A/A smokes independently
verify and report all required counters. Arm, call, phase, shape, schedule,
corpus, source, ELF, or executable substitution fails before execution. No
secure repeated capture, Metal cohort, confidence interval, or verdict has yet
been produced.

C-010 admits exactly the profile-tagged caller/provider tail to the reviewed
generic combined direct-plus-LogUp evaluator while retaining authenticated-AOT
Metal commitments and backend proof work. It rejects altered geometry,
capabilities, evaluator ownership, per-proof overrides, and CPU composition
requests; audit proxies require exactly one domain and one OODS evaluation per
profile component. Post-proof gates require stable runtime identity, resident
Merkle evidence, matching resident base/lookup dispatches, and zero backend CPU
fallback before releasing the proof. Real-device eight-call proof plus
independent verification passes six tests in each optimization mode. During
that sweep an inherited multi-job pointer packer was found to pair unequal
slices unsafely; the new exact-subslice helper is allocation-free, rejects
overflow, and has unequal-job coverage for base, lookup-main, and interaction
lanes. The additive Metal product commands now prove the admitted extension on
the real device and verify without a Metal device. The final eight-call route
records 65 Metal dispatches, 24 resident Merkle commitments, all 8/8 semantic
and lookup components eligible and resident, and zero CPU/fallback/decline
counters; base CLI behavior is unchanged.

R-001 is complete. A retained work-pool lease carries admitted capacity across
dependent waves and releases once. The pointer-free Tree-1 executor consumes
the exact seven-wave plan with deterministic destination ownership,
cancellation, and failure selection; structural serial and `N = 1/2/4` tests
pass in all three modes. It still calls structural callbacks rather than the
production trace generators. R-002 therefore owns coordinator-preallocated
final destinations, direct-range generator adapters, and exact committed-column
and proof-byte differentials.

At this checkpoint formatting and diff hygiene pass, and source conformance
reports exactly the six inherited Metal/source-ingest findings with no new
violation. Full workspace and inventory gates are rerun after the active
refinement, signed-load, and Metal product slices stop editing shared sources.

### 2026-08-11 — M8 closes all seventeen production typed-witness families

E-014/E-015 are complete. Production witness dispatch uses authenticated typed
writers for all 17 families: base ALU
immediate/register, shifts immediate/register, less-than immediate/register,
LUI, AUIPC, JALR, JAL, load/store, MUL, MULH, DIV, FENCE, and branch
less-than. Each cutover retains a
separate test-only legacy oracle and requires exact physical rows, ordered
relation entries, proof inputs, independently verified proof bytes and
transcript state, adversarial rejection, failure atomicity, padding, and paired
all-mode throughput before the handwritten production entry point retires.

The latest completed tranche adds LT_IMM, LT_REG, SHIFTS_IMM, SHIFTS_REG, and
MUL. LT_REG's exact A/B proof is 58,475 bytes with SHA-256
`41903dd780a9a1b9eefa6d1cad162fce84b30c020886ec2a4ef14bef825cd0cb`
and transcript
`cb8385b0af4c1b786801bf0c1e11e802582cdf0f03083bf48dd5200e850dea09`.
SHIFTS_IMM/SHIFTS_REG proofs are respectively 57,802/58,094 bytes and are
byte- and transcript-identical across generated and legacy authority in Debug,
ReleaseSafe, and ReleaseFast. Their deterministic exhaustions cover all three
directions, all 32 shift amounts, sign/word boundaries, and low-byte quotient
classes. An initially measured 19.8% SHIFTS_REG slowdown was rejected; the
replacement direct scalar writer is effectively at parity, with repeated
large-workload results within roughly one percent. MUL's direct writer is
approximately 25% faster at the largest isolated workload while retaining its
exact 60,222-byte proof.

Source retirement is literal rather than dispatch-only: the obsolete shift
writer module and dead DIV, control-transfer, M-extension, and branch-less-than
production writers are removed, while explicitly
named legacy oracles remain reachable only from differential tests and proof
hooks. MULH is exact at 47 physical columns, 24 direct roots, 22 ordered
effects, degree two, ten proof-owned refinements, and semantic digest
`00d717cfbaa5ba3f82604ce9fdedd1e3f4de1ede56d3fe09ddd835d3118c0e7b`.
Its generated and legacy authorities produce the same 62,003-byte proof in
Debug, ReleaseSafe, and ReleaseFast (SHA-256
`1ce681db92dac4427d49b6826030c942f7577b452ef48d7c66f30afd5acee8e3`,
transcript
`90a869d1f91aff8c2e604cfed0f1fa07722908861930b1e8d9c3a4da8a31fc71`,
one draw) while the large witness benchmarks remain at parity.

JAL uses the closed proof-carrying program-target capability from ADR-0035
without adding protocol columns, roots, effects, witness work, or transcript
draws. Its all-mode exact proof is 54,850 bytes (SHA-256
`ef797c33718909bece536409c81d39fd4b064500f3c1fe85649e3ddd197163ba`,
transcript
`39367abaaddac2755434c66518fb3bbd36586ed73c559c0d53580b9fa673c431`,
one draw). BRANCH_LT consumes the committed-target form, preserves all 37
physical columns, 33 direct roots, and 11 ordered effects, and its ReleaseFast
generated/legacy proof is the same 56,132 bytes (SHA-256
`e9baeb3697eec792fbf7a30aff4ae16b279dae4d7d41e67d7df0f1c39bc55f44`,
transcript
`f21881aeb03399e0cbb3b70800eec988b391ca765678c5f97f472aabc660d3c5`,
one draw).

BRANCH_EQ closes the portfolio at 30 physical columns, nine ordered effects,
lookup batch size two, semantic digest
`4b7ac248bf672d93a01cbd659e59a7a98f1ec81ab5b50dd29090ca8816e49b09`,
and witness-binding digest
`18b4a5dc55e5bcd193c714daaf62f6399023af74080f5653aa58e51d4bea48e6`.
The generated and retired test-only authorities produce the same 57,073-byte
proof in Debug, ReleaseSafe, and ReleaseFast (SHA-256
`1188c212cf160b7e4b77294e6f4b94d75b4ad8915db674f96a3349370df8b7d2`,
transcript
`79f12b629a0be20d86df373b302fee35e701922e819cca5f75ee87b5359e1537`,
one draw). The shared corpus performs 6,918 admissibility evaluations in every
mode; ReleaseFast generation is 1.1123x--1.1266x faster across the pinned
workloads. Production-source and physical/effect conformance guards pass, and
the final handwritten compare writer is absent. M8 is therefore complete for
its stated witness-retirement exit; test-only independent oracles remain solely
for regression authority. This does not close the original proposal's
execution/AIR single-source requirement: E-018 through E-022 track that
separate production migration and composition retirement explicitly.

### 2026-08-12 — P-002 closes the native family profile inventory

P-002 is complete. A compile-time registry binds all 17 protocol-ordered
production witness families to concrete native typed definitions, with ADDI
explicitly representing `base_alu_imm`. The cold collector produces fixed-shape
P-001 profiles without witness execution, runtime telemetry, or name-based
dispatch. Its aggregate is 644 physical columns, 545 direct roots, 242 lookup
events, 155 batches, and 620 interaction coordinates; maximum direct,
numerator, denominator, and modeled interaction degrees are 3/2/2/3.

The checked P-002 TSV carries the complete P-001 machine schema for every
family, and the paired Markdown is the readable review surface. Their SHA-256
digests are
`d4b187cbdf5baee61f4eb2541acf1d69e8e84ddae91007b574ec4a6663a18c6b`
and
`52bf9cff23de5ea05da9588846a1af2e21be67ad16379fd580bb4057cab34d1c`;
the underlying report digest is
`0dd67acd8705f77a5c482a8d3706b38929d799091b3971e995b20dcc44f56772`.
Every check/update run independently recompiles the A-005 production shadow
and requires exact family-by-family layout, batch, interaction, and degree
agreement before admitting bytes. Update is explicit and atomic. Production
activation remains `not_assessed`; no proof or performance claim is made.

### 2026-08-12 — C-013 CPU capture and reduction boundary closes

C-013 now has a create-only clean-source plan, the exact 80-attempt A/A plus
1,440-attempt M6 serial executor, an append-and-fsync raw journal, a retained
CPU reduction, and independent bundle replay. The reducer preserves all 18
shape/call rows, uses the pinned epoch-3 Hodges--Lehmann/bootstrap authority,
computes crossover separately for every shape, and reports launcher wall time,
verified/proving/verification time, CPU, instructions, cycles, energy, RSS,
proof bytes, and exact committed cells. The result explicitly remains a CPU
reduction verdict; it cannot populate the M6 promotion outcome without Metal
and the complete receipt contract.

The audit found a stale installed v1 proof child even though the build-graph
v3 check was green. Plan publication now rejects executables without the
current protocol markers, and the runbook explicitly installs all three
ReleaseFast capture tools before planning. Thirty-one focused Python tests,
twelve protocol mutation tests, the all-shape/corpus/A/A/proof-child ReleaseFast
preflight, and explicit artifact installation pass. One current v3 secure
dominant one-call diagnostic verifies both arms and shows the expected mixed
cost vector: verified-request speed `1.081174`, committed-cell ratio
`0.744605`, RSS ratio `0.914643`, CPU-work ratio `1.041787`, instruction-work
ratio `1.058546`, and proof-size ratio `1.273228`. It is retained only as a
dirty-tree, unpaired diagnostic.

The normative measurement remains `NO_VERDICT`: plan creation correctly
rejects the dirty shared feature checkout, and the full Metal cohort plus
source/build/toolchain closure, separate verifier receipts, complete geometry,
cross-lane checks, and final receipt renderer remain absent. The frozen CPU
schedule alone requires 25 minutes 19 seconds of cooldown; proof time and the
intentionally expensive core-dominated 4,096-call arm are additional and are
not extrapolated from the diagnostic. The exact runbook and gap are in the
[C-013 CPU capture readiness note](notes/2026-08-12-c013-cpu-capture-readiness.md).

### 2026-08-12 — generated geometry, batching, runtime profiling, and LUI SSOT advance

At this checkpoint A-013 owned an authenticated row-window and mask plan for all seventeen
families. The live opcode lookup component consumes its compact mask binding,
and real CPU proofs reject both row-zero recurrence-anchor and row-one
cross-row interaction forgeries through the ordinary Tree-2 commitment path.
Semantic main-column masks and statement-wide generated composition remained
open at this checkpoint; their later production closure is recorded below.

A-014 at this checkpoint had an authenticated degree-aware batching candidate. It preserves event
order and proof-wide maximum degree three while reducing the shadow native
inventory from 155 to 137 batches and 620 to 548 interaction M31 columns. Exact
algebra, collision, selected-component, allocation, and all-mode gates pass;
local ReleaseFast interaction generation improves by roughly 1.20--1.23x for
MUL/MULH/DIV. Production allocation, verifier order, protocol versioning, and
whole-proof evidence were still open at this checkpoint; CPU proof activation
is recorded below.

P-003 now has a versioned allocation-free join between the complete P-002 AIR
inventory, hierarchical stages, bounded task graphs, and independently verified
proof/runtime identities. It validates lifecycle accounting and semantic
attribution, authenticates complete source records, distinguishes exact
instrumentation from structural estimates, and emits canonical JSON. The
opt-in compatibility benchmark publishes a real receipt after verification.
Darwin capture now fills the shared process authority's lifetime peak physical
footprint and interval instructions/cycles/energy; unsupported hosts remain
explicit. Missing exact field/FFT/FRI/Merkle counters still prevent promotion.
Focused Debug, ReleaseSafe, and ReleaseFast tests pass.

The LUI convergence tranche now exposes retirement, witness generation, direct
constraints, ordered relations, and byte-exact formal/runtime export through
one authenticated authority. It has crossed the production boundary: the
generated retirement registry owns the runner route, the legacy executor fails
closed, and the former Stark-V-shaped AIR is a named test-only oracle. The
retirement hot path compiles a compact single-event transaction and skips
duplicate validation only while no allocator or other external code can run.
The pinned live Sail gate, exact proof, malicious rejection, and paired
performance gates are green. The exact proof remains 53,233 bytes with
SHA-256 `d08ac8d7dd90d63683ba75f63194101662967981ae2380ebcc16cac3568d5d0f`,
transcript
`cdf8abf6152bcf3a17fd02f9a15bbc809424b751567348604841146e02fc29ab`,
and one draw. A current ReleaseFast run measured 132,333 ns for 4,096 atomic
retirements versus 143,792 ns for the independent legacy path (1.0866x).

FENCE is the second production SSOT family. Its fixed typed authority owns the
six-column witness, two direct roots, three ordered relations, empty access
geometry, sequential execution, and formal/runtime export. Generated dispatch
cannot fall through to the legacy executor; the retired semantic implementation
is test-only. Its exact proof remains 55,922 bytes with SHA-256
`d40169c9015b816f043da0f7c8b613ca0b950b7f01e408ca4ec2583b34c82864`,
transcript
`a1c12df7dd49f82e44219e982299a47ecd23c670b05a9fb5d9a75bfde5dc91db`,
and one draw. The current ReleaseFast paired retirement sample is 714,583 ns
typed versus 781,458 ns legacy (1.1013x). Caller-owned direct output removes
the maximum-family return copy; the generic production direct path is now
1.0700x faster than the fixed FENCE reference while lookup construction is at
parity. ADR-0038 fixes this production activation pattern.

### 2026-08-12 — BASE_ALU_REG becomes the fifth production SSOT family

E-020 now has three of its fifteen post-LUI/FENCE families complete.
BASE_ALU_REG's pointer-free authority owns ADD, SUB, XOR, OR, and AND
architectural results and x0 behavior, all 35 witness columns, 22 direct roots,
18 ordered relations, formal extraction, and three-event failure-atomic
retirement. The production semantic registry no longer exports the retired
evaluator, witness projection goes through the pinned authority, generated
dispatch owns all five opcodes, and the legacy executor fails closed. The
all-alias destination correctly consumes the later phase-2 source event.

The canonical AIR and runner roots pass 668/668 and 319/319 tests respectively
in Debug, ReleaseSafe, and ReleaseFast. Required-live Sail covers every family
opcode, x0 discard, and `rd == rs1 == rs2`. The exact generated-versus-legacy
proof is 55,171 bytes with SHA-256
`e95dff718cf31f6cce4ade9ea8dce269437bb73e914e25e8d1fc3296af56ce50`,
transcript
`659a61c4c45bf996f91f8029457364e6231258179e06249bc88d89d410a8e4f8`,
and one draw. Canonical ReleaseFast measured the fixed direct evaluator at
1.3249x and atomic retirement at 1.1830x; witness medians were 0.9961x,
0.9973x, and 0.9888x, all above the strict 0.97x floor. The repaired
BASE_ALU_IMM retirement gate simultaneously measured 1.2463x, closing its
reopened executable admission. No compatibility manifest was regenerated;
the combined artifact update remains a serialized cross-family review step.

### 2026-08-12 — JAL becomes the sixth production SSOT family

JAL now crosses the complete E-020/E-021 production boundary. Its pinned typed
authority owns execution, witness projection, all direct roots and ordered
relations, production runtime/formal extraction, and failure-atomic retirement.
Generated dispatch owns the architectural route, the retired evaluator is
test-only, and required-live Sail passes on the exact proven stream.

Debug and ReleaseSafe AIR/runner gates, the ReleaseFast runner gate, and the
focused 65/65 ReleaseFast JAL AIR gate are green. Formal extraction covers all
17 families across 32 trials; the JAL corpus performs 6,918 admissibility
evaluations. Generated and retained-legacy arms independently verify to the
same 54,850-byte proof with SHA-256
`ef797c33718909bece536409c81d39fd4b064500f3c1fe85649e3ddd197163ba`,
transcript
`39367abaaddac2755434c66518fb3bbd36586ed73c559c0d53580b9fa673c431`,
and one draw. Three repeated ReleaseFast evaluator gates put direct evaluation
at 1.0787x--1.1129x and lookup construction at 1.0032x--1.0314x legacy
throughput; the production retirement typed/legacy time ratio is 0.8678. A
whole-suite ReleaseFast run reached and passed JAL before unrelated noisy
LT_REG/MULH performance gates, which are not attributed to this promotion.

### 2026-08-12 — JALR becomes the seventh production SSOT family

JALR now crosses the complete production boundary with one pointer-free typed
authority for indirect-control retirement, 41 witness columns, 23 direct roots,
18 ordered relations, and formal extraction. Generated dispatch owns the
architectural route, the legacy executor fails closed, and the handwritten AIR
survives only as a named differential oracle. The admission additionally caught
and repaired a field-equal but symbolically distinct phase-two access-clock DAG,
so authored and production programs now agree structurally as well as by value.

Debug and ReleaseSafe AIR/runner roots pass 678/678 and 336/336; the ReleaseFast
runner root passes 336/336. Formal extraction covers 17 families × 32 trials,
and the exhaustive corpus closes 6,918 admissibility evaluations. Exact A/B
proofs independently verify to 59,502 identical bytes with SHA-256
`bdc91a1290cac3ac66500581fa4f414621f90f5fef67af1aa3c0a2a4c0354f81`,
transcript
`d0fc1b48bfdcabecf41cd0b3953825a85d19aa08eba4306b8b94b129c584c0dd`,
one draw, and required-live Sail agreement. ReleaseFast production medians are
1.0439x for direct AIR, 3.1631x for lookup construction, and 1.5390x for
failure-atomic retirement. The full ReleaseFast AIR root passed every JALR gate
and stopped only on the unrelated noisy BASE_ALU_REG witness threshold.

### 2026-08-12 — BRANCH_EQ becomes the eighth production SSOT family

BEQ/BNE now cross the full production boundary through one authenticated,
pointer-free typed authority. Generated retirement owns both architectural
opcodes, the legacy executor fails closed, production witness projection and
AIR/formal construction share the fixed capability, and the handwritten
semantic evaluator is retained only as an explicitly named differential
oracle. The exact geometry remains 30 main columns, 18 direct roots, nine
ordered relation events, and lookup batch size two; its authority digest is
`afa781f9d1a02f5906706554bcc694f39658998470b6da79ee85717e4b0232f4`.

Debug and ReleaseSafe AIR roots pass 686/686; runner roots pass 346/346 in
Debug, ReleaseSafe, and ReleaseFast. Formal extraction covers 17 families × 32
trials and the exhaustive corpus closes 6,918 admissibility evaluations.
Generated and retained-legacy proofs independently verify to 57,073 identical
bytes with SHA-256
`1188c212cf160b7e4b77294e6f4b94d75b4ad8915db674f96a3349370df8b7d2`,
transcript
`79f12b629a0be20d86df373b302fee35e701922e819cca5f75ee87b5359e1537`,
one draw, and required-live Sail agreement.

Two final focused ReleaseFast samples place production direct evaluation at
1.1256x--1.1365x and lookup construction at 0.9962x--0.9986x retained legacy
throughput. Failure-atomic retirement is 1.6560x and the independent witness
scaling route is 1.1018x--1.1389x. The strict 0.97x floor remains unchanged.
Complete ReleaseFast AIR reruns also expose unrelated noisy BASE_ALU_REG,
FENCE, LT_REG, and MULH microbenchmark samples; none is waived or attributed
to this promotion.

### 2026-08-12 — BRANCH_LT becomes the ninth production SSOT family

BLT/BLTU/BGE/BGEU now cross the full production boundary through one
authenticated, pointer-free typed authority. Generated retirement owns all
four architectural opcodes, the legacy executor fails closed, production
witness projection and AIR/formal construction share the fixed capability,
and the handwritten semantic evaluator remains only as a named differential
oracle. Exact geometry is 37 main columns, 33 direct roots, 11 ordered
relations, and lookup batch size two; the authority digest is
`77e729cdac93b45bfd71ecfb8f7afa9411a1db09f9caf567c9fd87d460412a95`.

Debug and ReleaseSafe AIR roots pass 693/693; runner roots pass 355/355 in
Debug, ReleaseSafe, and ReleaseFast. Formal extraction covers 17 families × 32
trials, and exhaustive rigidity closes 6,918 admissibility evaluations.
Generated and retained-legacy proofs independently verify to 56,132 identical
bytes with SHA-256
`e9baeb3697eec792fbf7a30aff4ae16b279dae4d7d41e67d7df0f1c39bc55f44`,
transcript
`f21881aeb03399e0cbb3b70800eec988b391ca765678c5f97f472aabc660d3c5`,
one draw, and required-live Sail agreement.

Three focused ReleaseFast evaluator samples place production direct evaluation
at 1.1073x--1.1132x and lookup construction at 2.3772x--2.4420x retained
legacy throughput. Failure-atomic retirement is 1.5243x--1.5832x, and the
independent witness scaling route is 1.0620x--1.0739x from 1,024 through
262,144 rows. The strict 0.97x floor remains unchanged.

### 2026-08-12 — LT_IMM becomes the tenth production SSOT family

SLTI/SLTIU now cross the complete production boundary through one
authenticated, pointer-free typed authority. Generated retirement owns both
architectural opcodes, the legacy executor fails closed, production witness
projection and AIR/formal construction share the fixed capability, and the
handwritten semantic evaluator remains only as a named differential oracle.
Exact geometry is 37 main columns, 33 direct roots, 11 ordered relations, and
lookup batch size two; the authority digest is
`bfe5a4896da341e2efd83feaf82c2ac289937712a3d2971162f3d783a25b491f`.

Debug and ReleaseSafe AIR roots pass 702/702; runner roots pass 365/365.
Formal extraction covers 17 families × 32 trials, and exhaustive rigidity
closes 6,918 admissibility evaluations. Generated and retained-legacy proofs
independently verify to 55,680 identical bytes with SHA-256
`adc29b4eb673320042dbbc08a7ab87945ea19636ddb6ce65d624b5db7d043726`,
transcript
`9ed39ee4acb48175243824e4212318a51d821ac30eed565494c26b0339e69b05`,
one draw, and required-live Sail agreement.

Repeated focused ReleaseFast admissions place production direct evaluation at
1.1262x--1.1312x and lookup construction at 4.6455x--4.9150x retained legacy throughput.
Failure-atomic retirement is 1.2383x, and independent witness scaling is
1.0265x--1.0504x from 1,024 through 262,144 rows. The exact word gate covers
8,388,608 opcode/immediate/register encodings, and the strict 0.97x performance
floor remains unchanged.

### 2026-08-12 — Cairo frame and function-activation compiler lands

F-013 closes the structural hole between typed call metadata and the original
function-as-AIR-table design. The compiler now derives each function's
`[fp-args, fp+frame)` logical window from transitive dataflow, admits only
declared input leaves, emits every local once in topological order, and assigns
each untrusted hint invocation to one frame. Determinism propagates through the
acyclic call graph; a relation-backed return depending on a hint fails closed.

Every function has a domain-separated ABI identity bound to the current
semantic program digest, stable name, and exact input/output types. Required
relations receive one callee-consume event followed by caller or public emits
in canonical call order. The focused plan digest is
`6839b8661426cac5c33bb112eeb4daf0df1fbaf1abfbb68afdd31e5f577743da`;
7/7 tests pass in all three optimization modes, including mutations and full
allocation-failure enumeration. ADR-0037 deliberately keeps this as compiler
authority until F-014 binds its identities and events into prover/verifier
challenge draws and F-015 gives complete constraints/effects and inline calls
one frame-owned lowering path.

### 2026-08-12 — authenticated pair-node protocol substrate lands

R-009 now has a native, allocation-free shadow for its first canonical pair.
The exact 752-byte record orders the core-request leaf before the
Poseidon-provider leaf and compares every encoded field against exact expected
child-verifier output. Session, challenge, full authority, call commitment,
event count, power-of-two session leaf count, and aggregator VK are rebound.
The A2 VK-injection/root-pin seam and distinct root-authorized result, plus A3
derivation, exact relation closure, canonical empty-case, and
`kappa <= 1024` guards, are therefore concrete rather than prose. Versioned
identity domains and independent statement, proof, transcript, summary, and
node identities bind the recursive meaning; the record hash remains diagnostic.

Protocol review drove exact-child authority checks, a protocol-identical M31
event boundary, power-of-two session cardinality, schema-version binding, and
expanded adversarial coverage. The focused pair-node root passes 28/28 and the
integrated recursion-protocol gate passes in Debug, ReleaseSafe, and
ReleaseFast. This remains deliberately non-promotional: the shadow cannot prove
that its expected outputs came from a successful child verifier and neither
verifies child proof bytes nor builds, proves, or verifies the 36-row outer
circuit. R-009 remains active. See the
[authenticated pair-node note](notes/2026-08-12-r009-authenticated-pair-node.md).

### 2026-08-13 — current gates green; immutable capture remains open

The final release sweep advances M3 from blocked to ready without rewriting
its history. The workspace passes `21/21` packages and 70 edges, compatibility
manifests pass `17/17`, frontend Debug reports 2,149 passes plus one intentional
skip, and recursion passes `583/583` in Debug, ReleaseSafe, and ReleaseFast.
The concrete rows-29/33 proof gate now lives in the RISC-V CPU integration
package rather than the backend-neutral frontend; all three modes independently
verify the exact 5,184-byte proof estimate and identical transcript, and the
ReleaseFast CPU integration suite passes `17/17`.

The final formal reseal is green `59/59`, with formal digest
`375b77cc4c11c2af324b3d66a989fd1e69a58c809dbb68e444d6b6a25fdeba86`
and source closure
`c9bc6c362663ce20aac44b9a004a4d86e71f9888bf2a809512116733db0a8bb2`.
No clean top-level receipt yet covers this checkout. V-008 therefore remains
an immutable historical red snapshot while V-009 owns the new capture. Claim
boundaries remain unchanged: the historical Level-1 pilot is `2/46`, recursion
proof coverage is `3/36`, no child proof is actually verified, no full outer
proof exists, and both `whole_frontend_verified` and
`proof_system_soundness` remain `false`. Separately, the pair-node audit's
roughly 229 scalar Poseidon permutations remain a profile-and-deduplicate
follow-up, with no speedup claimed before measurement.

### 2026-08-13 — captured-leaf outer proof reaches 15/36

Later on the same development day, rows 20--23 and 25--34 entered one real
captured-leaf outer proof, including the shared row-34 Poseidon2 provider. The
14-component proof independently verifies at 58,284 bytes; union with the
separate row-0 gate raises honest proof coverage to 15/36. It is still not a
complete recursive verifier: row 24, upstream transcript/DEEP ownership, the
remaining rows, and global relation closure are open.

Live profiling also found and removed the quadratic interaction-row rebuild.
The same ReleaseSafe 4x/97 workload fell from 650.480 seconds to 14.086 seconds
at one worker and 12.608 seconds at four, without changing proof geometry or
the three mutation outcomes. The earlier pair-node follow-up is likewise now
measured: prepared authentication uses 55 scalar permutations rather than 229,
the compatibility path uses 94, and the focused benchmark reports about
1.898x improvement.

### 2026-08-13 — exact PCS/DEEP row reaches the outer proof

Row 24 now joins the captured-leaf outer proof, so the proved subsystem is a
contiguous 15-component span over rows 20--34 and the honest union with row 0
is 16/36. The verifier independently rebuilds both the PCS/DEEP and FRI
arithmetic circuits, all six segment/binary lowering lanes, their schedules,
preprocessing, component programs, and public boundaries. The input rows are
populated only from a transactionally successful native verifier capture.

The accepted frozen-V1 ReleaseSafe run uses four workers and the 2x/193
profile. It commits 307 preprocessing, 758 main, and 252 interaction columns,
evaluates 848 constraints, estimates 64,476 proof bytes, proves in 57.974 s,
and independently verifies in 18.860 s. All three outer mutations and all 21
fixed-adapter mutations reject. The same code under the non-promotional 4x/97
frontier candidate estimates 62,908 bytes, proves in 28.766 s, verifies in
9.440 s, and closes exactly 26,675 Poseidon2 requests.

Exact PCS batch factorization, cached denominator coefficients, and graph
constant identities reduce the first sound row-24 V1 checkpoint by 17.4% in
prove time, 20.0% in assembly, 25.3% in verification, and 3.3% in proof
estimate. A faster experiment that removed local query/route constraints was
rejected and reverted: the partial outer does not yet prove the global lookup
closure needed to justify that delegation. This remains a subsystem proof, not
a complete recursive verifier or a proved `2 -> 1` node; rows 1--19, row 35,
full relation closure, and child-proof binding remain open.

### 2026-08-13 — verifier-owned composition control reaches 17/36

Row 19 now precedes the arithmetic subsystem in the same real proof, making
the covered range contiguous from row 19 through row 34. Its preprocessing is
rebuilt from the exact authenticated VM and recursion schedule plans. Because
the row has no main columns, the verifier also recomputes its complete claimed
sum from that schedule, the fixed segment proof kind, and its own relation
challenges before consuming proof bytes. A forged row-19 claim therefore
rejects failure-atomically as the fourth outer mutation.

The four-worker frozen-V1 proof commits 316 preprocessing, 758 main, and 256
interaction columns, evaluates 850 constraints, estimates 66,360 bytes, proves
in 55.499 s, and verifies in 18.161 s. The measured 4x/97 candidate estimates
64,760 bytes, proves in 28.137 s, and verifies in 9.251 s. The PCS graph and
all arithmetic active/capacity counts remain byte-for-byte unchanged; the
small favorable timing delta is treated as run noise, not a claimed speedup.
The honest proof union is now 17/36. Row 18's production composition graph,
rows 1--17, row 35/global closure, complete child-proof binding, and the proved
`2 -> 1` node remain open.

### 2026-08-13 — production VM composition reaches 18/36

Row 18 now precedes row 19 in the same real proof, making the covered range
contiguous from row 18 through row 34. Its 19,352-node VM evaluation graph and
4,805-row input schedule are rebuilt from verifier-authenticated component,
profile, reference, preprocessing, and schedule authority. Prepared validation
replays all derived nodes, requires the circuit output to be zero, and binds
every row-18 value to its exact circuit input. The verifier independently
recomputes its claimed sum; a row-18 value forgery is the fifth rejecting
mutation.

The eight-worker frozen-V1 proof commits 347 preprocessing, 760 main, and 276
interaction columns, evaluates 862 constraints, closes exactly 52,303 shared
Poseidon2 calls, estimates 66,308 bytes, proves in 30.954 s, and verifies in
10.779 s. Removing four redundant inactive child arithmetic graphs while
retaining one authenticated binary-mode capacity anchor reduced proof time by
32.5%, assembly by 31.1%, the STARK body by 45.8%, and verification by 31.0%
against the first sound row-18 run. Live arithmetic counts and semantics remain
unchanged. The honest proof union is now 18/36. Rows 1--17, row 35/global
closure, complete child-proof binding, and the proved `2 -> 1` node remain open.

### 2026-08-13 — pair-node authority context becomes an immutable hot capability

The R-009 authentication profiler is now one executable 13-entry call tree,
derived from the exact byte and canonical-word preimage lengths. Compile-time
checks pin the tree-cold suite at 39 scalar Poseidon2-M31 permutations, the
authority-cold context at 17, and the transcript-authoritative output path at
38. This preserves the historical 229 audit, exact 94 convenience path, and
immutable 55 suite-prepared RED baseline while removing the 17 context
permutations from repeated authentication.

`prepareRootContext()` validates and copies the verifier-owned authority and
root pin by value. `authenticateRootWithPreparedContext()` still requires both
original inputs and rejects source or snapshot drift before validating the
record. The mutation fleet covers independent authority, pin, cache, context,
VK, proof, event-count, and balanced-relation changes. All V1 golden folds and
the final node identity remain bit-for-bit equal. The prepared type is
compile-time pointer-free and the exact cold/hot heap-allocation ledger is
zero. The focused build passes 259 tests with one intentional benchmark skip
in Debug, ReleaseSafe, and ReleaseFast; 18/18 directly declared non-benchmark
R-009 tests pass.

The exact 55-to-38 change removes 17 scalar permutations (30.9%). The expanded
ABCCBA microbenchmark is ready, but the development host was loaded, on battery,
and not suitable for timing evidence. No new wall-time speedup is claimed until
a quiet AC-powered capture is available.

### 2026-08-15 — SegmentV2 closes the complete recursive leaf

The verifier-owned native capture now crosses into one complete append-only
SegmentV2 outer proof. Its 39 components comprise all 36 universal rows, two
authenticated V2 boundary sources, and row 38's committed verifier-input
provider. Challenge-independent tuple classification closes 102,099
contributions with no unmatched tuple in any of 47 domains. The independently
reconstructed verifier admits the 91,722-byte canonical proof; the one-worker
ReleaseFast development run reports 1.155 s proving and 0.831 s verification.
These timings are not a frozen benchmark receipt.

The final proving blocker was diagnosed rather than patched by trial. A
per-component OODS differential placed the only mismatch at row 38; an
alpha-zero rerun isolated constraint 7, its sole LogUp recurrence. The row-38
witness wrote Tree 0/1 in logical order, while the framework already wrote Tree
2 in commitment order, and the generic installer had copied all three. Tree
0/1 now scatter exactly once through `committedRow`; Tree 2 remains byte-exact.
The focused order test passes, all 39 component differentials are green, and
the real 47-domain proof verifies.

This closes the recursive leaf, not temporal recursion. The verifier-minted
publication is temporal-child-ready and explicitly not complete-parent-ready.
At this 2026-08-15 checkpoint, `temporal_parent_verified = false`,
`whole_frontend_verified = false`, and `proof_system_soundness = false`. The
2026-08-20 parent evidence above supersedes only the first flag.

### 2026-08-15 — production SSOT and exact proof telemetry close; temporal custody advances

One shared production component authority now assembles all 17 opcode and 11
infrastructure components for both prover and verifier. It owns checked O(1)
offsets and fails atomically on manifest drift; its Debug and ReleaseFast
inventory passes 324/324. Function activation lowering separately closes
F-014 with compiler-owned degree-two LogUp constraints under the authenticated
degree-three bound, verifier-recomputed public-root claims, allocation-free hot
evaluation, and 21/21 Debug and ReleaseFast tests. A program without a
relation-backed production function remains an exact zero-cost compatibility
no-op.

R-005 is complete. The profiled production adapter records exactly five
non-overlapping witness-materialization regions, computes proving as their
checked complement inside the proof boundary, and binds guest, witness,
proving, native verification, queue/run/wait, and declared resource custody to
one verified attempt. The ordinary unprofiled API still enters the predecessor
path without a meter or recursion stage. The focused product gate passes a
real independently verified proof in Debug and ReleaseFast; serialization and
receipt work remain outside the timing authority. R-006 now owns the remaining
fresh-process 1/2/4/max-worker capture and validator-recomputed receipt.

That R-006 evidence path is now executable. Its immutable plan pins the frozen
protocol hash, clean commit/tree/source closure, ReleaseFast executable,
Darwin host and power declaration, exact fixed/generated workload bytes, and
the complete pairwise 1/2/4/max-worker plus A/A schedule: 1,040 fresh serial
attempts per lane. Each attempt fixes proof and Merkle worker width, leaves PoW
on the shared pool, runs one profiled proof, then invokes the independent
verifier outside the timing boundary. The create-only bundle retains every
proof and stream in an fsynced append-only journal; validation recomputes timing,
task, contribution, resource, statement, transcript, proof, and inventory
custody. The protocol plus controller suite passes 21/21. A real installed-
binary smoke and clean CPU/Metal captures remain open, so R-006 is active.

On the recursive path, active-empty V3.1 now instantiates a concrete canonical
empty heterogeneous session, pins the provider AIR program to its catalog
identity, and passes its count-guarded 8/8 Debug gate. Append-only temporal V3
custody binds rows 0--17, exact placement and layout identity, and 47/47
relation domains for each ordered verifier-minted SegmentV2 child. Swapped,
omitted, cross-session, cross-statement, registry, duplicate-domain, and frozen
row-eight substitutions reject. Temporal source-kind 13 is represented by a
disjoint, digest-bound payload V2 authority; the frozen 1--12-kind program and
cross-version truncations reject instead of coercing it. The focused
ReleaseFast gate passes 6/6. The tree writer and independently verified
two-to-one parent were still open at that checkpoint. That historical state is
superseded by the 2026-08-20 evidence above: rows 18--35 are authenticated, the
real parent independently verifies, and `temporal_parent_verified = true`.

Focused-test latency was also made fail-closed and materially shorter. The
initial heavy row-window and lookup-batching integration gates each passed
222/222 with
nonzero count floors, while their authority edit roots select only the intended
named tests. On this host the row-window loop fell from a one-minute, 4 GiB
compile to 5 seconds and 470 MiB; lookup batching compiles in 3 seconds and
441 MiB. The lightweight gates pass 9/9 and 8/8 respectively and do not replace
the production integration gates.

### 2026-08-15 — physical expressions, dormant V2 lookup execution, and enforced iteration lanes

A-013 at this checkpoint had an append-only physical expression authority without changing
the frozen logical V1 union. Shifted committed-column reads compile against the
authenticated row-window plan into pre-resolved tree/local-column/offset
bindings with typed component ownership and exact degree. Compilation rejects
cross-owner arithmetic, dead nodes, duplicate or invalid roots, forward
references, non-canonical constants, and degree-cap overflow. The prepared hot
loop uses caller-owned scratch with no allocation, hashing, search, or plan
lookup; cyclic row-zero semantics, geometry, field canonicity, and alias
preflight are covered. The live semantic component has also retired its
separate width lookup in favor of an authenticated row-window
`SemanticMaskBinding`. The shifted-expression gate is 6/6 in Debug and
ReleaseFast, the row-window edit gate is 11/11, and the post-cutover integration
gate is 229/229. The narrow semantic edit loop is 10/10 in 11.28 seconds and
2.54 GiB compiler RSS, versus the former broad 28.80-second/4.36-GiB loop. The
later production proof exit is recorded below.

A-014 at this checkpoint exported a dormant authenticated V2
polynomial capability. Its prepared evaluator is allocation-, hash-, and
search-free per row, and the CPU scalar backend admits it only under explicit
`authenticated_statement_v2` activation into worker-private packed scratch.
The disabled path retains the V1 bucket shape and direct hot loop. Exact
V1-uniform and selected-pair differentials, serial/two-lane execution,
identity/degree/geometry/resource mutation, and allocation-failure cleanup are
green: 9/9 CPU tests in 3.02 seconds and 9/9 frontend tests in 13.92 seconds.
All 17 V2 authority records and their exact 137-batch/548-column physical
ranges are generated and pinned. The later explicit CPU proof-path activation
and real-proof evidence are recorded below; V1 remains the production default.

P-003 now owns one versioned six-source exact-work authority for field
additions, multiplications, inversions, FFT butterflies, FRI folds, and Merkle
compressions. Coverage bits distinguish an observed zero from an unwired
producer; checked aggregation is transactional, complete receipts are
digest-bound, and `Recorder(false)` is a zero-size no-op capability. The R-006
validator independently recomputes the little-endian digest and rejects
partial/extra/malformed groups while retaining explicit legacy schema support.
Prover-API, runtime-profile, and Python gates are green. This establishes V2
transport, not producer-exhaustive measurement: the present ten-site inventory
uses free-form markers and seven coarse boundary counts, so it cannot detect a
jointly deleted plan and record or prevent one site from impersonating another.
Only the generic M31 polynomial-commit forward FFT currently reports an exact
field delta, `(A,M,I)=(2B,B,0)` for `B` completed butterflies. Production does
not finalize partial coverage and therefore remains `riscv_profiled_proof_v3`;
V4 exists only in validation fixtures. The exact closure audit now assigns
formulas and owners to cold twiddles, interpolation and remaining FFTs, secure
composition, witness/Poseidon work, relation/LogUp work, domain and OODS
composition, sampled evaluation, quotient preparation/execution, all FRI
folds and final interpolation, and transcript/VCS zero-or-Poseidon cases. The
next promotion tranche is a typed executable `Site` ledger with per-site
expected/completed arrays and compile-time `Site -> Boundary` aggregation,
followed by those producer deltas and one independently verified installed-
binary V4 request. During the first FFT tranche, a pre-existing CPU combined-LDE bug was
isolated: expansion above 2x could transform an uninitialized tail. The 2x
fast path remains; larger expansion zero-fills and performs the full transform.
Independent 2x/4x poisoned-tail differentials pass 10/10 in Debug and
ReleaseSafe before telemetry is allowed to rely on the boundary.

This paragraph records the 2026-08-15 checkpoint. It is superseded for P-003
closure by the schema-9, 23-site, CPU/Metal/joint 16/16 evidence above; only
R-006's installed-binary scaling capture and P-004 promotion budgets remain.

Temporal V3 now has a concrete deterministic Tree0/1/2 writer for rows 0--17,
one reusable maximum interaction scratch, exact placement/ownership, zero and
alias destination preflight, fail-atomic clearing, and pointer-free receipts.
Its real-child prefix/runtime bridge and allocation-free hot-plan validation
pass the declaration-complete binary gate in 15.65 seconds and the direct V3
writer/mutation gate in 1.92 seconds. At that checkpoint, rows 18--35 and
global parent closure were next; the 2026-08-20 section above supersedes that
boundary with `temporal_parent_verified = true`.

Finally, compiler concurrency is bounded and cache-isolated rather than
coordinated by chat. `scripts/typed_air_zig_lane.py` owns three nonblocking
Git-private slots, injects a distinct local Zig cache per occupied slot, shares
only the immutable global cache, publishes owner/PID/argv metadata, and exits
75 only when all slots are busy. Locks survive a killed controller through
descriptor inheritance. `--status` distinguishes live locks from stale
metadata. Eight unit tests cover direct and time-wrapped argv
execution, cache replacement, live second-slot admission, three-slot
contention, status, V1 migration exclusion, cleanup, and invalid requests.
Heavy proof execution remains serialized even
though focused compilers may run concurrently. All parallel agents must use
this wrapper for future Zig compile/test commands.

### 2026-08-15 — A-013 generated composition is exact; A-014 proves the selected CPU layout

A-013's correctness and production-activation exit is closed. A dedicated
reference backend aliases every production CPU operation except the optional
composition hooks, so its separately executed proof differs only by declining
generated composition. Against the real all-family statement, the production
CPU path records one admission, exactly 17/17 semantic/lookup pairs, and zero
declines. Debug and ReleaseFast both retain the frozen 688-column V1 Tree 2,
produce the same statement and interaction claim, the same 51,581 canonical
proof bytes, and the same terminal transcript; both proofs independently
verify through the ordinary production engine. The common proof SHA-256 is
`3a93cb594f9021f1d0625c3f31431401a668ab266d6502ade64129e0a10f783a`
and the transcript digest is
`3690d6814dbdf9ec02a85c3a59cb16d2ed87036291fed3e531c740b546c08293`.
One ReleaseFast attribution sample measured 2,113.513 ms reference versus
2,117.416 ms generated; it is not promoted to a performance claim. Only the
paired global P-004 evidence remains open for A-013.

A-014 now has a separate, explicit authenticated production protocol on CPU.
The real 17-family statement reduces opcode Tree-2 width from 620 to 548 while
leaving 68 infrastructure columns unchanged: 688 to 616 total, a 72-column
reduction equal to 11.61% of opcode interaction geometry and 10.47% of the
whole tree. Canonical proof size falls from 51,863 to 50,256 bytes, a 1,607-byte
or 3.10% reduction. Both protocols independently verify and reciprocal replay
rejects. Manifest, statement, and activation identities are respectively
`f205a9fb631bbab2b93efbb961fe662c5a2c0ee55d7d60d606d49d030a2de849`,
`8b1b08f4635daa583a55d91914103c49ad15a7db996a4290e23b6686109eeff0`,
and `d5771e0a86bb81a25f4e6d0a3b52e6a88766c3be3c1115d39f9846443a50fd51`.
Debug and ReleaseFast single samples disagree on proving-time direction, so no
throughput win is claimed. Compatibility V1 remains the default. Native Metal
V2 execution and a no-CPU-fallback receipt remain open.

Exact gates:

```text
python3 scripts/typed_air_zig_lane.py --label a013-final-drift-guarded-debug -- /usr/bin/time -l zig build --build-file src/integrations/riscv_cpu/build.zig test-riscv-generated-composition-native-proof -Doptimize=Debug -j1 --summary all
Build Summary: 4/4 steps succeeded; 1/1 tests passed

python3 scripts/typed_air_zig_lane.py --label a013-generated-composition-releasefast-proof -- /usr/bin/time -l zig build --build-file src/integrations/riscv_cpu/build.zig test-riscv-generated-composition-native-proof -Doptimize=ReleaseFast -j1 --summary all
Build Summary: 4/4 steps succeeded; 1/1 tests passed

python3 scripts/typed_air_zig_lane.py --label a014-full-cohort-real-proof-final -- /usr/bin/time -l zig build --build-file src/integrations/riscv_cpu/build.zig test-riscv-lookup-v2-native-proof -Doptimize=Debug -j1 --summary all
Build Summary: 1/1 steps succeeded

python3 scripts/typed_air_zig_lane.py --label a014-releasefast-real-proof -- /usr/bin/time -l zig build --build-file src/integrations/riscv_cpu/build.zig test-riscv-lookup-v2-native-proof -Doptimize=ReleaseFast -j1 --summary all
Build Summary: 1/1 steps succeeded

python3 scripts/typed_air_zig_lane.py --label a014-full-lookup-debug -- /usr/bin/time -l zig build --build-file src/frontends/riscv/build.zig test-lookup-batching -Doptimize=Debug -j1 --summary all
Build Summary: 3/3 steps succeeded; 326/326 tests passed
```

## Update protocol

Every progress update changes:

- status date;
- current milestone and active task;
- dashboard state;
- completed evidence;
- next three actions;
- new risks or decisions; and
- one dated log entry.

At most one task per dependency lane is marked active. Concurrent active tasks
must have explicit file ownership and independent acceptance gates. A task
becomes done only when its acceptance evidence is named.
