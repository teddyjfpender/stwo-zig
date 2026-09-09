# Stage101 leaf route flip: Poseidon provider through the D5 shard batch under one shared relation draw

Date 2026-09-03/04. Branch `autoresearch/metal-ecdsa-subsecond-20260829` on top of `6084a979` (working tree
has today's uncommitted throughput changes; nothing here reverts them). Host: Apple M5 Max, 18 CPUs,
64 GiB, Zig 0.15.2. No part of the route has been built or run — it does not exist yet; every `file:line` is
from the current working tree and every "not verified" is spelled out in Section 9. What WAS run today is the
existing gate set (Section 8's build-health table), which turned up one red gate that changes the plan
(blocker 1, and Step 0).

Companion notes: `autoresearch/notes/2026-09-03-d5-leaf-metal-host-throughput/note.md` (sweep numbers
and oracle), `conformance/2026-09-01-recursive-artifact-pipeline-v1.md` (omitted-provider bundles are
differential/migration gates, not the production 210-leaf plan).

## 0. Verdict and chosen design

Today the Stage101 leaf (`stage101-metal-autoresearch-v1`) proves the 6,671,301 Poseidon2 provider calls
as the native 445-column `poseidon2` infra component inside Tree 1/Tree 2 of the 4-tree V4 core
(`incremental_ethereum_orchestration_v3.provePreparedAfterAdmission`, :346-598; no omission hook).
The D5 sweep proves the same calls as 26 log18 shards in ~3.3 s (Stage A ~1.1 s + Metal prove ~2.2 s)
but under independent per-shard relation draws, so nothing binds them to a leaf.

Chosen design: **Design 0 (additive, opt-in route behind `--provider-route degree5-omit-v1`) as the
landing vehicle**, with the following grafts that all three judges converged on:

| # | Graft | From | Why |
| --- | --- | --- | --- |
| G1 | `...Validated` siblings through the whole omit path (Extension, ProjectionV1, ProviderStageAManifestV1, replayShared, admittedShard, validateBorrowed/takeScheme, Source.validate, closeFreshClaims) land BEFORE the first Metal timing, not as an optional tail step | Design 2 step 1 | Each `ProviderShardPlanV1.validate(calls)` re-hashes all 6.67M calls (~1 s single-threaded: the sweep measured Blake2s call commitment at 0.037 s per 2^18 shard). The non-validated omit path performs ~6 passes per shard per side plus ~6 on the core side; without G1 a first run is dominated by ~5 minutes of re-hashing and measures nothing. Identity-neutral (validation only). |
| G2 | `ProviderOmissionPinsV1`: the residency `Request` becomes comptime constants and its identity is mixed into the route domain | Design 1 step 5 / Design 2 step 3 | `residency_shard_plan.Request.identity` is hashed into `plan.residency.result.request_identity` (`src/prover/pcs/residency_shard_plan.zig:125,159`) which `authority.planIdentity` hashes (`authority.zig:640`); `plan.identity` enters the Frame and therefore the single relation draw. Env-driven host knobs would make proof identity host-dependent (the sweep already documents that 9 owners changed the plan). |
| G3 | A pre-Tree0 `IncrementalOmissionFrameV4` (projection identity + projected bridge geometry) directly after `profile.mixPreTree0`, and a `LeafOmissionAuthorityV4` digest (profile identity, frame identity, shared identity, full statement authority id) in every shard's local prefix and statement wrapper | Design 1 steps 1/4 | Tree 0's column count and every bridge mask offset depend on the projection, so they are fixed before the first root is absorbed; the local-prefix digest blocks relabelling a segment-, candidate- or standalone-route shard proof into this leaf. |
| G4 | STWIOL01 carries the 26 STWD5PR1 shard artifacts after the core proof; the CPU verifier decodes shards from bytes, rebuilds the plan from pins + calls and compares to the decoded fields | Design 1 step 6 / Design 2 step 6 | Makes the closure cold-verifiable from bytes and removes process-local shard structs. Call list stays borrowed from the producer process in phase 1 and is recorded as such. |
| G5 | `additional_registration` becomes optional in `ethereum_main.commitWithoutNativePoseidonWithExternalBlocks` (:155) | Design 2 step 1 | `commitInternal` already handles `additional_registration == null` with projection + blocks (`ethereum_main.zig:237-277`); the bridge issues no fixed-table lookups. Existing callers pass a non-optional value that coerces. |
| G6 | Three-way transcript parity test (orchestration draw == adapter `replayShared` == verifier `verifyRelations`) | all designs | Pins the single Fiat-Shamir order incl. the accepted redundant `mixMainClaim(projected core)` inside `Extension.drawChallenges`. |
| G7 | `verifyMerkleAndPoseidonCancellation` is not called on the omitted route unless `STWO_ZIG_STAGE101_DIAGNOSTIC_CANCELLATION=1` | Design 2 step 4 | It regenerates a full Poseidon interaction table serially (`incremental_transition_v2.zig:90-126`); the shard closure is the authoritative check. New file, so the native path is untouched. |

Explicitly NOT grafted now: Design 2's Metal-concurrent Stage-A/core/shard overlap (shares one runtime and
`OWNER_WINDOWS = 2` composition scratch), the campaign refactor of `replay_command_v4`, the
`batch_execution_v1:278` owner-subset relaxation, profile schema 3, prepared-program reuse, and cold
call re-derivation. They wait until this route has two deterministic runs with pinned identities.

Fail-closed invariants that do not move: `ACTIVATES_PRODUCTION_PROOF=false`, `PRODUCTION_ACTIVE=false`,
`RECURSIVE_VERIFICATION_IMPLEMENTED=false`; `FreshCoreResidualV1`, `VerifiedJointClosureV1`,
`FreshStrategyV1` all reject `production_eligible=true` / `recursive_admissible=true`
(`ethereum_omit_protocol_v1.zig:90-99,131-145`). The native leaf path, `orchestration_v3.zig`,
`verifier_v3.zig`, the STWIEF04 codec and the pinned native artifact `20baa3ae...`/57,928,628 bytes stay
byte-identical.

## 1. Verified facts the plan rests on (read in the working tree)

- `ProjectionV1.init` admits via `ethereum_admission.validateV2(full_native, extension, policy)`
  (`native_provider_omit_v1.zig:54-74`), the same function the V4 prepared orchestration calls at
  `orchestration_v3.zig:318` (`proof_admission.validateV2(expected_statement, prepared.extension, .proof)`).
  `deriveFullGeometry` requires unique program/merkle/poseidon2/clock_update descriptors with
  `merkle_index + 1 == poseidon_index` (`:331-340`). The V4 registry order is program, memory, merkle,
  poseidon2, clock (`base_component_assembly.zig:35-45`). Not run-verified on the segment-1 statement.
- `Extension(Engine)` (`ethereum_omit_protocol_v1.zig:239-663`): `init` re-validates the manifest
  (`:254-265`), `prepareProjectedCore(native, extension, manifest, authenticated, workspace_core,
  full_geometry)` installs the projected core into the workspace (`:278-304`), `drawChallenges` requires
  exactly two committed trees and calls `ethereum_transcript.proveToRelationsWithExtension` with the
  canonical `Frame` (`:501-531`), `verifyRelations` replays it (`:533-563`), `recordFreshVerifierAuthority`
  mints `FreshCoreResidualV1` (`:403-429`). `validateProjectedAuthority` (`:641-663`) requires
  `core == projection.projected_native.core`.
- `proveProviderPreparedWithTranscriptV2(Engine, TranscriptAdapter, alloc, pcs, program, ExecutionProfileV2,
  source: anytype, shard_index, prepared)` and `verifyProviderFreshWithTranscriptV2(...)`
  (`degree5_ethereum_omit_provider_proof_v1.zig:220-232, 526-549`) are the seams; the adapter contract is
  `replayShared(Engine, alloc, pcs, source) !protocol.Replay(Engine)` and
  `providerLocalPrefix(Engine, alloc, pcs, source, claim, ordered) !Engine.Channel` (`:906-935`,
  candidate template `degree5_ethereum_candidate_provider_v1.zig:634-689`).
- The internal prover passes `validated_calls = null` into `transaction.validateBorrowed` and
  `takeScheme` (`:271-303`); `validateBorrowedInternal` compares `self.validated_calls != validated_calls`
  by pointer (`degree5_provider_stage_a_transaction_v1.zig:241`), so today only `prepared_batch.prepareParallel`
  (non-Validated) transactions are consumable. `takeSchemeValidated`/`validateBorrowedValidated`/
  `harness.admittedShardValidated` already exist (`:204, :300`, `proof_harness.zig:401`).
- `closeFreshClaimsV2(Engine, alloc, program, ExecutionProfileV2, source: Source(Engine), core, providers)`
  takes the concrete ordinary `Source(Engine)` (`:774-855`); `Source.validate` runs manifest and
  projection validation (`ethereum_omit_provider_proof_v1.zig:61-95`).
- `ProviderStageAManifestV1.createFromRoots(alloc, plan, calls, roots)` re-validates the plan and again
  in `Self.init` (`ethereum_omit_protocol_v1.zig:177-199`).
- `Frame.mixInto` order: `frame_domain_words` (7 words incl. the three protocol flags), projection identity,
  manifest identity, plan identity, session, call_list_commitment, `providers.len`, per record (identity,
  descriptor identity, shard_index, shard_count, first_call, call_count, expected_log_size, mixRoot(pre),
  mixRoot(main)), mixRoot(T0), mixRoot(T1) (`:874-903`). `appendProviderLocalFrameV2` (`:826-866`).
- `proveToRelationsWithExtension`/`verifyToRelationsWithExtension` both start with `mixMainClaim(core)`
  (`ethereum_transcript.zig:71-85, 100-113`), then `extension.mixInto`, grind/verify 16-bit PoW, `mixU64`,
  `Relations.draw`.
- `AuthorityV4.mixPreTree0` ends with the FULL-prefix `bridge_geometry.mixFieldAuthority` and the profile
  identity (`profile_v4.zig:161-221`); `mixPostTree1` mixes the full core main claim + shard manifest,
  extension, POST_TREE1 words, full-prefix bridge geometry, profile identity (`:226-244`). The bridge
  placement is `GeometryV3.canonicalAfterPrefix(n_rows, prefix)` with absolute offsets after the full prefix
  (`incremental_bridge_external_v3.zig:77-104`; verifier recomputes it at `verifier_v3.zig:593-619`).
  `PreprocessedTraceV3/MainTraceV3/InteractionTraceV3.init` use only `log_size`/`n_rows`.
- `FreshVerifiedCaptureV4.validate` re-derives the bridge placement from the FULL statement
  (`verifier_v3.zig:117-123`), so the omitted route must not return a V4 capture.
- Omission-aware generators exist: `ethereum_preprocessed.generateWithoutNativePoseidonV2WithExternalBlocks`
  (`:163`), `ethereum_main.commitWithoutNativePoseidonWithExternalBlocks` (`:139`, non-optional
  registration), `ethereum_interaction.generateAndCommitWithoutNativePoseidonAuthenticatedLookupV2WithExternal`
  (`:197`), `ethereum_assembly.createWithoutNativePoseidonAuthenticatedLookupV2` (`:109`),
  `ethereum_cancellation.residualWithoutNativePoseidonV2` (`:74-105`, no bridge/public-sum term).
- `PreparedProofTransactionV4.validateBorrowed` requires `geometry.statement.core == workspace.statement`
  (`prepared_proof_transaction_v4.zig:640-643`); `providerCallView()` returns `calls`, `calls_owner_ptr`,
  `source_identity_sha256` (hash of program source identity, inventory, boundary sha, profile identity,
  wire id; `:687-710, 881-902`).
- Stage101 leaf `run()` forwards `arguments` untouched to `replay_command.runPreparedWithEnginesAndExecution`
  (`stage101_leaf_autoresearch_v1.zig:195-266`); `runPreparedVisitor(alloc, arguments, visitor)` exists
  (`replay_command_v4.zig:249-265`) and hands the visitor `PreparedVisitorCustodyV1{segment_index,
  public_wire, elf, program_source_identity_sha256}` + transaction + call view + evidence (`:71-124`).
- Sweep plan construction and env (`stage101_degree5_provider_sweep_v1.zig:376-397, 653-711`); the
  execution authority requires `concurrent_owners == admitted_parallel_shards`
  (`batch_execution_v1.zig:278`); `ExecutionProfileV2 = execution.executionProfile(program)`.
- Bundle v25 at `/private/tmp/stwo-metal-poseidon-aot-v25.hizW2m/share/stwo-zig/metal/core` matches the
  pins in both commands (manifest `fee0bfb9...`, metallib `c9a87203...`, source `c2daaaf7...`, air
  `bf21cda5...`, 166 exports); the leaf pins only manifest + metallib. Campaign inputs and the
  `20baa3ae` reference artifact exist at the paths in the context brief.
- Ordinary admission cannot accept a projected core: `statement_validation.validateGeometry` requires
  `n_infra >= 10` (`:242`) and the exact infra layout `program | memory* | merkle | poseidon2 | clock_update |
  lookup tables` with `index + 3 + LOOKUP_TABLE_COUNT == n_infra`, `poseidon_desc.kind == .poseidon2`,
  `n_columns == 445`, `n_rows == merkle_desc.n_rows` (`:281-299`). Every codec or authority that runs
  `ethereum_proof_admission.validateV2` must therefore be handed the FULL statement; this is exactly why
  STWIOL01 encodes the full statement in section 0 and only the claims against the projected core, and it is
  the cause of blocker 1 (the SegmentV2 omit test encodes a projected statement and is red today).
- Build health re-checked on the current tree at 2026-09-04 (numbers and the one failure in Section 8):
  `zig fmt --check` clean on all 38 modified `.zig` files; the Metal contract steps
  `test-stage101-leaf-autoresearch-v1` and `test-stage101-degree5-provider-sweep-v1` pass;
  `test-riscv-ethereum-provider-omitted-leaf-bundle`,
  `test-riscv-ethereum-incremental-full-leaf-replay-producer-v4` and
  `test-ethereum-candidate-degree5-provider-batch-v1` pass, while
  `test-ethereum-segment-transcript-extension` FAILS (blocker 1). Every build step this plan names exists in
  `zig build --help` today.

## 2. Ordered implementation steps

Effort is an estimate for one engineer; each step ends with `zig fmt` on its files and the listed tests.

### Step 0 (~1 h): decide the fate of the red omit gate before anything else

`test-ethereum-segment-transcript-extension` fails today (blocker 1). Pick one, and record the choice in the
receipt's `known_red_baselines` field: (a) apply blocker 1's smallest fix (the omitted arm asserts on prove
output + fresh verify + closure and skips the ordinary SegmentV2 artifact encode, which the omitted core has
no canonical envelope for), turning the gate green and giving Step 1 a usable fixture; or (b) leave it red and
pin its exact failure (step name, assertion site, error) as a baseline so a regression in the omit protocol is
still detectable. Option (a) is preferred and cheap; option (b) is acceptable only if the failing leg is
untouched by Steps 1-8. Either way, no step in this plan may claim that gate as green evidence.

### Step 1 (G1, ~10 h): validated fast paths through the omit path, identity-neutral

Files: `src/frontends/riscv/prover/memory_provider_shards/{ethereum_omit_protocol_v1.zig,
native_provider_omit_v1.zig, ethereum_omit_provider_proof_v1.zig, degree5_ethereum_omit_provider_proof_v1.zig,
authority.zig}`.

Additive siblings only; every existing function stays byte-identical:

- `ProjectionV1.initValidated(..., validated: *const OwnedValidatedPlanCallAuthorityV1, ...)` and
  `validateAgainstValidated(...)`: replace the `plan.validate(calls)` in `validateAgainstAfterAdmission`
  (`native_provider_omit_v1.zig:227`) and in `initAfterAdmission` with `validated.validateBorrowed(plan, calls)`;
  keep `ethereum_admission.validateV2` (cheap).
- `ProviderStageAManifestV1.createFromRootsValidated / initValidated / validateBorrowedValidated`
  (`ethereum_omit_protocol_v1.zig:158-223`).
- `Extension.initValidated`, `initForFreshVerifyValidated` (store `validated: ?*const ...`),
  `prepareProjectedCoreValidated`, `drawChallenges`/`verifyRelations` consult the stored token in
  `validateProjectedAuthority` when present.
- `replaySharedTranscriptValidated`, `providerLocalPrefixValidatedV2` (`:701-821`).
- `ethereum_omit_provider_proof_v1.Source` gains `validated_calls: ?*const OwnedValidatedPlanCallAuthorityV1 = null`;
  `validate()` uses it when present; `closeFreshClaimsV1` -> `authority.verifyAggregateClosureValidated`
  (`authority.zig:516-561`, replace the internal `plan.validate(calls)`).
- `degree5_ethereum_omit_provider_proof_v1`: `proveProviderPreparedValidatedWithTranscriptV2` and
  `verifyProviderFreshValidatedWithTranscriptV2` thread `validated_calls` into the two internal functions
  (`harness.admittedShardValidated`, `transaction.validateBorrowedValidated`, `takeSchemeValidated`).
- `authority.zig:22-28` header constants (`CALLER_N_MANIFEST_IMPLEMENTED`, `ORDERED_CALL_COMMITMENT_IS_AIR_PROVED`
  still `false` while the degree5 proof asserts them true): correct as constants with a comptime cross-check;
  no activation semantics.

Tests: parity test in `src/integrations/riscv_cpu/ethereum_omit_validated_parity_v1_test.zig` — validated
vs unvalidated on the SegmentV2 fixture of `ethereum_segment_transcript_extension_test.zig` produce identical
shard proof bytes, identical `SharedRelationAuthorityV1`, identical closure identity, and
`WorkReceiptV1.full_corpus_validations == 1` per side. The comparison must stop at the prove outputs and the
closure — it must NOT reuse that fixture's artifact encode/decode leg, which is red today (blocker 1). The
existing `test-ethereum-segment-transcript-extension` must stay exactly as red as it is now (same single
failing assertion, same failure chain) and no more.

### Step 2 (G2+G3, ~4 h): route protocol module (pins, pre-Tree0 frame, leaf omission authority)

File: `src/frontends/riscv/prover/incremental_ethereum_omit_protocol_v4.zig` (new; export from
`guest_precompile/mod.zig` next to `ethereum_native_provider_omit_protocol_v1`, `mod.zig:37-39`).

- `ProviderOmissionPinsV1` (comptime): `shard_log_size = 18`, `requested_parallel_shards = 18`,
  `log_blowup_factor = Q193_FRI_LOG_BLOWUP_FACTOR (1)`, `retention_policy = .always`,
  `host_byte_budget = 51_539_607_552`, `reserved_host_bytes = 8_589_934_592`, `column_count = 445`,
  `execution_owners = 18`, `engine_workers_per_owner = 1`, `non_column_reserve_per_owner = 536_870_912`.
  `request(total_call_count) residency_shard_plan.Request` and `identity_sha256` (domain
  `stwo-zig/riscv/ethereum/incremental-omission-pins/v1\0`). Comptime pin that `request(n).identity()`
  is a pure function of `n`.
- `IncrementalOmissionFrameV4 { format = 1, projection_identity, projected_bridge_geometry: GeometryV3,
  pins_identity, identity }` with `canonical(projection, bridge_n_rows, projected_prefix)` and
  `mixInto(channel)`: words `[0x5749_5453 'STIW', 0x3456_4d4f 'OMV4', 1, @intFromBool(ACTIVATES_PRODUCTION_PROOF)]`,
  projection identity (8 LE u32), pins identity, then `projected_bridge_geometry.mixFieldAuthority(channel)`.
- `projectedBridgeGeometry(full_bridge: GeometryV3, projected_core, extension, authenticated, manifest) !GeometryV3`
  = `GeometryV3.canonicalAfterPrefix(full_bridge.n_rows, PrefixColumnsV3{ preprocessed =
  projected_core.nPreprocessedColumns() + sum(eth.preprocessed_columns), main = projected_core.nMainColumns()
  + sum(eth.main_columns), interaction = authenticated.totalInteractionColumns(projected_core, manifest) +
  sum(eth.interaction_columns) })` with checks `log_size`/`n_rows` equal to the full geometry and placement
  deltas exactly (2, 445, 8).
- `LeafOmissionAuthorityV4 { format, profile_identity_sha256, frame_identity, shared_identity,
  full_statement_authority_id: [8]u32, identity }` (domain
  `stwo-zig/riscv/ethereum/incremental-leaf-omission/v4\0`).
- `residualIncrementalV4(public_sum, projected_canonical_total, extension_claim, bridge_claim) QM31`
  = `public_sum + total + extension.componentSum() + bridge_claim` (sign convention of
  `logup.verifyGlobalCancellation`: boundary + sum(claims) == 0, so the omitted native claim would be `-r`).

Unit tests: placement arithmetic on a synthetic prefix; pins identity determinism; frame identity changes
when any field changes.

### Step 3 (G5, ~0.5 h): optional registration

`ethereum_main.zig:155` `additional_registration: ?external_tree.LookupRegistration`. Callers that pass a
value coerce; the omitted route passes `null`. Non-regression: `test-riscv-ethereum-candidate-leaf-proof`
(the only current caller family) and `test-riscv-ethereum-incremental-full-leaf-proof-v4`.

### Step 4 (~10 h): V4 omitted-provider orchestration and verifier (new frontend file)

File: `src/frontends/riscv/prover/incremental_ethereum_omit_orchestration_v4.zig` (new); export as
`testing.incremental_ethereum_omit_orchestration_v4_internal` next to `testing.zig:244`.

`provePreparedOmittedProviderWithEngineUsingChannel(Engine, alloc, pcs, exec_trace, opt_chain, full_witness,
expected_statement, role_aware_public, keccak_calls/rows, recovery_calls/rows, prepared: PreparedProofInputsV4,
profile, recorder, channel, execution, extension: *Extension(Engine), options: OmittedRouteOptionsV1)
!ProveOutputV4Omitted(Engine)`:

1. Admission prologue copied verbatim from `provePreparedWithEngineUsingChannel` (`orchestration_v3.zig:264-322`,
   including `proof_admission.validateV2`).
2. `manifest = Manifest.native()`, `authenticated = AuthenticatedStatement.init(&workspace.statement /*full*/, &manifest)`;
   `profile.validateAgainstStatement(&built.statement, extension, role_aware_public)`.
3. `extension.prepareProjectedCoreValidated(&built.statement, ext, &manifest, &authenticated, &workspace.statement,
   built.base)`; `defer workspace.statement = full_core_copy` (restores the transaction invariant
   `geometry.statement.core == workspace.statement`); require `workspace.statement == projection.projected_native.core`.
4. `projected_bridge = projectedBridgeGeometry(profile.bridge_geometry, ...)`; `frame_v4 =
   IncrementalOmissionFrameV4.canonical(...)`.
5. Transcript: `profile.mixPreTree0(&built.statement, role_aware_public, channel)`; `frame_v4.mixInto(channel)`.
6. `Engine.init`, retention `.never`; bridge Tree0 block from `&profile.bridge_geometry` (init uses only
   `log_size`/`n_rows`); `tree0 = ethereum_preprocessed.generateWithoutNativePoseidonV2WithExternalBlocks(alloc,
   &projection, &built.statement, ext, &tree0_blocks)`; `Engine.commit`.
7. `tree1_logs = ethereum_main.logSizesWithExternalBlocks(alloc, &workspace.statement /*projected*/, ext, &tree1_blocks)`;
   `requireTree1Residency`; `retained = ethereum_main.commitWithoutNativePoseidonWithExternalBlocks(Engine, alloc,
   workspace, &scheme, channel, recorder, exec_trace, &full_witness.base, built.base, opt_chain, witness,
   keccak_calls.records(), recovery_calls.records(), &projection, &tree1_blocks, null)`.
8. `profile.mixPostTree1(&built.statement, role_aware_public, channel)`; `try Engine.flushPendingCommit(&scheme,
   alloc, channel)` (no-op unless a deferred first tree is pending);
   `prefix = extension.drawChallenges(alloc, &scheme, channel, &built.statement, &workspace.statement, ext,
   &manifest, &authenticated, recorder)`; `leaf_omission = LeafOmissionAuthorityV4.canonical(profile.identity_sha256,
   frame_v4.identity, extension.shared_relation.?.identity, built.statement.authority_id)`.
9. `if (options.diagnostic_cancellation) full_witness.boundary.verifyMerkleAndPoseidonCancellation(&prefix.relations.base)`
   (default off; G7).
10. Bridge Tree2 from `prefix.relations.base` with `&profile.bridge_geometry`; `extension_claim =
    ethereum_interaction.generateAndCommitWithoutNativePoseidonAuthenticatedLookupV2WithExternal(Engine, ...,
    &full_witness.base, built.base, &retained.lookup_source, &prefix, witness, pool, base_claim, &manifest,
    &authenticated, &projection, &bridge_columns, BridgeClaimMix{...}, mixBridgeClaim)` (this mixes
    `mixInteractionClaimV2(projected core)` then the bridge claim, then commits Tree 2).
11. `projection.validateAgainstValidated(...)`; `residual = residualIncrementalV4(incremental_public.sum(...),
    authenticated.canonicalInteractionClaim(&projection.projected_native.core, &manifest, base_claim).view().total(),
    extension_claim, bridge_claim)`; `extension.recordProverResidual(residual)` (diagnostic; replaces
    `logup.verifyGlobalCancellation`).
12. `proof_finalize.assembleAuthenticatedLookupV2WithIncrementalBoundaryV3(workspace /*projected*/, ...)` (the base
    registry iterates the workspace `infra_descs`, so no `.poseidon2` HashComponent is created — same reliance as the
    SegmentV2 omit route, not yet exercised for the V3-boundary variant);
    `ethereum_assembly.Assembly(.prover).createWithoutNativePoseidonAuthenticatedLookupV2(alloc, &projection,
    &built.statement, ext, &prefix.relations, base_components, &extension_claim, &manifest, &authenticated)`;
    `incremental_bridge.Assembly(.prover).create(alloc, ethereum_components.active(), &projected_bridge, roots.entry,
    roots.exit, &prefix.relations.base, bridge_claim)`; `Engine.prove` unchanged.
13. Output: `ProveOutputV4` fields plus `projection`, `projected_bridge_geometry`, `frame_v4`, `leaf_omission`,
    `shared_relation: SharedRelationAuthorityV1(Engine)`, `prover_residual: QM31`.

`verifyOmittedProviderWithEngineUsingChannel(Engine, Profile, alloc, statement_value, extension_statement,
role_aware_public, profile, proof_in, base_claim, extension_claim, bridge_claim, omission: DecodedOmissionV1,
channel, extension: *Extension(Engine) /*initForFreshVerifyValidated, projection already prepared by the caller*/)
!FreshOmittedCoreV4(Engine)`: copy of `verifier_v3.zig:252-505` with: `statement.validate`, `extension.validateV2`,
`profile.validateAgainstStatement(full)`; require `extension.projection_ready` and
`projection.validateSealAndFull(full, ext)`; `base_claim.n_infra == projected_core.n_infra` else `InvalidStructure`;
`projected_bridge` recomputed and compared to `omission.projected_bridge_geometry`; `frame_v4` recomputed and compared;
tree log sizes on the projected core (`ethereum_preprocessed/main/interaction.logSizes...` take `*const RiscVStatement`);
Tree0 root recomputed with `generateWithoutNativePoseidonV2WithExternalBlocks` and compared to `commitments[0]`;
`profile.mixPreTree0`, `frame_v4.mixInto`, commit T0, T1, `profile.mixPostTree1`, `relations = extension.verifyRelations(alloc,
pcs, channel, full, &projected_core, ext, &manifest, &authenticated, base_claim.interaction_pow, commitments[0], commitments[1])`
(rejects a shared-authority mismatch against the expected value), `mixInteractionClaimV2(channel, &projected_core, ...)`,
`incremental_bridge.mixClaim`, commit T2; `fresh_residual` computed before the STARK from `VerifiedPublicSumsV4.total`;
verifier components via `base_verifier.assembleComponentsAuthenticatedLookupV2WithIncrementalBoundaryV3(workspace,
&projected_core, ...)`, `Assembly(.verifier).createWithoutNativePoseidonAuthenticatedLookupV2`, bridge with the projected
geometry; `core_verifier.verify` (no ProofCapture); on success
`extension.recordFreshVerifierAuthority(fresh_residual, extension.proofCommitmentsIdentity(commitments))`.
Returns `{ fresh_core: FreshCoreResidualV1, shared, relations, leaf_omission, transcript_after_relations_digest,
transcript_final_digest, draw_count }`.

Small private helpers (`validateClockAuthority`, `BridgeClaimMix/mixBridgeClaim`, `freeColumns`, `prefixColumns`,
`verifyPreprocessedRoot`) are duplicated into the new file rather than exported from the native files.

### Step 5 (~5 h): V4 shared-transcript source and adapter for D5 shard proofs

File: `src/integrations/riscv_cpu/ethereum_incremental_omitted_provider_transcript_v1.zig` (new).

- `SourceV1(Engine)`: ordinary `Source(Engine)` fields (native, extension, lookup_manifest, authenticated_lookup
  (full core), projection, plan, calls, validated_calls, provider_stage_a, shared) plus
  `profile: *const AuthorityV4`, `role_aware_public`, `projected_bridge: GeometryV3`, `frame_v4`, `leaf_omission`,
  `pcs_config`. `validate()` = ordinary validated `Source.validate()` + `profile.validateAgainstStatement` +
  recompute `projected_bridge`/`frame_v4`/`leaf_omission` and require equality. `ordinary()` returns the ordinary
  `Source(Engine)` with `retirement_supplement = null` (for `closeFreshClaimsV2`).
- `Stage101TranscriptAdapterV1.replayShared`: `source.validate()`; `channel = Engine.Channel{}`;
  `profile.mixPreTree0(native, role_aware_public, &channel)`; `frame_v4.mixInto(&channel)`;
  `MerkleChannel.mixRoot(shared.tree0_root)`; `mixRoot(shared.tree1_root)`; `profile.mixPostTree1(...)`;
  `relations = ethereum_transcript.verifyToRelationsWithExtension(alloc, &channel, &projection.projected_native.core,
  shared.interaction_pow, ProviderFrameV1(Engine){...})`; require
  `PoseidonRelationContextV1.canonical(plan.session, z, alpha) == shared.relation_context` else
  `error.EthereumProviderRelationContextMismatch`; return `Replay{channel, relations, authority_value = shared}`.
- `providerLocalPrefix`: `replayShared`, then `appendProviderLocalFrameV2(&channel, plan, provider_stage_a,
  shared.relation_context.identity, claim, ordered)`, then route words `[0x5749_5453 'STIW', 0x3456_4c50 'PLV4', 1, 0]`,
  `mixDigest(leaf_omission.identity)`, `mixDigest(pins identity)`.
- `LeafProviderStatementV4 { leaf_omission_identity, provider: ProviderStatementV1, identity }` (statement wrapper as
  `makeCandidateStatement`, `degree5_ethereum_candidate_provider_v1.zig:701-720`).
- Engine retype helpers: `retypeStageARoots(From, To, roots)`, `retypeSharedRelation(From, To, value)` (field copy;
  comptime assert `From.Hasher == To.Hasher and From.Channel == To.Channel and From.MerkleChannel == To.MerkleChannel`,
  as `order_batch_v1.zig:317-324`), `manifestForVerifier = ProviderStageAManifestV1(Cpu).createFromRootsValidated(...)`
  with an identity-equality check against the Metal-typed manifest.

### Step 6 (~5 h): shared-transcript D5 batch prover/verifier

File: `src/integrations/riscv_cpu/ethereum_candidate_degree5_provider_shared_batch_v1.zig` (new; skeleton copied from
`ethereum_candidate_degree5_provider_order_batch_v1.zig:125-247, 249-367, 369-568`).

- `EncodedSharedShardV1 { statement: LeafProviderStatementV4, execution_profile_identity, stwd5pr1_bytes, sha256 }`
  produced by `ethereum_degree5_provider_proof_artifact_v1.encodeAlloc(Engine, alloc, pcs, profile.identity,
  statement.provider, proof, limits)` (`:72-131`; canonical postcard + statement_size 370 preflight).
- `proveSharedPreparedParallelValidated(ProducerEngine, alloc, pcs, program, profile: ExecutionProfileV2, source: SourceV1,
  validated, prepared: *OwnedPreparedBatchV1, execution)`: preconditions `source.validate()`,
  `execution.validateAgainstPlan(plan)`, `profile == execution.executionProfile(program)`,
  `prepared.validatePreparedValidated(...)`; per shard on `std.heap.smp_allocator`
  `proveProviderPreparedValidatedWithTranscriptV2(Engine, Stage101TranscriptAdapterV1, ...)`, encode, destroy the proof;
  after the pool `prepared.validateConsumed()`; `validateCanonical(plan, shared.identity)` checks
  `shard_index == index`, `descriptor_identity`, `relation_context_identity == shared.relation_context.identity`,
  `manifest_identity == provider_stage_a.identity`, `leaf_omission_identity`, byte cap
  `MAX_CANONICAL_PROOF_BYTES_PER_SHARD`.
- `verifySharedFreshParallelValidated(ProducerEngine, CpuVerifierEngine, ..., source_cpu: SourceV1(Cpu), shards, execution)
  !OwnedFreshSharedBatchV1 { claims: []FreshDegree5ProviderClaimV1 }`: per shard `decodeAlloc` (STWD5PR1), require decoded
  statement == wrapped statement and `leaf_omission_identity == source_cpu.leaf_omission.identity`,
  `verifyProviderFreshValidatedWithTranscriptV2(Cpu, Stage101TranscriptAdapterV1, ...)`; `validateAgainst(plan)` requires
  every `claim.shared_core_relation_context_verified == true` and `claim.provider.native_claim.shard_index == index`.

### Step 7 (~1.5 h): omitted prove entry on the prepared transaction

File: `src/integrations/riscv_cpu/ethereum_incremental_full_leaf_prepared_proof_transaction_v4.zig` (one method + import).

`pub fn proveOmittedProviderWithEngineUsingChannel(self, Engine, alloc, recorder, channel, execution, extension, options)`
next to `proveWithEngineUsingChannel` (`:715-752`): `view = try self.proofView()`; require
`extension.calls.ptr == self.storage.prepared_witness.full.base.poseidonCalls().ptr` and equal len (pointer custody, as
`ProviderCallViewV1.validateAgainst`); call the Step 4 prover; debug-assert `validateBorrowed()` passes after the prove
(workspace core restored). No change to `initOwned`, codec guards, or the comptime block.

### Step 8 (G4, ~6 h): STWIOL01 envelope (core + omission section + 26 shard artifacts)

File: `src/integrations/riscv_cpu/ethereum_incremental_omitted_leaf_proof_artifact_v1.zig` (new; copied from
`ethereum_incremental_full_leaf_proof_artifact_v4.zig`).

Header: `MAGIC = 'STWIOL01'`, format 1, schema 1, u64 total length, u64 section lengths,
`CONTENT_DOMAIN = "stwo.ethereum.incremental-omitted-leaf-proof.v1\0"`, SHA-256 seal. Sections:

| # | content |
| --- | --- |
| 0 | full statement (statement_wire, unchanged) |
| 1 | role-aware public (unchanged) |
| 2 | extension (fixed size, unchanged) |
| 3 | profile `AuthorityV4` schema 2 bound to the FULL statement (unchanged encoder) |
| 4 | omission section (LE, fixed layout): omit protocol format, `ProviderOmissionPinsV1` fields + identity, `projection.identity`, `omitted_infra_index`, omitted descriptor {kind, log_size, n_rows, n_columns}, `projected_native.authority_id` [8]u32, `plan.identity`, `plan.session`, `plan.call_list_commitment`, `plan.total_call_count`, `shard_count`, per shard {descriptor_identity, first_call u64, call_count u32, expected_log_size u32, preprocessed_root, main_root}, `provider_stage_a.identity`, `interaction_pow` u64, `relation_context` {identity, z, alpha as 8 M31 words}, `shared.identity`, `projected_bridge_geometry` {n_rows, log_size, placement x4, totals x3, identity}, `frame_v4.identity`, `leaf_omission.identity`, D5 `air_program_identity`, `execution_profile_identity` |
| 5 | claims: `ethereum_wire.encodeClaim(writer, &projection.projected_native.core, extension, base_claim, extension_claim)` + bridge QM31 |
| 6 | postcard core proof (4 commitments) |
| 7..7+N | N STWD5PR1 shard artifacts, u64 length-prefixed, canonical shard order |

`encodeAlloc` requires `profile.validateAgainstStatement(full)`, `projection.validateSealAndFull(full, ext)`,
`base_claim.n_infra == projected_core.n_infra`, `N == shard_count`. Decode is two-phase:
`decodeAllocWithRetainedLease(...)` returns statement/public/extension/profile/omission/core proof/shard byte slices and the
raw claim bytes; after the verifier's `Extension.prepareProjectedVerifierCore` the caller runs
`decoded.decodeClaims(alloc, &projection.projected_native.core, &extension)` and
`decoded.omission.validateAgainst(projection, plan, provider_stage_a, shared_cpu, projected_bridge, frame_v4, leaf_omission)`
(every field equal; the plan is the one rebuilt from pins + calls, never the decoded shards). The STWIEF04 decoder must reject
the STWIOL01 magic and vice versa (test).

### Step 9 (~8 h): Metal opt-in command module, flag dispatch, build wiring, facade exports

Files: `src/integrations/riscv_metal/stage101_leaf_degree5_provider_v1.zig` (new),
`src/integrations/riscv_metal/stage101_leaf_autoresearch_v1.zig` (run(): strip the `--provider-route <value>` pair before
forwarding; `degree5-omit-v1` delegates, `native`/absent is the unchanged path), `src/integrations/riscv_metal/build.zig`
(add the module to `stage101_module`'s imports, add tests to the filter list), `src/integrations/riscv_cpu/stage101_degree5_metal_facade.zig`
(export `ethereum_candidate_degree5_provider_shared_batch_v1`, `ethereum_incremental_omitted_provider_transcript_v1`,
`ethereum_incremental_omitted_leaf_proof_artifact_v1`, `ethereum_incremental_full_leaf_profile_v4`,
`ethereum_incremental_full_leaf_proof_v4`, `ethereum_incremental_full_leaf_prepared_proof_transaction_v4`); the leaf
module additionally imports `stwo_riscv_cpu_stage101_degree5_metal` (build.zig:35-38 already creates it).

`run(alloc, arguments)`: env = leaf `STWO_ZIG_STAGE101_WORKER_COUNT/HOST_BYTE_BUDGET/HOST_BYTE_LIMIT` +
`STWO_RISCV_METAL_AOT_BUNDLE`; NO `STWO_ZIG_D5_PROVIDER_*` (pins now); validate the four AOT SHAs + 166 exports as the sweep;
init runtime; `replay_command.runPreparedVisitor(alloc, forwarded_args, visitor)`. `visit(custody, transaction, call_view, evidence)`:

1. Sweep prologue verbatim (custody/call view/evidence validation, retained-source pins, `plan = ProviderShardPlanV1.create(
   session = call_view.source_identity_sha256, calls, pins.request(total))`, `producer_calls = OwnedValidatedPlanCallAuthorityV1.init`,
   `execution = AuthorityV1.initAgainstPlan(host, &plan, pins as RequestV1)`, `TopologyReceiptV1`, `requireFirstArm`,
   `program = VerifierProgramAuthorityV2.coldCompile`, `exec_profile = execution.executionProfile(program)`).
2. Stage A: `prepared = prepared_batch.prepareParallelValidated(MetalEngine, ...)`;
   `owned_manifest = ProviderStageAManifestV1(MetalEngine).createFromRootsValidated(alloc, &plan, calls, &producer_calls, prepared.roots())`.
3. Core: `var extension = Extension(MetalEngine).initValidated(&plan, calls, &producer_calls, &owned_manifest.manifest)`;
   `channel = MetalEngine.Channel{}`; `output = transaction.proveOmittedProviderWithEngineUsingChannel(MetalEngine, alloc,
   recorder, &channel, policy.executionOptions(), &extension, .{ .diagnostic_cancellation = env flag })`.
4. Shards: `source_metal = SourceV1(MetalEngine){...}` from `view = transaction.proofView()`, `output`, `plan`,
   `producer_calls`, manifest; `shards = shared_batch.proveSharedPreparedParallelValidated(MetalEngine, ...)`.
5. Encode STWIOL01 (core + omission + shards); destroy `output.proof`, `prepared`, Metal-typed manifest; keep bytes + POD
   authorities only (`producer_proofs_destroyed_before_cpu_decode = true`).
6. CPU fresh verify: phase-1 decode; `plan_cpu = ProviderShardPlanV1.create(session, call_view.calls, pins.request(total))`
   and require `plan_cpu.identity == decoded.plan_identity` and every decoded shard record equals the record rebuilt from
   `plan_cpu` + decoded roots; `fresh_calls = OwnedValidatedPlanCallAuthorityV1.init(&plan_cpu, calls)`;
   `manifest_cpu = ProviderStageAManifestV1(Cpu).createFromRootsValidated(...)` with identity equal to the producer's;
   `shared_cpu = retypeSharedRelation(...)`; `verify_ext = Extension(Cpu).initForFreshVerifyValidated(&plan_cpu, calls,
   &fresh_calls, &manifest_cpu.manifest, shared_cpu)`; `verify_ext.prepareProjectedVerifierCore(...)`;
   `decoded.decodeClaims(...)`; `decoded.omission.validateAgainst(...)`; `fresh_core_result = verifyOmittedProviderWithEngineUsingChannel(Cpu, AuthorityV4, ...)`;
   `source_cpu` from decoded full statement/extension/profile/public + `verify_ext.projection` + `manifest_cpu` + `verify_ext.shared_relation.?`;
   `fresh_shards = shared_batch.verifySharedFreshParallelValidated(...)`;
   `closed = closeFreshClaimsV2(Cpu, alloc, program, exec_profile, source_cpu.ordinary(), verify_ext.fresh_core.?, fresh_shards.claims)`;
   require `closed.closure.closed_sum.isZero()`, `closed.closure.validate()`, `closed.strategy.validate()`,
   `output.prover_residual == fresh_core.poseidon2_residual`.
7. Metal lifecycle/telemetry as the leaf (`validateAuthenticatedLifecycle`, identity unchanged,
   `delta.requireResidentRiscPolynomialExecution`, `validateRequiredKernelCoverage` over the whole run plus
   `base_batch_dispatches >= 26 and lookup_batch_dispatches >= 26`); host placements recorded, not pinned, on the first run.
8. Receipt (Section 4) sealed like the sweep and `artifact_io.publishCreateOnlyDurable(output_path)`; THEN
   `ProviderRouteBudgetV1.validate` fails closed (`Stage101ProviderRouteBudgetExceeded`), exactly like the leaf's
   receipt-then-budget order (`:170-188`).

### Step 10 (~8 h): tests and build steps (Section 5)

### Step 11 (~3 h): Metal run, oracle pins, note (Section 6)

Total ~62 h before the first Metal timing; Step 0 (~1 h) and the G1 prerequisite (Step 1, ~10 h) come first.
Hard ordering: 0 -> 1 -> {2, 3} -> 4 -> {5, 7} -> 6 -> 8 -> 9 -> 10 -> 11. Steps 2/3 and 5/7 are the only
pairs that can be worked in parallel.

## 3. Exact transcript and binding order

All channels are `Engine.Channel` (q193 Poseidon2 channel); `MetalEngine` and `CpuVerifierEngine` share
`Hasher/Channel/MerkleChannel` (comptime-asserted, `order_batch_v1.zig:317-324`). Producer core, CPU core verifier and
every shard prover/verifier must be at byte-identical channel states at the relation draw (G6 test).

Core channel C (prove; the verifier replays [1]-[8] with `verifyRelations` at [6]):

1. `AuthorityV4.mixPreTree0(full_statement, role_aware_public, C)` — unchanged (`profile_v4.zig:161-221`): pcs config, native
   public transcript, lookup activation, `PRE_TREE0 [STIW, ELF4, 4, 2]`, header/coordinate/roots, FULL component and
   infrastructure counts, wire id, boundary sha, FULL compatibility + physical tree columns, FULL `statement_authority_id`,
   base geometry identity, protocol ids, pcs words, `ethereum.mixIntoV2`, ethereum identity, public boundary identity,
   completion, FULL-prefix `bridge_geometry.mixFieldAuthority`, profile identity. The public statement stays the full
   445-column statement.
2. NEW `IncrementalOmissionFrameV4.mixInto(C)`: `[STIW, OMV4, 1, 0]`, projection identity (8 LE u32; binds full authority id,
   extension identity, lookup manifest/statement/activation ids, plan identity (which contains the pins' request identity),
   call_list_commitment, omitted index + descriptor {poseidon2, log_size, n_rows = 6,671,301, 445}, projected authority id,
   projected geometry), pins identity, then projected-prefix bridge geometry words (DOMAIN_WORDS, format, n_rows, log_size,
   is_first/is_active col idx (-2), main_col_offset (-445), interaction_col_offset (-8), totals).
3. Tree 0 root absorbed by `Engine.commit` (projected base preprocessed + 14 Ethereum blocks + bridge is_first/is_active).
4. Tree 1 root absorbed (projected infra: program, memory, merkle, clock — no 445-column table; Ethereum; bridge main).
5. `AuthorityV4.mixPostTree1(full, role_aware_public, C)` — unchanged: FULL core main claim + shard manifest,
   `ethereum.mixIntoV2`, `POST_TREE1 [STIW, BRF4, 4, 2]`, FULL-prefix bridge geometry, profile identity.
6. `Extension.drawChallenges` (`ethereum_omit_protocol_v1.zig:501-531`) = `proveToRelationsWithExtension(C, projected_core, Frame)`:
   `mixMainClaim(projected core)` (redundant with [5]'s full-core claim; accepted, consistent on all three sides because all
   three use the same function), `Frame.mixInto` (frame_domain_words with OMIT_RECOMPUTE_CORE_IMPLEMENTED=1,
   FRESH_PROVIDER_CLOSURE_REQUIRED=1, ACTIVATES_PRODUCTION_PROOF=0; projection identity; manifest identity; plan identity;
   session = `call_view.source_identity_sha256`; call_list_commitment; 26; per record identity, descriptor identity, index,
   count, first_call, call_count, log size (17 or 18), mixRoot(preprocessed_root), mixRoot(main_root); mixRoot(T0); mixRoot(T1)),
   `grind(16)` (GPU search admissible; host re-verifies), `mixU64(nonce)`, `Relations.draw` (base incl. poseidon2 {z, alpha}
   and poseidon2_io, Keccak, secp). `SharedRelationAuthorityV1 = {plan id, manifest id, projection id, T0, T1, pow bits/nonce,
   PoseidonRelationContextV1(session, z, alpha)}`; `LeafOmissionAuthorityV4 = H(profile identity, frame_v4 identity, shared
   identity, full statement authority id)`.
7. `mixInteractionClaimV2(C, projected_core, manifest, authenticated, base_claim (n_infra = full - 1), extension_claim)`,
   `incremental_bridge.mixClaim(bridge_claim)`.
8. Tree 2 root absorbed (projected base interaction (-8) + Ethereum + bridge interaction).
9. Composition (Tree 3), FRI, 193 queries, blowup 1 — unchanged.

Residual: `r = incremental_public.sum(full public_data, role_aware_public, relations.base) + canonical(projected core).total()
+ extension_claim.componentSum() + bridge_claim`; prover records it (diagnostic), the fresh verifier mints
`FreshCoreResidualV1{..., poseidon2_residual = r, fresh_core_stark_verified = true, non_poseidon_buses_closed = true,
production_eligible = false, recursive_admissible = false}` only after `core_verifier.verify` succeeds.

Shard i (26, D5 239-column AIR + `ProviderOrderComponent`, unchanged geometry): Stage A Tree0/Tree1 are committed once per
leaf on Metal by `prepared_batch` (roots depend only on shard calls, `expected_log_size`, `call_count`) and their roots enter
[6] before the draw, so shard witnesses are fixed before the challenge. Shard channel: fresh `Engine.Channel{}` -> [1] -> [2]
-> mixRoot(shared.T0) -> mixRoot(shared.T1) -> [5] -> `verifyToRelationsWithExtension(projected_core, shared.nonce, Frame)`
(== [6]) -> require relation context equality -> `appendProviderLocalFrameV2` (`[STWE, PRV2, 1, 12]`, manifest id, record id,
call_list_commitment, shard index/first/count, interaction_column_count = 4, `claims.sums`, ordered claim format/first/count/
terminal) -> NEW `[STIW, PLV4, 1, 0]`, `leaf_omission.identity`, pins identity -> `finishLocalPrefix` (`strategy_domain
[STWB, E5OP, 1, 239, 12, 2, 4, 0]`, `air_program_identity`, `ProviderStatementV1.identity`) -> Tree 2 commit (8 LogUp + 4
order columns) -> composition -> FRI. The fresh shard verifier additionally requires `commitments[0..1]` == the manifest
record roots, recomputes the preprocessed root, and recomputes the ordered-call claim from the calls under `relations.base`
(`degree5_ethereum_omit_provider_proof_v1.zig:576-612`).

Closure (CPU only, after all STARKs): `closeFreshClaimsV2` requires every `FreshDegree5ProviderClaimV1` to carry the same
`relation_context_identity`, program/profile identities, `shard_index == position`, and `verifyAggregateClosure` requires
`core.claim + sum_i claims_i.total() == 0` (`authority.zig:551`). `VerifiedJointClosureV1`/`FreshStrategyV1` validate only
with both eligibility flags false.

Bound in STWIOL01: full statement, role public, extension, full-statement profile, omission section (Section 2 step 8),
claims against the projected core, core proof, 26 shard artifacts; seal over all content. NOT bound anywhere (receipt only):
host owner/worker counts (fixed by pins for the plan; runtime owner count is forced to 18 by `batch_execution_v1:278`),
route flag, the fact that the verifier's call list is borrowed from the producer process.

## 4. Fail-closed receipt (`stwo.stage101.leaf-degree5-provider-route.v1`, JSON, sealed like the sweep)

Required-true: `core_plus_providers_closed`, `closed_sum_is_zero`, `residuals_equal` (prover == fresh),
`cpu_fresh_verified`, `producer_proofs_destroyed_before_cpu_decode`, `shared_context_verified_count == shard_count (26)`,
`plan_rebuilt_from_pins_matches_decoded`, `manifest_identity_equal_across_engines`.

Required-false (activation guards): `production_active`, `complete_leaf_proof`, `recursive_capture_available`,
`recursive_admissible`, `production_eligible`, `stage_a_transactions_validated_authority` must be TRUE (G1 landed) —
if false the receipt is invalid.

Provenance/limitation fields (no silent defaults): `provider_route = "degree5-omit-v1"`, `durable_core_envelope = "STWIOL01"`,
`durable_shard_artifacts = true`, `fresh_calls_source = "producer_process_borrowed"`,
`provider_plan_admission = "pins_v1"` (not `FreshClosureAdmissionV1`), `diagnostic_cancellation_ran: bool`,
`legacy_full_corpus_validations_producer/verifier` (must be 1/1 from `WorkReceiptV1`),
`known_red_baselines` (the Step 0 decision: empty if blocker 1 was fixed, otherwise the exact failing
step/assertion it is allowed to keep failing at).

Identities: full and projected `statement_authority_id`, `projection_identity`, `pins_identity`, `frame_v4_identity`,
`leaf_omission_identity`, `plan_identity`, `session`, `call_list_commitment`, `manifest_identity`, `shared_relation_identity`,
`relation_context_identity`, `interaction_pow`, `core_artifact_byte_count/sha256`, `core_commitments_identity`,
`prover_residual`, `fresh_residual`, `closure_identity`, `strategy_identity`, `shard_count`,
`ordered_shard_proof_identity_sha256`, `ordered_fresh_identity_sha256`, all D5 topology/AOT/backend fields of the sweep
receipt (`stage101_degree5_provider_sweep_v1.zig:116-183`), `validation_identity_sha256`.

Timing (ns) + `ResourceReceiptV1` per phase: `runtime_init`, `admission`, `replay`, `snapshot`, `witness`, `profile`,
`plan`, `stage_a`, `core_prove`, `shard_prove`, `encode`, `core_fresh_verify`, `shard_fresh_verify`, `closure`, `total`;
plus telemetry (`TelemetryReceiptV1`). Budget `ProviderRouteBudgetV1`: admission+replay <= 200 ms, witness+profile <= 800 ms,
`plan + stage_a + core_prove + shard_prove` <= 3.8 s, encode <= 200 ms, total <= 5 s; validated AFTER publish, fail-closed.

## 5. Test list

Unit (frontend, via `test_inventory.zig` + `refAllDecls` on the new `testing` export):
- pins identity is a function of call count only; frame identity sensitivity; `projectedBridgeGeometry` deltas 2/445/8 and
  equal `log_size`/`n_rows`; `residualIncrementalV4` sign convention against `logup.verifyGlobalCancellation` on a synthetic
  claim set.
- `retypeStageARoots`/`retypeSharedRelation` preserve identity (`SharedRelationAuthorityV1(Cpu).validate` passes).
- Metal module unit tests (added to the `stage101_tests` filter list, `build.zig:129-141`): "Stage101 D5 route budget maps
  stage A into the proof-core window", "Stage101 D5 route receipt rejects unshared relation context and non-zero closure",
  "Stage101 D5 route strips only its own flag and rejects unknown route values", "Stage101 D5 route pins equal the sweep's
  retained request".

Parity:
- G1: validated vs unvalidated omit path — identical shard proof bytes, `SharedRelationAuthorityV1`, closure identity;
  `full_corpus_validations == 1` per side.
- G6: channel digest + `n_draws` after `Relations.draw` equal across (a) orchestration, (b) `Stage101TranscriptAdapterV1.replayShared`,
  (c) verifier `verifyRelations` (expose `transcript_after_relations_digest`); shard local prefix differs from the ordinary
  `providerLocalPrefixV2` by exactly the `[STIW, PLV4, ...]` frame.
- Native non-regression: `test-riscv-ethereum-incremental-full-leaf-proof-v4` (ProofTestGuard identity),
  `test-riscv-ethereum-incremental-full-leaf-replay-producer-v4`, `test-riscv-ethereum-candidate-leaf-proof`,
  `test-riscv-degree5-provider-order-proof`, `test-stage101-leaf-autoresearch-v1`,
  `test-stage101-degree5-provider-sweep-v1`; one native leaf run must still produce
  `20baa3ae632cf116...`, 57,928,628 bytes, 193 queries.
  `test-ethereum-segment-transcript-extension` is a *known-red* baseline, not a green gate (blocker 1): assert only
  that its failure is unchanged, or fix it first with blocker 1's smallest fix and then require green.

Fresh-verify end-to-end (new step `test-riscv-ethereum-incremental-omitted-leaf-proof-v1`, file
`src/integrations/riscv_cpu/ethereum_incremental_omitted_leaf_proof_v1_test.zig`, fixture copied from
`ethereum_incremental_full_leaf_proof_v4_test.zig:60-480`, test pins `shard_log 4..6` so N >= 3; pattern
`build_proof_steps.zig:280-312`, `ProofTestGuard`):
- omitted core proves; `base_claim.n_infra == full.n_infra - 1`; projected columns full-2/445/8; STWIOL01 round-trips;
  fresh verify succeeds with `initForFreshVerifyValidated(expected shared)`; `prover_residual == fresh_residual`;
  every shard fresh-verifies with `shared_core_relation_context_verified == true`; `closeFreshClaimsV2` gives
  `closed_sum.isZero()`, `!production_eligible`, `!recursive_admissible`.
- Mutations (typed errors, no panics): flipped Stage-A main root in the omission section; changed `interaction_pow`
  (`InvalidInteractionProofOfWork`); swapped two shard artifacts (`NonCanonicalFreshProviderOrder`); dropped shard
  (`InvalidDegree5EthereumProviderClaimCount`); altered one shard `claims.sums`; mutated `projected_bridge_geometry.placement`;
  mutated a pin (plan identity mismatch); mutated profile identity; decoded plan fields disagreeing with the plan rebuilt
  from calls; seal mismatch; STWIEF04 decoder rejects STWIOL01 magic and vice versa; a standalone-route
  (`degree5_provider_order_proof_v2`, independent draw) shard proof of the same calls is rejected (relation context);
  a segment-route (`OrdinaryTranscriptAdapter`) shard proof of the same calls is rejected (local prefix / leaf omission);
  an `OrdinaryTranscriptAdapter` replay cannot verify a route shard proof.

Proof identity (Metal): two consecutive runs reproduce `core_artifact_sha256`, `ordered_shard_proof_identity_sha256`,
`closure_identity`, `projection_identity`, `shared_relation_identity`; these become the route oracle. The sweep oracle
`89ee5ce2ec0ed975...` will NOT match by construction (shards now prove under the shared draw and a different local prefix),
and the native oracle `20baa3ae...` will not match because Trees 0/1/2 differ.

## 6. Build, run, measure

```
# CPU gates (from src/integrations/riscv_cpu)
zig build test-riscv-ethereum-provider-omitted-leaf-bundle test-ethereum-candidate-degree5-provider-batch-v1
zig build test-ethereum-segment-transcript-extension   # KNOWN RED today (blocker 1); ~730 s
zig build test-riscv-ethereum-omit-validated-parity-v1                      # new (step 1)
zig build test-riscv-ethereum-incremental-omitted-leaf-proof-v1             # new (step 10)
zig build test-riscv-ethereum-incremental-full-leaf-proof-v4 test-riscv-ethereum-candidate-leaf-proof \
          test-riscv-degree5-provider-order-proof test-riscv-ethereum-incremental-full-leaf-replay-producer-v4
# frontend
(cd ../../frontends/riscv && zig build test)
# Metal contract tests (from src/integrations/riscv_metal)
zig build test-stage101-leaf-autoresearch-v1 test-stage101-degree5-provider-sweep-v1
zig fmt --check <every changed/new file>

# Metal binary (~10 min ReleaseFast, single compilation unit)
cd src/integrations/riscv_metal && zig build -p <prefix> install-stage101-leaf-autoresearch-v1 -Doptimize=ReleaseFast

# Route run (never concurrently with another heavy Metal run)
STWO_ZIG_STAGE101_WORKER_COUNT=18 STWO_ZIG_WORKERS=18 STWO_ZIG_MERKLE_WORKERS=18 \
STWO_ZIG_STAGE101_HOST_BYTE_BUDGET=51539607552 STWO_ZIG_STAGE101_HOST_BYTE_LIMIT=64424509440 \
STWO_ZIG_STAGE101_REFERENCE_ARTIFACT=/private/tmp/stwo-stage101-profile.8iE8D4/segment-000001.stwief04 \
STWO_RISCV_METAL_AOT_BUNDLE=/private/tmp/stwo-metal-poseidon-aot-v25.hizW2m/share/stwo-zig/metal/core \
STWO_ZIG_STAGE101_STAGE_PROFILE=1 \
<prefix>/bin/stage101-metal-autoresearch-v1 --provider-route degree5-omit-v1 \
  --retained-materialization-result /private/tmp/stwo-incremental-capture-v4-hoisted-release.VSdg8m/authority/materialization-v2.json \
  --publication-root /private/tmp/stwo-incremental-capture-v4-hoisted-release.VSdg8m/run/publication-parent/ethereum-incremental-capture-v4 \
  --segment-index 1 --output <out>/segment-000001.route-receipt.json
# Native control arm: same command without --provider-route; must still print artifact_sha256=20baa3ae...

# Measure: receipt JSON (scratchpad/receipt.py), STAGE101_PROFILE lines
#   (expect riscv_infrastructure_trace_generation_without_native_poseidon present and
#    riscv_interaction_poseidon absent in the core), `sample <pid> 20 1 -mayDie -file out.txt` during core prove,
#   optional STWO_ZIG_METAL_PROFILE_OUT=<ndjson> + prof_agg.py (not for verdicts).
```

Expected first-run outcome: the receipt publishes and the command then FAILS CLOSED on
`Stage101ProviderRouteBudgetExceeded`. Measured pieces (sweep build 8): Stage A 1.06-1.39 s, shard prove 2.15-2.45 s
(may rise slightly: each shard replays `mixPreTree0/mixPostTree1`), CPU shard fresh verify 3.5-3.7 s. Not measured: the V4
core without the 445-column table (the native core is 176-240 s prove_ns with it; remaining core is CPU trace generation
for program/memory/merkle/clock/14 Ethereum components + Metal commits, plausibly tens of seconds) and the core fresh
verify. Report per-phase numbers and identities; the budget failure is the expected result of the route, not a defect.

## 7. Explicitly out of scope

- Any change to `incremental_ethereum_orchestration_v3.zig`, `incremental_ethereum_verifier_v3.zig`, the STWIEF04 codec,
  `AuthorityV4` wire/schema, `replay_command_v4.runWithEnginesInternal`, or the native artifact pin.
- Production/recursive activation: no flag flips, no H1 wrapper, no `FreshVerifiedCaptureV4` for the omitted core,
  no `FreshClosureAdmissionV1`/`ProviderPlanAdmissionV1` compatibility (their policy pins log 20 / 1 shard / 1 owner).
- Metal-concurrent overlap of Stage A with core Tree0/1 and shards with the core tail; campaign-level amortization
  (`CampaignContextV1`, prepared-program reuse, hash-prefix cache, Stage-A scheme cloning).
- Cold re-derivation of the 6.67M-call list in the verifier process (keep the typed call-source seam; flip later).
- `batch_execution_v1:278` owner-subset relaxation (18 owners remain forced at runtime).
- Any `.metal` shader change (would require a bundle remint and repin of four SHAs + export count in both commands).
- The sweep command and its oracle `89ee5ce2...` remain as they are.

## 8. Pre-existing blockers found (smallest fix)

Blocker 1 was found by running the gates today and is the one that changes the plan; the rest are already
folded into the steps above.

1. **`test-ethereum-segment-transcript-extension` is RED on the current tree** (measured 2026-09-04:
   `zig build test-ethereum-segment-transcript-extension ...` exit 1, 727 s wall, 14/15 tests passed).
   This is the only end-to-end omit-protocol proof gate, so the plan cannot cite it as a green control arm.
   Failure chain: `ethereum_segment_transcript_extension_test.zig:310` encodes the **projected** statement
   (`&projection.projected_native`) into the ordinary SegmentV2 Poseidon2 artifact ->
   `ethereum_segment_poseidon2_proof_artifact.encodeAllocWithLimits:126` ->
   `ethereum_segment_proof_artifact.validateMetadata:330` -> `ethereum_proof_admission.validateV2:49` ->
   `statement_validation.validateV2:108` -> `validateGeometry:243` -> `ProverError.InvalidStatement`.
   Root cause (read out today, not a today-regression: none of these five files is modified in the working
   tree, and `poseidon2_air.N_MAIN_COLUMNS` is unchanged at 445): ordinary admission **requires** the omitted
   descriptor. `validateGeometry` demands the exact infra layout `program | memory* | merkle | poseidon2 |
   clock_update | lookup tables` with `index + 3 + LOOKUP_TABLE_COUNT == n_infra`,
   `poseidon_desc.kind == .poseidon2`, `poseidon_desc.n_columns == 445` and
   `poseidon_desc.n_rows == merkle_desc.n_rows` (`statement_validation.zig:281-292, 299`), plus
   `n_infra >= 10` (`:242`). A projected core has that descriptor removed, so it can never pass
   `proof_admission.validateV2`.
   Smallest fix (test-side, no protocol change): stop routing a projected core through ordinary admission.
   Either (a) the omitted arm of the test asserts on the prove output and the fresh-verify/closure path and
   skips the ordinary artifact encode entirely (the omitted core has no canonical SegmentV2 envelope today),
   or (b) add `validateMetadataOmitted(full_statement, extension, global, projection)` next to
   `validateMetadata:324` that admits the FULL statement and then checks
   `native_provider_omit.ProjectionV1.validateSealAndFull(full, extension)` instead of admitting the
   projected core.
   Consequences for this plan, both already satisfied by the design: (i) **STWIOL01 must carry the FULL
   statement** in section 0 and only the claims against the projected core (Step 8) — never a projected
   statement through an admission-running codec; the plan's `ProjectionV1.init` / `Extension` calls always
   admit the full statement, so the route is unaffected; (ii) the Step 1 validated-vs-unvalidated parity
   test must compare prove outputs, shard proof bytes, `SharedRelationAuthorityV1` and the closure identity
   **before** any artifact encode, or wait for Step 8's envelope — it cannot reuse the segment fixture's
   encode/decode leg while that leg is red.
2. `update-riscv-polynomial-aot` (`build_support/products/riscv_metal.zig:329-343`) fails with a duplicate
   `stwo_metal_backend` module root, so the checked-in `riscv_polynomials.metal` had to be hand-transformed
   in today's campaign (`autoresearch/notes/2026-09-03-d5-leaf-metal-host-throughput/note.md:123-125`).
   Root cause read out today: `riscv_metal_modules.createDependencies` (`riscv_metal_modules.zig:179-211`) is
   not memoized, so `createModule` (used for `proof_test_module`, `riscv_metal.zig:245`) and
   `createFacadeModule` (`:301-306`, imported into the same module as `stwo_riscv_metal`) each call
   `graph.createMetalBackend` and produce two distinct module roots over the same files.
   Smallest fix: give `createFacadeModule` an overload that takes the already-created `Dependencies`
   (or memoize `createDependencies` per logical product) and pass `proof_test_module`'s existing
   `stwo_metal_backend`/`stwo_riscv_frontend`/`stwo_riscv_metal_integration` imports into the facade.
   Not needed for this route (no shader change, no remint).
3. Non-Validated-only consumption in the shared-transcript D5 prover/verifier (`degree5_ethereum_omit_provider_proof_v1.zig:271-303`
   passes `null`; `stage_a_transaction.zig:241` rejects a `initValidated` transaction). Fix = step 1 (threading
   `validated_calls`; siblings already exist).
4. `ethereum_main.commitWithoutNativePoseidonWithExternalBlocks` requires a non-optional registration (`:155`) while
   `commitInternal` handles `null` (`:237-277`). Fix = step 3 (make the parameter optional; callers coerce).
5. Host knobs enter proof identity: the sweep feeds `requested_parallel_shards`/budgets from env into
   `ProviderShardPlanV1.create` (`sweep_v1.zig:380-397`) and `request_identity` is hashed into `plan.identity`
   (`residency_shard_plan.zig:125`, `authority.zig:640`). Fix = step 2 pins (for the route; the sweep is untouched).
6. `authority.zig:22-28` header constants are stale relative to the degree5 modules (`CALLER_N_MANIFEST_IMPLEMENTED`,
   `ORDERED_CALL_COMMITMENT_IS_AIR_PROVED`). Fix: correct constants + comptime cross-check (step 1); no protocol effect.
7. The Stage101 leaf `ThroughputBudgetV1` (5 s) fails closed after every run, so the native command exits non-zero on this
   host; the route must publish its receipt before budget validation (mirrored in step 9.8). Not a code defect.
8. Module wiring gap for the route. `stage101_degree5_metal_facade.zig` exports only seven modules today
   (`ethereum_block_leaf_support`, `..._batch_execution_v1`, `..._order_batch_v1`, `..._prepared_batch_v1`,
   `ethereum_incremental_full_leaf_replay_command_v4`, `..._throughput_execution_v1`,
   `ethereum_precompile_artifact_io`) — none of the profile/proof/transaction/artifact modules the route needs.
   And `stage101_module` (`riscv_metal/build.zig:119-128`) imports only `stwo_riscv_cpu_stage101_metal`, while
   the D5 facade module `stwo_riscv_cpu_stage101_degree5_metal` is already created at `:38` and imported only by
   the sweep (`:166-169`). Fix = step 9 wiring (facade exports + one `addImport` on `stage101_module`).
9. Cosmetic: sweep test name "Stage101 D5 backend identity pins authenticated ABI21 custody" (`sweep_v1.zig:1071`) while the
   runtime/bundle is ABI22; rename when touched.

Build health measured on the current tree, 2026-09-04 (commands and exit codes, not recollection):

| Command | Result |
| --- | --- |
| `zig build test-stage101-leaf-autoresearch-v1 test-stage101-degree5-provider-sweep-v1` (riscv_metal) | exit 0, 0.98 s (cached) |
| `zig build test-ethereum-segment-transcript-extension test-riscv-ethereum-provider-omitted-leaf-bundle test-riscv-ethereum-incremental-full-leaf-replay-producer-v4 test-ethereum-candidate-degree5-provider-batch-v1` (riscv_cpu) | exit 1, 727 s wall / 990 s CPU; 13/16 steps, 14/15 tests; the only failure is blocker 1 above — the other three steps pass |
| `zig fmt --check <all 38 modified .zig files>` | exit 0 |
| `zig build --help` in both roots | every step this plan names exists today |

Not run here (cost, and not required to write the plan): the four heavy CPU proof gates
(`test-riscv-ethereum-incremental-full-leaf-proof-v4`, `test-riscv-ethereum-candidate-leaf-proof`,
`test-riscv-degree5-provider-order-proof`, `test-riscv-metal-*-proof`), any Metal binary build or run,
and `update-riscv-polynomial-aot` (blocker 2, corroborated only by today's campaign note).

## 9. Not verified

- `ProjectionV1.init`/`findExactProvider`/`deriveFullGeometry` admission of the segment-1 V4 statement (by reading only;
  fallback is `prepareProjectedCoreWithRetirementSupplementV2` with `profile_v4.retirementSupplement`). Note this is
  admission of the FULL statement: admission of a projected core is not merely unverified, it is impossible by
  construction (`statement_validation.validateGeometry:281-299`, blocker 1), so any new code path added by this plan
  that reaches `ethereum_proof_admission.validateV2` must be handed the full statement.
- `assembleAuthenticatedLookupV2WithIncrementalBoundaryV3` with a core lacking `.poseidon2` (the SegmentV2 omit route relies on
  the sibling `assembleAuthenticatedLookupV2`).
- Whether the omitted core's remaining components keep the same Metal composition eligibility (`maxConstraintLogDegreeBound >= 16`)
  and the same 3 small-circle host placements; both are recorded, not pinned, on the first run.
- Memory: 26 retained log18 Stage-A schemes (`.always` retention) resident during the omitted core prove under the 48 GiB
  budget; `requireTree1Residency` and the D5 reservation are the fail-closed guards. If the footprint blocks, sequence
  Stage A with retention `.never` (roots only) and re-run Stage A inside each shard proof (costs Stage A twice).
- Segment-1 `poseidon_log_size` (computed 23 from 6,671,301 calls) and the omitted core prove time.
