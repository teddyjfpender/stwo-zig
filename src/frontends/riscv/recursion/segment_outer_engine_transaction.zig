//! Backend-bound outer proof production, independent verification and fail-atomic publication.

pub fn For(comptime owner_context: anytype) type {
    const std = owner_context.std;
    const stwo_core = owner_context.stwo_core;
    const postcard = owner_context.postcard;
    const canonical_identity = owner_context.canonical_identity;
    const verified_publication = owner_context.verified_publication;
    const verified_artifact = owner_context.verified_artifact;
    const recursion = owner_context.recursion;
    const manifest_mod = owner_context.manifest_mod;
    const shared_provider = owner_context.shared_provider;
    const universal = owner_context.universal;
    const poseidon2_channel = owner_context.poseidon2_channel;
    const Engine = owner_context.Engine;
    const OuterProofCapture = owner_context.OuterProofCapture;
    const VerifiedSegmentV2PublicationV1 = owner_context.VerifiedSegmentV2PublicationV1;
    const RecursiveWitnessV1 = owner_context.RecursiveWitnessV1;
    const VerifierScheme = owner_context.VerifierScheme;
    const ProofExecutionPool = owner_context.ProofExecutionPool;
    const TreeStorage = owner_context.TreeStorage;
    const ProducerAllocator = owner_context.ProducerAllocator;
    const moveOwnedForVerifier = owner_context.moveOwnedForVerifier;
    const rejectTransactionOutputAlias = owner_context.rejectTransactionOutputAlias;
    const qm31Words = owner_context.qm31Words;
    const relationDraws = owner_context.relationDraws;
    const commitVerifierTree = owner_context.commitVerifierTree;
    const CANONICAL_PROOF_SERIALIZATION_PASSES = owner_context.CANONICAL_PROOF_SERIALIZATION_PASSES;
    const ExecutionOptions = owner_context.ExecutionOptions;
    const Receipt = owner_context.Receipt;
    const OUTER_CONFIG = owner_context.OUTER_CONFIG;
    const decodeCanonicalProof = owner_context.decodeCanonicalProof;
    const checkSerializedArtifactRejections = owner_context.checkSerializedArtifactRejections;
    const validateManifest = owner_context.validateManifest;
    const assertCohortContract = owner_context.assertCohortContract;
    const Diagnostics = owner_context.Diagnostics;
    return struct {
        pub fn EngineKernel(comptime Cohort: type) type {
            assertCohortContract(Cohort);
            return struct {
                pub fn proveAndVerify(
                    allocator: std.mem.Allocator,
                    authority_inputs: Cohort.AuthorityInputs,
                    capture_out: *OuterProofCapture,
                    publication_out: *VerifiedSegmentV2PublicationV1,
                    witness_out: *RecursiveWitnessV1,
                ) !Receipt {
                    return proveAndVerifyWithExecution(
                        allocator,
                        authority_inputs,
                        .{},
                        capture_out,
                        publication_out,
                        witness_out,
                    );
                }

                pub fn proveAndVerifyWithExecution(
                    allocator: std.mem.Allocator,
                    authority_inputs: Cohort.AuthorityInputs,
                    execution: ExecutionOptions,
                    capture_out: *OuterProofCapture,
                    publication_out: *VerifiedSegmentV2PublicationV1,
                    witness_out: *RecursiveWitnessV1,
                ) !Receipt {
                    var transaction_timer = try std.time.Timer.start();
                    var receipt = try proveAndVerifyTransaction(
                        allocator,
                        authority_inputs,
                        execution,
                        capture_out,
                        publication_out,
                        witness_out,
                    );
                    // Includes verifier, canonical-byte and execution-pool teardown.
                    // Returned verifier capture/publication belong to the consumer.
                    receipt.transaction_ns = transaction_timer.read();
                    return receipt;
                }

                fn proveAndVerifyTransaction(
                    allocator: std.mem.Allocator,
                    authority_inputs: Cohort.AuthorityInputs,
                    execution: ExecutionOptions,
                    capture_out: *OuterProofCapture,
                    publication_out: *VerifiedSegmentV2PublicationV1,
                    witness_out: *RecursiveWitnessV1,
                ) !Receipt {
                    comptime @import("stwo_prover_api").assertProverEngine(Engine);
                    try rejectTransactionOutputAlias(
                        capture_out,
                        publication_out,
                        witness_out,
                    );

                    var execution_pool: ProofExecutionPool = .{};
                    try execution_pool.initInPlace(allocator, execution.worker_count);
                    defer execution_pool.deinit();
                    const effective_worker_count = try execution_pool.visibleWorkerCount();

                    // Only the serialized artifact and copied scalar diagnostics leave
                    // this allocator. The admitted native leaf belongs to the caller.
                    var producer_memory = ProducerAllocator{};
                    defer std.debug.assert(producer_memory.isEmpty());
                    const producer_allocator = producer_memory.allocator();
                    var prepare_timer = try std.time.Timer.start();
                    var prover = try Cohort.init(producer_allocator, authority_inputs);
                    var prover_owned = true;
                    defer if (prover_owned) prover.deinit();
                    // Constructor admission has just completed on this local owner.
                    const manifest = prover.manifest();
                    try validateManifest(manifest);

                    const preprocessed_columns = std.math.cast(
                        u32,
                        manifest.total_preprocessed_columns,
                    ) orelse return error.ArithmeticOverflow;
                    const main_columns = std.math.cast(
                        u32,
                        manifest.total_main_columns,
                    ) orelse return error.ArithmeticOverflow;
                    const interaction_columns = std.math.cast(
                        u32,
                        manifest.total_interaction_columns,
                    ) orelse return error.ArithmeticOverflow;

                    const roster_count = manifest.roster_count;
                    const producer_prepare_ns = prepare_timer.read();
                    var prove_timer = try std.time.Timer.start();
                    var proof_bundle = try prove(producer_allocator, &prover);
                    var proof_owned = true;
                    defer if (proof_owned) proof_bundle.proof.deinit(producer_allocator);
                    const transcript_draws = proof_bundle.transcript_draws;
                    const prove_ns = prove_timer.read();
                    const proof_size = proof_bundle.proof.sizeEstimate();
                    const publication_proof_size = std.math.cast(
                        u64,
                        proof_size,
                    ) orelse return error.ArithmeticOverflow;
                    var proof_canonicalize_timer = try std.time.Timer.start();
                    var encoded: std.ArrayList(u8) = .empty;
                    defer encoded.deinit(allocator);
                    try postcard.serializeProof(
                        recursion.engine.Hasher,
                        encoded.writer(allocator),
                        proof_bundle.proof,
                    );
                    const proof_bytes = try encoded.toOwnedSlice(allocator);
                    defer allocator.free(proof_bytes);
                    const proof_identity = try canonical_identity
                        .CanonicalProofIdentityV1.fromBytes(proof_bytes);
                    const proof_canonicalize_ns = proof_canonicalize_timer.read();

                    var destroy_timer = try std.time.Timer.start();
                    proof_bundle.proof.deinit(producer_allocator);
                    proof_owned = false;
                    prover.deinit();
                    prover_owned = false;
                    try producer_memory.requireEmpty();
                    const producer_destroy_ns = destroy_timer.read();

                    // No original outer proof, trace, or cohort survives this boundary.
                    // Shape, statements and challenges come from a separately rebuilt
                    // cohort and the decoded artifact, never producer-owned values.
                    var decode_timer = try std.time.Timer.start();
                    var decoded_proof = try decodeCanonicalProof(allocator, proof_bytes);
                    var decoded_owned = true;
                    defer if (decoded_owned) decoded_proof.deinit(allocator);
                    const decode_ns = decode_timer.read();
                    var artifact_rejections_ns: u64 = 0;
                    if (execution.check_serialized_artifact_rejections) {
                        var rejection_timer = try std.time.Timer.start();
                        try checkSerializedArtifactRejections(allocator, proof_bytes);
                        artifact_rejections_ns = rejection_timer.read();
                        std.debug.print("\nSEGMENT_V2_OUTER_ARTIFACT_REJECTIONS truncated=true trailing=true\n", .{});
                    }
                    prepare_timer.reset();
                    var verifier = try Cohort.init(allocator, authority_inputs);
                    defer verifier.deinit();
                    // Fresh constructor admission precedes all verifier-side reads.
                    const verifier_prepare_ns = prepare_timer.read();
                    var verify_timer = try std.time.Timer.start();
                    const verifier_receipt = try verify(
                        allocator,
                        &verifier,
                        &decoded_proof,
                        &decoded_owned,
                        publication_proof_size,
                        proof_identity,
                        capture_out,
                        publication_out,
                        witness_out,
                    );
                    std.debug.assert(!decoded_owned);

                    const canonical_proof_bytes: usize = proof_identity.byte_count;
                    const canonical_proof_streamed_bytes = try std.math.mul(
                        usize,
                        canonical_proof_bytes,
                        CANONICAL_PROOF_SERIALIZATION_PASSES,
                    );

                    const receipt = Receipt{
                        .proof_size_estimate = proof_size,
                        .canonical_proof_bytes = canonical_proof_bytes,
                        .canonical_proof_streamed_bytes = canonical_proof_streamed_bytes,
                        .canonical_proof_serialization_passes = CANONICAL_PROOF_SERIALIZATION_PASSES,
                        .canonical_proof_retained_bytes = proof_bytes.len,
                        .canonical_proof_id = proof_identity.proof_id,
                        .canonical_proof_sha256 = proof_identity.canonical_proof_sha_id,
                        .canonical_proof_id_poseidon_permutations = poseidon2_channel.bytePermutationCount(
                            canonical_proof_bytes,
                        ),
                        .proof_canonicalize_ns = proof_canonicalize_ns,
                        .producer_prepare_ns = producer_prepare_ns,
                        .producer_destroy_ns = producer_destroy_ns,
                        .producer_peak_bytes = producer_memory.peakBytes(),
                        .producer_live_bytes_after_destroy = producer_memory.snapshot().active_bytes,
                        .verifier_prepare_ns = verifier_prepare_ns,
                        .decode_ns = decode_ns,
                        .artifact_rejections_ns = artifact_rejections_ns,
                        .stark_verify_ns = verifier_receipt.stark_verify_ns,
                        .transaction_ns = 0, // Filled after all transaction owners are destroyed.
                        .prove_ns = prove_ns,
                        .verify_ns = verify_timer.read(),
                        .publication_ns = verifier_receipt.publication_ns,
                        .transcript_draws = transcript_draws,
                        .preprocessed_columns = preprocessed_columns,
                        .main_columns = main_columns,
                        .interaction_columns = interaction_columns,
                        .roster_count = roster_count,
                        .worker_count = effective_worker_count,
                    };
                    try receipt.validate();
                    return receipt;
                }

                const ProofBundle = struct {
                    proof: recursion.engine.Proof,
                    transcript_draws: usize,
                };

                const VerifierPublicationReceipt = struct {
                    publication_ns: u64,
                    stark_verify_ns: u64,
                };

                fn prove(
                    allocator: std.mem.Allocator,
                    cohort: *Cohort,
                ) !ProofBundle {
                    var phase_timer = try std.time.Timer.start();
                    const manifest = cohort.manifest();
                    try validateManifest(manifest);

                    const composition_diagnostic_enabled =
                        std.process.hasEnvVarConstant(
                            Diagnostics.COMPOSITION_DIAGNOSTIC_ENV,
                        );
                    if (composition_diagnostic_enabled)
                        try Diagnostics.validateCompositionDiagnosticRoster();
                    var scheme = try Engine.init(allocator, OUTER_CONFIG);
                    const retention_policy: @TypeOf(scheme.coefficient_retention_policy) =
                        if (composition_diagnostic_enabled) .always else .never;
                    scheme.setCoefficientRetentionPolicy(retention_policy);
                    if (scheme.coefficient_retention_policy != retention_policy)
                        return error.DiagnosticRetentionPolicyMismatch;
                    var scheme_moved = false;
                    defer if (!scheme_moved) Engine.deinit(&scheme, allocator);
                    var channel = Engine.Channel{};

                    const setup_ns = phase_timer.lap();
                    var preprocessed = try TreeStorage.init(
                        allocator,
                        manifest,
                        manifest_mod.PREPROCESSED_TREE_INDEX,
                    );
                    defer preprocessed.deinit();
                    try cohort.fillPreprocessedInto(manifest, preprocessed.columns);
                    const tree0_prepare_ns = phase_timer.lap();
                    try preprocessed.commit(&scheme, &channel);
                    try Engine.flushPendingCommit(&scheme, allocator, &channel);

                    const tree0_commit_ns = phase_timer.lap();
                    var main = try TreeStorage.init(
                        allocator,
                        manifest,
                        manifest_mod.MAIN_TREE_INDEX,
                    );
                    defer main.deinit();
                    try cohort.fillMainInto(manifest, main.columns);
                    const tree1_prepare_ns = phase_timer.lap();
                    try main.commit(&scheme, &channel);
                    try Engine.flushPendingCommit(&scheme, allocator, &channel);

                    const tree1_commit_ns = phase_timer.lap();
                    try manifest.mixStatementPrefix(&channel);
                    try cohort.mixAuthority(&channel);
                    const relations = try universal.UniversalRelations.draw(
                        allocator,
                        &channel,
                    );
                    const provider_relations =
                        try shared_provider.SharedProviderRelations.init(&relations);

                    const transcript_prefix_ns = phase_timer.lap();
                    var interaction = try TreeStorage.init(
                        allocator,
                        manifest,
                        manifest_mod.INTERACTION_TREE_INDEX,
                    );
                    defer interaction.deinit();
                    const generated = try cohort.fillInteractionInto(
                        manifest,
                        &relations,
                        &provider_relations,
                        interaction.columns,
                    );
                    const interaction_generate_ns = phase_timer.lap();
                    // Generation finalized this local receipt. It has not escaped or
                    // been mutated; auditGlobalClosure below independently admits the
                    // receipt, claim vector and exact closure at their next boundary.
                    var claims = try cohort.claimVector(&generated);

                    _ = try cohort.auditGlobalClosure(
                        &generated,
                        &claims,
                        &relations,
                        &provider_relations,
                    );
                    const interaction_admit_closure_ns = phase_timer.lap();
                    try claims.mixInteractionClaims(manifest, &channel);
                    try cohort.mixPublicWireBoundary(&channel, &relations);
                    try interaction.commit(&scheme, &channel);

                    const transcript_tree2_commit_ns = phase_timer.lap();
                    var components = try cohort.initComponents(
                        &generated,
                        &relations,
                        &provider_relations,
                    );
                    defer components.deinit();
                    var gate = try manifest_mod.ProofGate.init(manifest);
                    try components.appendToGate(manifest, &gate);
                    try gate.sealGate(manifest);

                    const components_ns = phase_timer.lap();
                    if (composition_diagnostic_enabled) {
                        try Engine.flushPendingCommit(&scheme, allocator, &channel);
                        if (scheme.pending_commit != null)
                            return error.DiagnosticPendingCommit;
                        if (scheme.trees.items.len != manifest_mod.TREE_COUNT)
                            return error.DiagnosticTreeCountMismatch;
                        const diagnostic_provers = try gate.proverSlice();
                        const diagnostic_verifiers = try gate.verifierSlice();
                        if (diagnostic_provers.len != manifest_mod.COMPONENT_COUNT or
                            diagnostic_verifiers.len != manifest_mod.COMPONENT_COUNT)
                        {
                            return error.DiagnosticRosterMismatch;
                        }
                        try Diagnostics.diagnoseCompositionComponents(
                            allocator,
                            &scheme,
                            diagnostic_provers,
                            diagnostic_verifiers,
                            manifest.total_preprocessed_columns,
                        );
                    }

                    const diagnostic_ns = phase_timer.lap();
                    scheme_moved = true;
                    var extended = try Engine.prove(
                        allocator,
                        try gate.proverSlice(),
                        &channel,
                        scheme,
                        .{},
                    );
                    defer extended.aux.deinit(allocator);
                    const stark_ns = phase_timer.lap();
                    const proof = extended.proof;
                    extended.proof = undefined;
                    // Contiguous, disjoint body spans; deferred cleanup and printing
                    // remain in the enclosing Receipt.prove_ns.
                    std.debug.print("\nSEGMENT_V2_OUTER_PHASES role=producer scope=body_before_cleanup setup_ns={d} tree0_prepare_ns={d} tree0_commit_ns={d} tree1_prepare_ns={d} tree1_commit_ns={d} transcript_prefix_ns={d} interaction_generate_ns={d} interaction_admit_closure_ns={d} transcript_tree2_commit_ns={d} components_ns={d} diagnostic_ns={d} stark_ns={d} phase_sum_ns={d}\n", .{
                        setup_ns,
                        tree0_prepare_ns,
                        tree0_commit_ns,
                        tree1_prepare_ns,
                        tree1_commit_ns,
                        transcript_prefix_ns,
                        interaction_generate_ns,
                        interaction_admit_closure_ns,
                        transcript_tree2_commit_ns,
                        components_ns,
                        diagnostic_ns,
                        stark_ns,
                        setup_ns + tree0_prepare_ns + tree0_commit_ns + tree1_prepare_ns + tree1_commit_ns + transcript_prefix_ns + interaction_generate_ns + interaction_admit_closure_ns + transcript_tree2_commit_ns + components_ns + diagnostic_ns + stark_ns,
                    });
                    return .{
                        .proof = proof,
                        .transcript_draws = channel.n_draws,
                    };
                }

                fn verify(
                    allocator: std.mem.Allocator,
                    cohort: *Cohort,
                    proof_in: *recursion.engine.Proof,
                    proof_owned: *bool,
                    proof_size_estimate: u64,
                    proof_identity: canonical_identity.CanonicalProofIdentityV1,
                    capture_out: *OuterProofCapture,
                    publication_out: *VerifiedSegmentV2PublicationV1,
                    witness_out: *RecursiveWitnessV1,
                ) !VerifierPublicationReceipt {
                    var phase_timer = try std.time.Timer.start();
                    if (!proof_owned.*) return error.ProofAlreadyConsumed;
                    const manifest = cohort.manifest();
                    try validateManifest(manifest);
                    const commitments = proof_in.commitment_scheme_proof.commitments.items;
                    if (commitments.len != manifest_mod.TREE_COUNT + 1)
                        return error.InvalidProofShape;
                    const preflight_ns = phase_timer.lap();
                    try assertPreprocessedRoot(
                        allocator,
                        cohort,
                        commitments[manifest_mod.PREPROCESSED_TREE_INDEX],
                    );

                    const preprocessed_root_ns = phase_timer.lap();
                    var scheme = try VerifierScheme.init(allocator, OUTER_CONFIG);
                    defer scheme.deinit(allocator);
                    var channel = Engine.Channel{};
                    try commitVerifierTree(
                        allocator,
                        &scheme,
                        manifest,
                        manifest_mod.PREPROCESSED_TREE_INDEX,
                        commitments[manifest_mod.PREPROCESSED_TREE_INDEX],
                        &channel,
                    );
                    try commitVerifierTree(
                        allocator,
                        &scheme,
                        manifest,
                        manifest_mod.MAIN_TREE_INDEX,
                        commitments[manifest_mod.MAIN_TREE_INDEX],
                        &channel,
                    );
                    try manifest.mixStatementPrefix(&channel);
                    try cohort.mixAuthority(&channel);
                    const relations = try universal.UniversalRelations.draw(
                        allocator,
                        &channel,
                    );
                    const provider_relations =
                        try shared_provider.SharedProviderRelations.init(&relations);

                    const transcript_prefix_ns = phase_timer.lap();
                    const generated = try cohort.rebuildGeneratedInteractions(
                        &relations,
                        &provider_relations,
                    );
                    const interaction_regenerate_ns = phase_timer.lap();
                    // Generation finalized this local receipt. It has not escaped or
                    // been mutated; auditGlobalClosure below independently admits the
                    // receipt, claim vector and exact closure at their next boundary.
                    var claims = try cohort.claimVector(&generated);

                    const interaction_validate_claims_ns = phase_timer.lap();
                    // This exact verifier-reconstructed closure remains live through
                    // native proof admission and is the sole closure authority for the
                    // successful publication.
                    const verified_closure = try cohort.auditGlobalClosure(
                        &generated,
                        &claims,
                        &relations,
                        &provider_relations,
                    );
                    const closure_ns = phase_timer.lap();
                    try claims.mixInteractionClaims(manifest, &channel);
                    try cohort.mixPublicWireBoundary(&channel, &relations);
                    try commitVerifierTree(
                        allocator,
                        &scheme,
                        manifest,
                        manifest_mod.INTERACTION_TREE_INDEX,
                        commitments[manifest_mod.INTERACTION_TREE_INDEX],
                        &channel,
                    );
                    const pre_core_channel =
                        recursion.outer_parent_child_admission.ChannelCheckpointV1{
                            .digest = channel.digestWords(),
                            .draw_count = channel.n_draws,
                        };

                    const transcript_after_ns = phase_timer.lap();
                    const components = try cohort.initVerifierComponents(
                        &relations,
                        &claims,
                        generated.core.poseidon2_partials,
                    );
                    defer components.deinit();

                    const components_ns = phase_timer.lap();
                    const publication_authority =
                        try cohort.publicationAuthority();

                    const publication_authority_ns = phase_timer.lap();
                    var stark_verify_timer = try std.time.Timer.start();
                    const proof = moveOwnedForVerifier(
                        recursion.engine.Proof,
                        proof_in,
                        proof_owned,
                    );
                    var capture: OuterProofCapture = undefined;
                    try stwo_core.verifier.verifyWithProofCapture(
                        recursion.engine.Hasher,
                        recursion.engine.MerkleChannel,
                        allocator,
                        try components.verifierComponents(),
                        &channel,
                        &scheme,
                        proof,
                        &capture,
                    );

                    const stark_verify_ns = stark_verify_timer.read();
                    const stark_ns = phase_timer.lap();

                    // Capture owns verifier allocations after admission.  Every
                    // publication derivation and validation remains local so any error
                    // releases the capture and leaves all caller destinations intact.
                    errdefer capture.deinit(allocator);
                    const publication_inputs = try cohort.recursivePublicationInputs(
                        &relations,
                        &claims,
                    );
                    const transcript_prefix_source = publication_inputs.transcript_prefix;
                    const transcript_prefix = try verified_artifact.TranscriptPrefixV1
                        .init(
                        transcript_prefix_source.noncore_authority_sha_id,
                        transcript_prefix_source.core_authority_sha_id,
                        transcript_prefix_source.core_layout_sha_id,
                        transcript_prefix_source.core_call_buffer_sha_id,
                        transcript_prefix_source.core_total_call_count,
                        transcript_prefix_source.public_wire_boundary,
                    );
                    const admission_boundaries = publication_inputs.boundaries;
                    var component_log_sizes: [verified_artifact.CLAIM_COUNT]u32 =
                        undefined;
                    for (&component_log_sizes, 0..) |*log_size, row| {
                        const placement = manifest.placements[row] orelse
                            return error.CohortContractViolation;
                        log_size.* = placement.geometry.log_size;
                    }
                    var publication_timer = try std.time.Timer.start();
                    const capture_id = verified_publication.captureIdentity(&capture);
                    const transcript_id = recursion.protocol.transcriptId(
                        channel.digestWords(),
                        channel.n_draws,
                    );
                    var domain_totals: [verified_publication.RELATION_DOMAIN_COUNT]verified_publication.Qm31Words = undefined;
                    for (&domain_totals, verified_closure.domain_totals) |*destination, total|
                        destination.* = qm31Words(total);

                    const context = publication_authority.context;
                    var staged = VerifiedSegmentV2PublicationV1{
                        .proof_size_estimate = proof_size_estimate,
                        .canonical_proof_byte_count = proof_identity.byte_count,
                        .canonical_proof_sha_id = proof_identity.canonical_proof_sha_id,
                        .segment_index = context.segment_index,
                        .segment_count = context.segment_count,
                        .global_cycle_start = context.global_cycle_start,
                        .global_cycle_end = context.global_cycle_end,
                        .entry_continuation_root = context.entry_continuation_root,
                        .exit_continuation_root = context.exit_continuation_root,
                        .statement_words = publication_authority.statement_words,
                        .statement_id = context.statement_id,
                        .session_id = context.session_id,
                        .job_id = context.job_id,
                        .position_id = context.position_id,
                        .segment_wire_id = context.segment_wire_id,
                        .entry_lineage_id = context.entry_lineage_id,
                        .exit_lineage_id = context.exit_lineage_id,
                        .lineage_id = context.lineage_id,
                        .source_context_id = context.authenticated_context_id,
                        .recursive_parent_vk_id = context.recursive_parent_vk_id,
                        .verification_key_id = context.segment_leaf_vk_id,
                        .air_program_id = undefined,
                        .manifest_id = undefined,
                        .profile_id = undefined,
                        .capture_id = capture_id,
                        .recursive_witness_id = undefined,
                        .transcript_id = transcript_id,
                        .verifier_context_id = undefined,
                        .proof_id = proof_identity.proof_id,
                        .prepared_leaf_sha_id = publication_authority.prepared_leaf_sha_id,
                        .cohort_authority_sha_id = publication_authority.cohort_authority_sha_id,
                        .manifest_sha_id = publication_authority.manifest_sha_id,
                        .catalog_sha_id = publication_authority.catalog_sha_id,
                        .relation_registry_sha_id = publication_authority.relation_registry_sha_id,
                        .plan_sha_id = publication_authority.plan_sha_id,
                        .closure = .{
                            .active_domain_mask = verified_closure.active_domain_mask,
                            .logical_rows = verified_closure.logical_rows,
                            .event_terms = verified_closure.event_terms,
                            .domain_totals = domain_totals,
                            .framework_total = qm31Words(
                                verified_closure.framework_total,
                            ),
                            .verifier_receipt_id = undefined,
                            .claimed_sums_id = undefined,
                            .relation_replay_id = undefined,
                            .auxiliary_claim_seal_id = undefined,
                            .generated_interactions_sha_id = generated.identity,
                            .claim_seal_sha_id = claims.seal,
                            .audit_sha_id = verified_closure.audit_identity,
                            .closure_receipt_id = undefined,
                        },
                        .publication_id = undefined,
                    };
                    staged.manifest_id = verified_publication.expectedManifestId(
                        staged.manifest_sha_id,
                    );
                    staged.air_program_id =
                        verified_publication.expectedAirProgramId(&staged);
                    staged.profile_id =
                        verified_publication.expectedProfileId(&staged);
                    staged.verifier_context_id =
                        verified_publication.expectedVerifierContextId(&staged);
                    var outer_admission_receipt =
                        verified_artifact.OuterAdmissionReceiptV2{
                            .proof_id = staged.proof_id,
                            .capture_id = staged.capture_id,
                            .component_log_sizes = component_log_sizes,
                            .pre_core_channel = pre_core_channel,
                            .claimed_sums = claims.values,
                            .verifier_input_boundary = admission_boundaries.verifier_input,
                            .wire_closure = .{
                                admission_boundaries.input_wire,
                                admission_boundaries.public_wire,
                            },
                            .receipt_id = undefined,
                        };
                    outer_admission_receipt.receipt_id =
                        verified_artifact.outerAdmissionReceiptId(
                            &outer_admission_receipt,
                            &staged,
                        );
                    var staged_witness = RecursiveWitnessV1{
                        .proof_id = staged.proof_id,
                        .capture_id = staged.capture_id,
                        .statement_id = staged.statement_id,
                        .air_program_id = staged.air_program_id,
                        .manifest_id = staged.manifest_id,
                        .profile_id = staged.profile_id,
                        .claimed_sums = claims.values,
                        .relation_draws = relationDraws(&relations),
                        .poseidon2_partials = generated.core.poseidon2_partials,
                        .transcript_prefix = transcript_prefix,
                        .outer_admission = outer_admission_receipt,
                        .relation_draws_id = undefined,
                        .poseidon2_partials_id = undefined,
                        .witness_id = undefined,
                    };
                    staged_witness.relation_draws_id =
                        verified_artifact.relationDrawsId(&staged_witness, &staged);
                    staged_witness.poseidon2_partials_id =
                        verified_artifact.poseidon2PartialsId(&staged_witness, &staged);
                    staged_witness.witness_id =
                        verified_artifact.witnessId(&staged_witness, &staged);
                    staged.recursive_witness_id = staged_witness.witness_id;
                    staged.closure.claimed_sums_id =
                        verified_publication.expectedClaimedSumsId(&staged);
                    staged.closure.relation_replay_id =
                        verified_publication.expectedRelationReplayId(&staged);
                    staged.closure.auxiliary_claim_seal_id =
                        verified_publication.expectedAuxiliaryClaimSealId(&staged);
                    staged.closure.verifier_receipt_id =
                        verified_publication.expectedVerifierReceiptId(&staged);
                    staged.closure.closure_receipt_id =
                        try verified_publication.expectedTemporalClosureId(
                            &staged.closure,
                        );
                    staged.publication_id =
                        verified_publication.expectedPublicationId(&staged);
                    try staged.validate();
                    try staged_witness.validateAgainstValidatedPublication(
                        &staged,
                        manifest,
                    );
                    const publication_ns = publication_timer.read();
                    const publication_total_ns = phase_timer.lap();

                    // Disjoint body spans. Existing stark_verify_ns and publication_ns
                    // are nested subspans, not additional work to add to this sum.
                    std.debug.print("\nSEGMENT_V2_OUTER_PHASES role=verifier scope=body_before_cleanup preflight_ns={d} preprocessed_root_ns={d} transcript_prefix_ns={d} interaction_regenerate_ns={d} interaction_validate_claims_ns={d} closure_ns={d} transcript_after_ns={d} components_ns={d} publication_authority_ns={d} stark_ns={d} publication_total_ns={d} phase_sum_ns={d}\n", .{
                        preflight_ns,
                        preprocessed_root_ns,
                        transcript_prefix_ns,
                        interaction_regenerate_ns,
                        interaction_validate_claims_ns,
                        closure_ns,
                        transcript_after_ns,
                        components_ns,
                        publication_authority_ns,
                        stark_ns,
                        publication_total_ns,
                        preflight_ns + preprocessed_root_ns + transcript_prefix_ns + interaction_regenerate_ns + interaction_validate_claims_ns + closure_ns + transcript_after_ns + components_ns + publication_authority_ns + stark_ns + publication_total_ns,
                    });
                    // Aliasing was rejected before work began.  All fallible work is
                    // complete, so these are the transaction's only output writes.
                    publication_out.* = staged;
                    witness_out.* = staged_witness;
                    capture_out.* = capture;
                    return .{ .publication_ns = publication_ns, .stark_verify_ns = stark_verify_ns };
                }

                fn assertPreprocessedRoot(
                    allocator: std.mem.Allocator,
                    cohort: *Cohort,
                    actual: recursion.engine.Hasher.Hash,
                ) !void {
                    const manifest = cohort.manifest();
                    var scheme = try Engine.init(allocator, OUTER_CONFIG);
                    defer Engine.deinit(&scheme, allocator);
                    var channel = Engine.Channel{};
                    var tree = try TreeStorage.init(
                        allocator,
                        manifest,
                        manifest_mod.PREPROCESSED_TREE_INDEX,
                    );
                    defer tree.deinit();
                    try cohort.fillPreprocessedInto(manifest, tree.columns);
                    try tree.commit(&scheme, &channel);
                    try Engine.flushPendingCommit(&scheme, allocator, &channel);
                    var roots = try scheme.roots(allocator);
                    defer roots.deinit(allocator);
                    if (roots.items.len != 1 or !std.meta.eql(roots.items[0], actual))
                        return error.PreprocessedRootMismatch;
                }
            };
        }
    };
}
