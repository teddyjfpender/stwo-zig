//! Cohesive internal authority extracted from recursive_fri_outer.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const M31 = context.d_M31;
        const recursion = context.d_recursion;
        const air = context.d_air;
        const pcs_witness = context.d_pcs_witness;
        const input_witness = context.d_input_witness;
        const lowering = context.d_lowering;
        const manifest_mod = context.d_manifest_mod;
        const shared_provider = context.d_shared_provider;
        const universal = context.d_universal;
        const MAX_ARITHMETIC_EVALUATION_LANES = context.d_MAX_ARITHMETIC_EVALUATION_LANES;
        const Engine = context.d_Engine;
        const PCS_SEGMENT_CIRCUIT_ID = context.d_PCS_SEGMENT_CIRCUIT_ID;
        const PCS_LEFT_CIRCUIT_ID = context.d_PCS_LEFT_CIRCUIT_ID;
        const PCS_RIGHT_CIRCUIT_ID = context.d_PCS_RIGHT_CIRCUIT_ID;
        const COMPOSITION_DIAGNOSTIC_ENV = context.d_COMPOSITION_DIAGNOSTIC_ENV;
        const CLOSURE_DIAGNOSTIC_ENV = context.d_CLOSURE_DIAGNOSTIC_ENV;
        const OUTER_CONFIG = context.d_OUTER_CONFIG;
        const VerifierPlans = context.d_VerifierPlans;
        const SegmentTranscriptInputs = context.d_SegmentTranscriptInputs;
        const PreparedQueryWitness = context.d_PreparedQueryWitness;
        const AssemblyProfile = context.d_AssemblyProfile;
        const ClosureAudit = context.d_ClosureAudit;
        const ProofBundle = context.d_ProofBundle;
        const ProofExecutionPool = context.d_ProofExecutionPool;
        const PreparedRelationRows = context.d_PreparedRelationRows;
        const ScheduleFacts = context.d_ScheduleFacts;
        const Authority = context.d_Authority;
        const InvocationBuffers = context.d_InvocationBuffers;
        const MerklePathBuffers = context.d_MerklePathBuffers;
        const PoseidonCallBuffers = context.d_PoseidonCallBuffers;
        const buildArithmeticEvaluations = context.d_buildArithmeticEvaluations;
        const Components = context.d_Components;
        const fillPreprocessed = context.d_fillPreprocessed;
        const fillMain = context.d_fillMain;
        const fillInteraction = context.d_fillInteraction;
        const claimVector = context.d_claimVector;
        const mixAuthority = context.d_mixAuthority;
        const mixPublicBoundaries = context.d_mixPublicBoundaries;
        const verifyGlobalClosure = context.d_verifyGlobalClosure;
        const diagnoseGlobalClosure = context.d_diagnoseGlobalClosure;
        const diagnoseCompositionComponents = context.d_diagnoseCompositionComponents;
        const stageTelemetryBegin = context.d_stageTelemetryBegin;
        const stageTelemetryEnd = context.d_stageTelemetryEnd;
        const stageTelemetryCommitPool = context.d_stageTelemetryCommitPool;
        const stageTelemetrySampledValuesPool = context.d_stageTelemetrySampledValuesPool;
        const TreeStorage = context.d_TreeStorage;

        pub fn proveCaptured(
            allocator: std.mem.Allocator,
            captured: *const recursion.captured_fri.Owned,
            vm_air: ?*const recursion.vm_air_composition_circuit.Prepared,
            verifier_plans: ?VerifierPlans,
            segment_transcript: ?SegmentTranscriptInputs,
            execution_pool: *ProofExecutionPool,
        ) !ProofBundle {
            var assembly_timer = try std.time.Timer.start();
            var phase_timer = try std.time.Timer.start();
            var assembly_profile: AssemblyProfile = .{};
            var inactive = try captured.evaluateInactive();
            defer inactive.deinit();
            var pcs_inactive = try captured.evaluatePcsInactive();
            defer pcs_inactive.deinit();
            stageTelemetryBegin("prover.authority-init");
            var authority_timer = try std.time.Timer.start();
            var authority = try Authority.init(
                allocator,
                &captured.circuit,
                &captured.pcs_circuit,
                captured.trace_tree_heights,
                captured.column_log_sizes,
                ScheduleFacts.fromCaptured(captured),
                vm_air,
                verifier_plans,
                segment_transcript,
                null,
                0,
            );
            stageTelemetryEnd("prover.authority-init", authority_timer.read());
            defer authority.deinit();
            var prepared_query = try PreparedQueryWitness.init(
                allocator,
                captured,
                segment_transcript,
            );
            defer prepared_query.deinit();
            const query_witness = prepared_query.value;
            const merkle_root_witness_value = captured.merkleRootWitness();
            const trace_opening_witness = captured.traceOpeningWitness();
            const fri_opening_witness = captured.friOpeningWitness();
            const evaluations = input_witness.Evaluations{
                .segment = &captured.evaluation,
                .left = &inactive,
                .right = &inactive,
            };
            const pcs_input_count = captured.pcs_circuit.bindings.len;
            const pcs_active_inputs = try allocator.alloc(M31, pcs_input_count);
            defer allocator.free(pcs_active_inputs);
            const pcs_inactive_inputs = try allocator.alloc(M31, pcs_input_count);
            defer allocator.free(pcs_inactive_inputs);
            try captured.pcs_circuit.inputValuesInto(
                &captured.pcs_evaluation,
                pcs_active_inputs,
            );
            try captured.pcs_circuit.inputValuesInto(
                &pcs_inactive,
                pcs_inactive_inputs,
            );
            const pcs_graph_digest = captured.pcs_circuit.graph().identity_digest;
            const pcs_inputs = pcs_witness.InputWitness{ .lanes = .{
                .{
                    .verifier_id = pcs_witness.SEGMENT_VERIFIER_ID,
                    .circuit_id = PCS_SEGMENT_CIRCUIT_ID,
                    .graph_digest = pcs_graph_digest,
                    .input_values = pcs_active_inputs,
                },
                .{
                    .verifier_id = pcs_witness.LEFT_RECURSION_VERIFIER_ID,
                    .circuit_id = PCS_LEFT_CIRCUIT_ID,
                    .graph_digest = pcs_graph_digest,
                    .input_values = pcs_inactive_inputs,
                },
                .{
                    .verifier_id = pcs_witness.RIGHT_RECURSION_VERIFIER_ID,
                    .circuit_id = PCS_RIGHT_CIRCUIT_ID,
                    .graph_digest = pcs_graph_digest,
                    .input_values = pcs_inactive_inputs,
                },
            } };
            var arithmetic_evaluation_storage: [MAX_ARITHMETIC_EVALUATION_LANES]lowering.Evaluation = undefined;
            const arithmetic_evaluations = try buildArithmeticEvaluations(
                &authority,
                captured,
                &inactive,
                null,
                &arithmetic_evaluation_storage,
            );
            var invocations = try InvocationBuffers.init(
                allocator,
                authority.lowering_plan.counts(.segment_leaf),
            );
            defer invocations.deinit();
            var merkle_paths = try MerklePathBuffers.init(allocator, captured);
            defer merkle_paths.deinit();
            var poseidon_calls = try PoseidonCallBuffers.init(
                allocator,
                authority.poseidon2_row_count,
            );
            defer poseidon_calls.deinit();
            var prepared_relation_rows = try PreparedRelationRows.init(allocator, &authority);
            defer prepared_relation_rows.deinit();
            try authority.lowering_plan.materializeInto(
                authority.arithmetic_reference,
                arithmetic_evaluations,
                .segment_leaf,
                invocations.view(),
            );

            const composition_diagnostic_enabled =
                std.process.hasEnvVarConstant(COMPOSITION_DIAGNOSTIC_ENV);
            var scheme = try Engine.init(allocator, OUTER_CONFIG);
            // The outer verifier never opens committed columns after proving.  Retaining
            // their interpolated coefficients only duplicates hundreds of MiB of live
            // state across the wide recursive trace. The opt-in composition
            // differential is the sole exception because it deliberately evaluates
            // each committed polynomial before proving.
            const retention_policy: @TypeOf(scheme.coefficient_retention_policy) =
                if (composition_diagnostic_enabled) .always else .never;
            scheme.setCoefficientRetentionPolicy(retention_policy);
            if (scheme.coefficient_retention_policy != retention_policy)
                return error.DiagnosticRetentionPolicyMismatch;
            var scheme_moved = false;
            defer if (!scheme_moved) Engine.deinit(&scheme, allocator);
            var channel = Engine.Channel{};
            assembly_profile.setup_ns = phase_timer.lap();

            var preprocessed = try TreeStorage.init(
                allocator,
                &authority.manifest,
                manifest_mod.PREPROCESSED_TREE_INDEX,
            );
            defer preprocessed.deinit();
            stageTelemetryBegin("prover.preprocessed-fill");
            try fillPreprocessed(&authority, &preprocessed);
            assembly_profile.preprocessed_fill_ns = phase_timer.lap();
            stageTelemetryEnd(
                "prover.preprocessed-fill",
                assembly_profile.preprocessed_fill_ns,
            );
            stageTelemetryBegin("prover.preprocessed-commit");
            try stageTelemetryCommitPool(
                "prover.preprocessed-commit",
                execution_pool,
                preprocessed.evaluations,
            );
            try preprocessed.commit(&scheme, &channel);
            try Engine.flushPendingCommit(&scheme, allocator, &channel);
            assembly_profile.preprocessed_commit_ns = phase_timer.lap();
            stageTelemetryEnd(
                "prover.preprocessed-commit",
                assembly_profile.preprocessed_commit_ns,
            );

            var main = try TreeStorage.init(
                allocator,
                &authority.manifest,
                manifest_mod.MAIN_TREE_INDEX,
            );
            defer main.deinit();
            stageTelemetryBegin("prover.main-fill");
            try fillMain(
                &authority,
                &main,
                evaluations,
                pcs_inputs,
                &invocations,
                query_witness,
                merkle_root_witness_value,
                trace_opening_witness,
                fri_opening_witness,
                captured,
                &merkle_paths,
                &poseidon_calls,
                &prepared_relation_rows,
            );
            assembly_profile.main_fill_ns = phase_timer.lap();
            stageTelemetryEnd("prover.main-fill", assembly_profile.main_fill_ns);
            stageTelemetryBegin("prover.main-commit");
            try stageTelemetryCommitPool(
                "prover.main-commit",
                execution_pool,
                main.evaluations,
            );
            try main.commit(&scheme, &channel);
            try Engine.flushPendingCommit(&scheme, allocator, &channel);
            assembly_profile.main_commit_ns = phase_timer.lap();
            stageTelemetryEnd("prover.main-commit", assembly_profile.main_commit_ns);

            try authority.manifest.mixStatementPrefix(&channel);
            mixAuthority(&channel, &authority);
            const relations = try universal.UniversalRelations.draw(allocator, &channel);
            const provider_relations = try shared_provider.SharedProviderRelations.init(
                &relations,
            );
            var interaction = try TreeStorage.init(
                allocator,
                &authority.manifest,
                manifest_mod.INTERACTION_TREE_INDEX,
            );
            defer interaction.deinit();
            stageTelemetryBegin("prover.interaction-fill");
            var closure_audit = ClosureAudit.init(allocator, true);
            defer closure_audit.deinit();
            const closure_audit_out: ?*ClosureAudit = if (std.process.hasEnvVarConstant(
                CLOSURE_DIAGNOSTIC_ENV,
            )) &closure_audit else null;
            const claims = try fillInteraction(
                allocator,
                &authority,
                &interaction,
                evaluations,
                pcs_inputs,
                arithmetic_evaluations,
                &invocations,
                query_witness,
                merkle_root_witness_value,
                &merkle_paths,
                &poseidon_calls,
                &prepared_relation_rows,
                &provider_relations,
                &relations,
                closure_audit_out,
            );
            assembly_profile.interaction_fill_ns = phase_timer.lap();
            stageTelemetryEnd(
                "prover.interaction-fill",
                assembly_profile.interaction_fill_ns,
            );
            var claim_vector = try claimVector(&authority.manifest, claims);
            stageTelemetryBegin("prover.global-closure");
            var closure_timer = try std.time.Timer.start();
            if (closure_audit_out) |audit|
                try diagnoseGlobalClosure(audit, &claim_vector, claims);
            try claims.verifyWireClosure();
            try verifyGlobalClosure(&claim_vector, claims.public_boundaries);
            stageTelemetryEnd("prover.global-closure", closure_timer.read());
            try claim_vector.mixInteractionClaims(&authority.manifest, &channel);
            mixPublicBoundaries(&channel, claims);
            var components = try Components.init(
                &authority,
                &relations,
                &provider_relations,
                claims,
            );
            defer components.deinit();
            stageTelemetryBegin("prover.interaction-commit");
            try stageTelemetryCommitPool(
                "prover.interaction-commit",
                execution_pool,
                interaction.evaluations,
            );
            try interaction.commit(&scheme, &channel);
            assembly_profile.interaction_commit_ns = phase_timer.lap();
            stageTelemetryEnd(
                "prover.interaction-commit",
                assembly_profile.interaction_commit_ns,
            );
            var gate = try manifest_mod.ProofGate.init(&authority.manifest);
            try components.append(&gate, &authority.manifest);
            try gate.sealGate(&authority.manifest);
            if (composition_diagnostic_enabled) {
                try Engine.flushPendingCommit(&scheme, allocator, &channel);
                if (scheme.pending_commit != null) return error.DiagnosticPendingCommit;
                if (scheme.trees.items.len != manifest_mod.TREE_COUNT)
                    return error.DiagnosticTreeCountMismatch;
                const diagnostic_provers = try gate.proverSlice();
                const diagnostic_verifiers = try gate.verifierSlice();
                if (diagnostic_provers.len != air.universal_roster.COMPONENT_COUNT or
                    diagnostic_verifiers.len != air.universal_roster.COMPONENT_COUNT)
                {
                    return error.DiagnosticRosterMismatch;
                }
                try diagnoseCompositionComponents(
                    allocator,
                    &scheme,
                    diagnostic_provers,
                    diagnostic_verifiers,
                    authority.manifest.total_preprocessed_columns,
                );
            }
            assembly_profile.component_seal_ns = phase_timer.lap();
            const assembly_ns = assembly_timer.read();
            std.debug.assert(assembly_profile.total() <= assembly_ns);
            var stark_prove_timer = try std.time.Timer.start();
            scheme_moved = true;
            stageTelemetryBegin("prover.stark-prove");
            try stageTelemetrySampledValuesPool(
                execution_pool,
                manifest_mod.TREE_COUNT + 1,
            );
            var extended = try Engine.prove(
                allocator,
                try gate.proverSlice(),
                &channel,
                scheme,
                .{},
            );
            const stark_prove_ns = stark_prove_timer.read();
            stageTelemetryEnd("prover.stark-prove", stark_prove_ns);
            defer extended.aux.deinit(allocator);
            const proof = extended.proof;
            extended.proof = undefined;
            return .{
                .proof = proof,
                .claims = claims,
                .log_sizes = authority.log_sizes,
                .geometry = authority.geometry(),
                .transcript_draws = channel.n_draws,
                .assembly_ns = assembly_ns,
                .assembly_profile = assembly_profile,
                .stark_prove_ns = stark_prove_ns,
                .poseidon2_call_count = authority.poseidon2_row_count,
                .pcs_graph_nodes = captured.pcs_circuit.nodes.len,
                .pcs_graph_inputs = captured.pcs_circuit.bindings.len,
                .pcs_graph_outputs = captured.pcs_circuit.outputs.len,
                .arithmetic_active_counts = .{
                    authority.lowering_plan.counts(.segment_leaf).multiply,
                    authority.lowering_plan.counts(.segment_leaf).inverse,
                    authority.lowering_plan.counts(.segment_leaf).linear,
                },
                .arithmetic_capacity_rows = .{
                    authority.lowering_plan.multiply_rows.len,
                    authority.lowering_plan.inverse_rows.len,
                    authority.lowering_plan.linear_rows.len,
                },
            };
        }

        pub const VerificationMetrics = struct {
            exact_domain_closure_checked: bool = false,
            exact_domain_closure_ns: u64 = 0,
        };
    };
}
