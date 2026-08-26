//! Cohesive internal authority extracted from recursive_fri_outer.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const M31 = context.d_M31;
        const recursion = context.d_recursion;
        const pcs_witness = context.d_pcs_witness;
        const input_witness = context.d_input_witness;
        const lowering = context.d_lowering;
        const MAX_ARITHMETIC_EVALUATION_LANES = context.d_MAX_ARITHMETIC_EVALUATION_LANES;
        const OuterProofCapture = context.d_OuterProofCapture;
        const VerifiedOuterProofV1 = context.d_VerifiedOuterProofV1;
        const VerifiedOuterProofV2 = context.d_VerifiedOuterProofV2;
        const PCS_SEGMENT_CIRCUIT_ID = context.d_PCS_SEGMENT_CIRCUIT_ID;
        const PCS_LEFT_CIRCUIT_ID = context.d_PCS_LEFT_CIRCUIT_ID;
        const PCS_RIGHT_CIRCUIT_ID = context.d_PCS_RIGHT_CIRCUIT_ID;
        const CLOSURE_DIAGNOSTIC_ENV = context.d_CLOSURE_DIAGNOSTIC_ENV;
        const MutationProbeMode = context.d_MutationProbeMode;
        const ExecutionOptions = context.d_ExecutionOptions;
        const TupleClosureFrontierReceipt = context.d_TupleClosureFrontierReceipt;
        const TUPLE_CLOSURE_FRONTIER_MASK = context.d_TUPLE_CLOSURE_FRONTIER_MASK;
        const VerifierPlans = context.d_VerifierPlans;
        const SegmentTranscriptInputs = context.d_SegmentTranscriptInputs;
        const PreparedQueryWitness = context.d_PreparedQueryWitness;
        const AssemblyProfile = context.d_AssemblyProfile;
        const proveAndVerifyCapturedImpl = context.d_proveAndVerifyCapturedImpl;
        const TupleLedger = context.d_TupleLedger;
        const PreparedRelationRows = context.d_PreparedRelationRows;
        const ScheduleFacts = context.d_ScheduleFacts;
        const Authority = context.d_Authority;
        const InvocationBuffers = context.d_InvocationBuffers;
        const MerklePathBuffers = context.d_MerklePathBuffers;
        const buildArithmeticEvaluations = context.d_buildArithmeticEvaluations;
        const prepareTupleClassifierRows = context.d_prepareTupleClassifierRows;
        const collectTupleClosureFrontier = context.d_collectTupleClosureFrontier;
        const diagnoseTupleClosureReport = context.d_diagnoseTupleClosureReport;

        pub const Receipt = struct {
            proof_size_estimate: usize,
            prove_ns: u64,
            assembly_ns: u64,
            assembly_profile: AssemblyProfile,
            stark_prove_ns: u64,
            verify_ns: u64,
            vm_input_log_size: u32,
            composition_control_log_size: u32,
            input_log_size: u32,
            query_bits_log_size: u32,
            query_mapping_log_size: u32,
            merkle_root_log_size: u32,
            trace_merkle_log_size: u32,
            pcs_deep_log_size: u32,
            fri_leaf_log_size: u32,
            fri_node_log_size: u32,
            fri_anchor_log_size: u32,
            control_log_size: u32,
            multiply_log_size: u32,
            inverse_log_size: u32,
            linear_log_size: u32,
            merkle_path_log_size: u32,
            poseidon2_log_size: u32,
            poseidon2_call_count: u32,
            pcs_graph_nodes: usize,
            pcs_graph_inputs: usize,
            pcs_graph_outputs: usize,
            vm_graph_nodes: usize,
            vm_graph_inputs: usize,
            vm_graph_outputs: usize,
            vm_schedule_rows: usize,
            arithmetic_active_counts: [3]usize,
            arithmetic_capacity_rows: [3]usize,
            worker_count: usize,
            preprocessed_columns: u32,
            main_columns: u32,
            interaction_columns: u32,
            constraints: u32,
            roster_count: u8,
            active_verifier_rows: u8,
            active_provider_rows: u8,
            transcript_draws: usize,
            mutation_probe_mode: MutationProbeMode,
            mutation_rejections: u8,
            exact_domain_closure_checked: bool,
            exact_domain_closure_ns: u64,
        };

        pub fn proveAndVerifyCaptured(
            allocator: std.mem.Allocator,
            captured: *const recursion.captured_fri.Owned,
        ) !Receipt {
            return proveAndVerifyCapturedWithExecution(allocator, captured, .{});
        }

        pub fn proveAndVerifyCapturedWithExecution(
            allocator: std.mem.Allocator,
            captured: *const recursion.captured_fri.Owned,
            execution: ExecutionOptions,
        ) !Receipt {
            return proveAndVerifyCapturedImpl(
                allocator,
                captured,
                null,
                null,
                null,
                execution,
                null,
            );
        }

        /// Extends the captured FRI outer proof with production row 18 and folds its
        /// authenticated VM composition DAG into the same shared arithmetic rows.
        pub fn proveAndVerifyCapturedWithVmAirExecution(
            allocator: std.mem.Allocator,
            captured: *const recursion.captured_fri.Owned,
            vm_air: *const recursion.vm_air_composition_circuit.Prepared,
            verifier_plans: VerifierPlans,
            segment_transcript: SegmentTranscriptInputs,
            execution: ExecutionOptions,
        ) !Receipt {
            try vm_air.validate();
            return proveAndVerifyCapturedImpl(
                allocator,
                captured,
                vm_air,
                verifier_plans,
                segment_transcript,
                execution,
                null,
            );
        }

        /// Production-equivalent outer proving with transactional publication of only
        /// the proof material authenticated by the successful independent verifier.
        /// This is the native-to-recursive custody boundary used by a subsequent
        /// binary node; `capture_out` is untouched on every failure.
        pub fn proveAndVerifyCapturedWithVmAirExecutionAndCapture(
            allocator: std.mem.Allocator,
            captured: *const recursion.captured_fri.Owned,
            vm_air: *const recursion.vm_air_composition_circuit.Prepared,
            verifier_plans: VerifierPlans,
            segment_transcript: SegmentTranscriptInputs,
            execution: ExecutionOptions,
            capture_out: *OuterProofCapture,
        ) !Receipt {
            try vm_air.validate();
            return proveAndVerifyCapturedImpl(
                allocator,
                captured,
                vm_air,
                verifier_plans,
                segment_transcript,
                execution,
                .{ .capture = capture_out },
            );
        }

        /// Production-equivalent outer proving with fail-atomic publication of the
        /// complete trusted child-admission bundle. `verified_out` is untouched unless
        /// native STARK verification, receipt construction, capture validation, and
        /// verifier-seal derivation all succeed.
        pub fn proveAndVerifyCapturedWithVmAirExecutionAndAdmission(
            allocator: std.mem.Allocator,
            captured: *const recursion.captured_fri.Owned,
            vm_air: *const recursion.vm_air_composition_circuit.Prepared,
            verifier_plans: VerifierPlans,
            segment_transcript: SegmentTranscriptInputs,
            execution: ExecutionOptions,
            verified_out: *VerifiedOuterProofV1,
        ) !Receipt {
            try vm_air.validate();
            return proveAndVerifyCapturedImpl(
                allocator,
                captured,
                vm_air,
                verifier_plans,
                segment_transcript,
                execution,
                .{ .verified = verified_out },
            );
        }

        /// Explicit V2 admission. The proof and V1 transcript are unchanged; the
        /// successful independent verifier additionally publishes its exact 47-domain
        /// segment closure. `verified_out` is untouched on every failure.
        pub fn proveAndVerifyCapturedWithVmAirExecutionAndAdmissionV2(
            allocator: std.mem.Allocator,
            captured: *const recursion.captured_fri.Owned,
            vm_air: *const recursion.vm_air_composition_circuit.Prepared,
            verifier_plans: VerifierPlans,
            segment_transcript: SegmentTranscriptInputs,
            execution: ExecutionOptions,
            verified_out: *VerifiedOuterProofV2,
        ) !Receipt {
            try vm_air.validate();
            return proveAndVerifyCapturedImpl(
                allocator,
                captured,
                vm_air,
                verifier_plans,
                segment_transcript,
                execution,
                .{ .verified_v2 = verified_out },
            );
        }

        /// Builds the exact authenticated relation tuples needed by the current
        /// closure frontier and classifies them before any relation challenge,
        /// denominator inversion, commitment, or STARK proof is constructed. The
        /// caller supplies an already verified capture and already prepared segment
        /// sources, so this function also performs no native proof replay.
        pub fn classifyCapturedTupleClosureWithVmAir(
            allocator: std.mem.Allocator,
            captured: *const recursion.captured_fri.Owned,
            vm_air: *const recursion.vm_air_composition_circuit.Prepared,
            verifier_plans: VerifierPlans,
            segment_transcript: SegmentTranscriptInputs,
        ) !TupleClosureFrontierReceipt {
            try vm_air.validate();
            try captured.evaluation.validateAgainst(&captured.circuit);
            try captured.pcs_evaluation.validateAgainst(&captured.pcs_circuit);
            var timer = try std.time.Timer.start();

            var inactive = try captured.evaluateInactive();
            defer inactive.deinit();
            var pcs_inactive = try captured.evaluatePcsInactive();
            defer pcs_inactive.deinit();
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
            defer authority.deinit();

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
            try authority.lowering_plan.materializeInto(
                authority.arithmetic_reference,
                arithmetic_evaluations,
                .segment_leaf,
                invocations.view(),
            );
            var merkle_paths = try MerklePathBuffers.init(allocator, captured);
            defer merkle_paths.deinit();
            var prepared_relation_rows = try PreparedRelationRows.init(
                allocator,
                &authority,
            );
            defer prepared_relation_rows.deinit();
            const setup_ns = timer.lap();

            var prepared_query = try PreparedQueryWitness.init(
                allocator,
                captured,
                segment_transcript,
            );
            defer prepared_query.deinit();
            const query_witness = prepared_query.value;
            const root_witness = captured.merkleRootWitness();
            try prepareTupleClassifierRows(
                &authority,
                captured,
                captured.traceOpeningWitness(),
                captured.friOpeningWitness(),
                query_witness,
                &merkle_paths,
                &prepared_relation_rows,
            );
            const row_prepare_ns = timer.lap();

            var ledger = TupleLedger.init(allocator);
            defer ledger.deinit();
            try collectTupleClosureFrontier(
                allocator,
                &authority,
                evaluations,
                pcs_inputs,
                &invocations,
                query_witness,
                root_witness,
                &merkle_paths,
                &prepared_relation_rows,
                &ledger,
            );
            const report = ledger.classify();
            if (std.process.hasEnvVarConstant(CLOSURE_DIAGNOSTIC_ENV))
                try diagnoseTupleClosureReport(&ledger, report);
            const classify_ns = timer.lap();
            return .{
                .domain_mask = TUPLE_CLOSURE_FRONTIER_MASK,
                .report = report,
                .setup_ns = setup_ns,
                .row_prepare_ns = row_prepare_ns,
                .classify_ns = classify_ns,
            };
        }
    };
}
