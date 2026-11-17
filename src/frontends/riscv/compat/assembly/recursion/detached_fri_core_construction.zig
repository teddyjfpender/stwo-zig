//! Failure-atomic detached core admission and cold witness preparation.
pub fn Namespace(comptime context: type, comptime NativeSegmentCoreV2: type, comptime PreparedInputsV4: type, comptime poseidonBuffers: anytype, comptime poseidonBuffersMut: anytype) type {
    return struct {
        const std = context.d_std;
        const M31 = context.d_M31;
        const recursion = context.d_recursion;
        const schedule = context.d_schedule;
        const lowering = context.d_lowering;
        const manifest_mod = context.d_manifest_mod;
        const shared_schedule_v2 = context.d_shared_schedule_v2;
        const public_native_sum = context.d_public_native_sum;
        const LogIndex = context.d_LogIndex;
        const MAX_ARITHMETIC_EVALUATION_LANES = context.d_MAX_ARITHMETIC_EVALUATION_LANES;
        const NativeSegmentCoreAuthorityInputsV4 = context.d_NativeSegmentCoreAuthorityInputsV4;
        const validateMaterializedArithmeticLane = context.d_validateMaterializedArithmeticLane;
        const nativeV2CoreStageFailure = context.d_nativeV2CoreStageFailure;
        const VerifierPlans = context.d_VerifierPlans;
        const PreparedQueryWitness = context.d_PreparedQueryWitness;
        const PreparedRelationRows = context.d_PreparedRelationRows;
        const ScheduleFacts = context.d_ScheduleFacts;
        const Authority = context.d_Authority;
        const InvocationBuffers = context.d_InvocationBuffers;
        const MerklePathBuffers = context.d_MerklePathBuffers;
        const PoseidonCallBuffers = context.d_PoseidonCallBuffers;
        const buildArithmeticEvaluations = context.d_buildArithmeticEvaluations;
        const fillPreprocessed = context.d_fillPreprocessed;
        const fillMainConsumers = context.d_fillMainConsumers;
        const nativeCoreAuthorityIdentity = context.d_nativeCoreAuthorityIdentity;
        const TreeStorage = context.d_TreeStorage;
        const AuthorityInputs = NativeSegmentCoreV2.AuthorityInputs;

        pub fn init(
            allocator: std.mem.Allocator,
            inputs: AuthorityInputs,
        ) !NativeSegmentCoreV2 {
            inputs.validate() catch |err|
                return nativeV2CoreStageFailure("inputs", err);
            return initAuthenticated(
                allocator,
                inputs.captured,
                inputs.vm_air,
                inputs.verifier_plans,
                inputs.public_native_sum_source.loweringLane(),
                try inputs.public_native_sum_evaluation.loweringEvaluation(
                    inputs.public_native_sum_source,
                ),
                inputs.public_native_sum_evaluation.identity,
                null,
                .{ .legacy = .{
                    .prepared = inputs.transcript_prepared,
                    .program = inputs.transcript_program,
                    .execution = inputs.transcript_execution,
                    .plan = inputs.transcript_plan,
                } },
                inputs.boundary_layout,
                inputs.boundary_calls,
                null,
            );
        }

        /// Versioned sibling for a native capture whose public arithmetic
        /// graph and complete q193 query words are authenticated by newer
        /// typed owners.  The frozen SegmentV2 constructor above remains
        /// byte- and API-identical.
        pub fn initVersionedV4(
            allocator: std.mem.Allocator,
            inputs: NativeSegmentCoreAuthorityInputsV4,
        ) !NativeSegmentCoreV2 {
            inputs.validate() catch |err|
                return nativeV2CoreStageFailure("versioned-inputs", err);
            return initAuthenticated(
                allocator,
                inputs.captured,
                inputs.vm_air,
                inputs.verifier_plans,
                inputs.public_native_sum_lane,
                inputs.public_native_sum_evaluation,
                inputs.public_native_sum_evaluation_id,
                inputs.statement_arithmetic,
                .{ .full_words = inputs.full_query_words },
                inputs.boundary_layout,
                inputs.boundary_calls,
                null,
            );
        }

        /// Target-native sibling for role-specific padding remints. The
        /// requested domains are consumed before any tree allocation, so
        /// every column is genuinely regenerated at the target.
        pub fn initVersionedV4ForLogSizes(
            allocator: std.mem.Allocator,
            inputs: NativeSegmentCoreAuthorityInputsV4,
            requested_log_sizes: [LogIndex.count]u32,
        ) !NativeSegmentCoreV2 {
            inputs.validate() catch |err|
                return nativeV2CoreStageFailure("versioned-padded-inputs", err);
            return initAuthenticated(
                allocator,
                inputs.captured,
                inputs.vm_air,
                inputs.verifier_plans,
                inputs.public_native_sum_lane,
                inputs.public_native_sum_evaluation,
                inputs.public_native_sum_evaluation_id,
                inputs.statement_arithmetic,
                .{ .full_words = inputs.full_query_words },
                inputs.boundary_layout,
                inputs.boundary_calls,
                requested_log_sizes,
            );
        }

        const QueryAuthorityV4 = union(enum) {
            legacy: struct {
                prepared: *const context.d_segment_transcript_source_v2.PreparedV2,
                program: *const recursion.transcript_program_v2.Program,
                execution: *const recursion.transcript_program_v2.Execution,
                plan: *const schedule.Plan,
            },
            full_words: []const M31,
        };

        pub fn initAuthenticated(
            allocator: std.mem.Allocator,
            captured: *const recursion.captured_fri.Owned,
            vm_air: recursion.vm_composition_preparation.Source,
            verifier_plans: VerifierPlans,
            public_lane: lowering.Lane,
            public_evaluation: lowering.Evaluation,
            public_evaluation_id: [32]u8,
            statement_arithmetic: ?*const recursion.statement_arithmetic_preparation.Prepared,
            query_authority: QueryAuthorityV4,
            boundary_layout: *const shared_schedule_v2.SharedPoseidonCallLayoutV2,
            boundary_calls: []const shared_schedule_v2.Call,
            requested_log_sizes: ?[LogIndex.count]u32,
        ) !NativeSegmentCoreV2 {
            const boundary_prefix_count = boundary_calls.len;
            var authority = Authority.initWithStatementArithmetic(
                allocator,
                &captured.circuit,
                &captured.pcs_circuit,
                captured.trace_tree_heights,
                captured.column_log_sizes,
                ScheduleFacts.fromCaptured(captured),
                vm_air,
                verifier_plans,
                null,
                public_lane,
                boundary_prefix_count,
                requested_log_sizes,
                statement_arithmetic,
            ) catch |err| return nativeV2CoreStageFailure("authority", err);
            errdefer authority.deinit();
            var inactive = try captured.evaluateInactive();
            errdefer inactive.deinit();
            var pcs_inactive = try captured.evaluatePcsInactive();
            errdefer pcs_inactive.deinit();
            var prepared_query = switch (query_authority) {
                .legacy => |legacy| try PreparedQueryWitness.initV2(
                    allocator,
                    captured,
                    legacy.prepared,
                    legacy.program,
                    legacy.execution,
                    legacy.plan,
                ),
                .full_words => |words| try PreparedQueryWitness.initFullWordsV2(
                    allocator,
                    captured,
                    words,
                ),
            };
            errdefer prepared_query.deinit();

            const pcs_input_count = captured.pcs_circuit.view().bindings.len;
            const pcs_active_inputs = try allocator.alloc(M31, pcs_input_count);
            errdefer allocator.free(pcs_active_inputs);
            const pcs_inactive_inputs = try allocator.alloc(M31, pcs_input_count);
            errdefer allocator.free(pcs_inactive_inputs);
            try captured.pcs_circuit.inputValuesInto(
                &captured.pcs_evaluation,
                pcs_active_inputs,
            );
            try captured.pcs_circuit.inputValuesInto(
                &pcs_inactive,
                pcs_inactive_inputs,
            );

            var invocations = try InvocationBuffers.init(
                allocator,
                authority.lowering_plan.counts(.segment_leaf),
            );
            errdefer invocations.deinit();
            var merkle_paths = try MerklePathBuffers.init(allocator, captured);
            errdefer merkle_paths.deinit();
            var poseidon_calls = try PoseidonCallBuffers.init(
                allocator,
                authority.poseidon2_row_count,
            );
            errdefer poseidon_calls.deinit();
            try poseidon_calls.appendAuthenticatedPrefix(boundary_calls);
            var prepared_relation_rows = try PreparedRelationRows.init(
                allocator,
                &authority,
            );
            errdefer prepared_relation_rows.deinit();
            var preprocessed_tree = try TreeStorage.init(
                allocator,
                &authority.manifest,
                manifest_mod.PREPROCESSED_TREE_INDEX,
            );
            errdefer preprocessed_tree.deinit();
            var main_tree = try TreeStorage.init(
                allocator,
                &authority.manifest,
                manifest_mod.MAIN_TREE_INDEX,
            );
            errdefer main_tree.deinit();
            var interaction_tree = try TreeStorage.init(
                allocator,
                &authority.manifest,
                manifest_mod.INTERACTION_TREE_INDEX,
            );
            errdefer interaction_tree.deinit();

            var result = NativeSegmentCoreV2{
                .allocator = allocator,
                .captured = captured,
                .vm_air_prepared = vm_air,
                .verifier_plans = verifier_plans,
                .public_native_sum_lane = public_lane,
                .public_native_sum_evaluation = public_evaluation,
                .public_native_sum_authority_id = public_lane.circuit_identity,
                .public_native_sum_evaluation_id = public_evaluation_id,
                .authority = authority,
                .inactive = inactive,
                .pcs_inactive = pcs_inactive,
                .prepared_query = prepared_query,
                .pcs_active_inputs = pcs_active_inputs,
                .pcs_inactive_inputs = pcs_inactive_inputs,
                .invocations = invocations,
                .merkle_paths = merkle_paths,
                .poseidon_calls = poseidon_calls,
                .prepared_relation_rows = prepared_relation_rows,
                .preprocessed_tree = preprocessed_tree,
                .main_tree = main_tree,
                .interaction_tree = interaction_tree,
                .boundary_prefix_count = boundary_prefix_count,
                .core_poseidon_call_count = 0,
                .complete_layout = undefined,
                .provider_main_ready = false,
                .generated_interactions = null,
                .authority_id = undefined,
            };
            prepareColdTreesAndCoreCalls(&result, boundary_layout) catch |err|
                return nativeV2CoreStageFailure("cold-trees-and-core-calls", err);
            if (std.meta.activeTag(query_authority) == .full_words and std.meta.activeTag(vm_air) == .immutable)
                result.prepared_inputs_v4 = try PreparedInputsV4.admit(&result);
            return result;
        }

        /// Initializes an already stable owner slot. This is the preferred entry
        /// point for a heap-owned full SegmentV2 cohort; it also makes the storage
        /// policy explicit at the aggregation boundary. `init` remains available
        /// for standalone callers because this type has no retained self/sibling
        /// pointers (see `NATIVE_V2_CORE_RETAINS_SELF_POINTERS`).
        pub fn initInPlace(
            self: *NativeSegmentCoreV2,
            allocator: std.mem.Allocator,
            inputs: AuthorityInputs,
        ) !void {
            self.* = try init(allocator, inputs);
        }

        pub fn prepareColdTreesAndCoreCalls(
            self: *NativeSegmentCoreV2,
            boundary_layout: *const shared_schedule_v2.SharedPoseidonCallLayoutV2,
        ) !void {
            fillPreprocessed(&self.authority, &self.preprocessed_tree) catch |err|
                return nativeV2CoreStageFailure("preprocessed", err);
            var arithmetic_storage: [MAX_ARITHMETIC_EVALUATION_LANES]lowering.Evaluation = undefined;
            const arithmetic_evaluations = try buildArithmeticEvaluations(
                &self.authority,
                self.captured,
                &self.inactive,
                self.public_native_sum_evaluation,
                &arithmetic_storage,
            );
            self.authority.lowering_plan.materializeInto(
                self.authority.arithmetic_reference,
                arithmetic_evaluations,
                .segment_leaf,
                self.invocations.view(),
            ) catch |err| return nativeV2CoreStageFailure("arithmetic-materialize", err);
            validateMaterializedArithmeticLane(
                self.authority.arithmetic_reference,
                arithmetic_evaluations,
                .segment_leaf,
                self.invocations.view(),
                public_native_sum.CIRCUIT_ID,
            ) catch |err| return nativeV2CoreStageFailure("arithmetic-replay", err);
            fillMainConsumers(
                &self.authority,
                &self.main_tree,
                self.evaluations(),
                self.pcsInputs(),
                &self.invocations,
                self.prepared_query.value,
                self.captured.merkleRootWitness(),
                self.captured.traceOpeningWitness(),
                self.captured.friOpeningWitness(),
                self.captured,
                &self.merkle_paths,
                poseidonBuffersMut(self),
                &self.prepared_relation_rows,
            ) catch |err| return nativeV2CoreStageFailure("main-consumers", err);
            const core_calls = try poseidonBuffers(self).preparedSuffix(
                self.boundary_prefix_count,
            );
            if (core_calls.len == 0) return error.V2CoreCohortMismatch;
            self.core_poseidon_call_count = core_calls.len;
            self.complete_layout = shared_schedule_v2.SharedPoseidonCallLayoutV2
                .initComplete(
                try boundary_layout.transcript.count(),
                try boundary_layout.statement_authority.count(),
                core_calls.len,
                poseidonBuffers(self).calls[0..poseidonBuffers(self).cursor],
            ) catch return error.V2CoreCohortMismatch;
            self.authority_id = nativeCoreAuthorityIdentity(self);
            self.validateCoreReady() catch |err|
                return nativeV2CoreStageFailure("core-ready", err);
        }
    };
}
