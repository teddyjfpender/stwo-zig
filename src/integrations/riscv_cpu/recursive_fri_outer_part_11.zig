//! Cohesive internal authority extracted from recursive_fri_outer.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const recursion = context.d_recursion;
        const composition_control_air = context.d_composition_control_air;
        const composition_control_witness = context.d_composition_control_witness;
        const circuit_mod = context.d_circuit_mod;
        const query_bits_air = context.d_query_bits_air;
        const query_bits_witness = context.d_query_bits_witness;
        const query_mapping_air = context.d_query_mapping_air;
        const query_mapping_witness = context.d_query_mapping_witness;
        const merkle_root_air = context.d_merkle_root_air;
        const merkle_root_witness = context.d_merkle_root_witness;
        const trace_merkle_air = context.d_trace_merkle_air;
        const trace_merkle_witness = context.d_trace_merkle_witness;
        const pcs_circuit_mod = context.d_pcs_circuit_mod;
        const pcs_air = context.d_pcs_air;
        const pcs_witness = context.d_pcs_witness;
        const fri_leaf_air = context.d_fri_leaf_air;
        const fri_leaf_witness = context.d_fri_leaf_witness;
        const fri_node_air = context.d_fri_node_air;
        const fri_node_witness = context.d_fri_node_witness;
        const fri_anchor_air = context.d_fri_anchor_air;
        const fri_anchor_witness = context.d_fri_anchor_witness;
        const control_air = context.d_control_air;
        const control_witness = context.d_control_witness;
        const schedule = context.d_schedule;
        const input_air = context.d_input_air;
        const input_witness = context.d_input_witness;
        const lowering = context.d_lowering;
        const multiply_air = context.d_multiply_air;
        const multiply_witness = context.d_multiply_witness;
        const inverse_air = context.d_inverse_air;
        const inverse_witness = context.d_inverse_witness;
        const linear_air = context.d_linear_air;
        const linear_witness = context.d_linear_witness;
        const merkle_path_air = context.d_merkle_path_air;
        const merkle_path_witness = context.d_merkle_path_witness;
        const poseidon2_authority = context.d_poseidon2_authority;
        const SegmentTranscriptSource = context.d_SegmentTranscriptSource;
        const SegmentLeafOuterBundle = context.d_SegmentLeafOuterBundle;
        const LogIndex = context.d_LogIndex;
        const InputRelation = context.d_InputRelation;
        const CompositionControlRelation = context.d_CompositionControlRelation;
        const QueryBitsRelation = context.d_QueryBitsRelation;
        const QueryMappingRelation = context.d_QueryMappingRelation;
        const MerkleRootRelation = context.d_MerkleRootRelation;
        const TraceMerkleRelation = context.d_TraceMerkleRelation;
        const PcsRelation = context.d_PcsRelation;
        const FriLeafRelation = context.d_FriLeafRelation;
        const FriNodeRelation = context.d_FriNodeRelation;
        const FriAnchorRelation = context.d_FriAnchorRelation;
        const ControlRelation = context.d_ControlRelation;
        const MultiplyRelation = context.d_MultiplyRelation;
        const InverseRelation = context.d_InverseRelation;
        const LinearRelation = context.d_LinearRelation;
        const MerklePathRelation = context.d_MerklePathRelation;
        const SEGMENT_CIRCUIT_ID = context.d_SEGMENT_CIRCUIT_ID;
        const LEFT_CIRCUIT_ID = context.d_LEFT_CIRCUIT_ID;
        const RIGHT_CIRCUIT_ID = context.d_RIGHT_CIRCUIT_ID;
        const PCS_SEGMENT_CIRCUIT_ID = context.d_PCS_SEGMENT_CIRCUIT_ID;
        const PCS_LEFT_CIRCUIT_ID = context.d_PCS_LEFT_CIRCUIT_ID;
        const PCS_RIGHT_CIRCUIT_ID = context.d_PCS_RIGHT_CIRCUIT_ID;
        const VM_BINARY_CAPACITY_CIRCUIT_ID = context.d_VM_BINARY_CAPACITY_CIRCUIT_ID;
        const VerifierPlans = context.d_VerifierPlans;
        const SegmentTranscriptInputs = context.d_SegmentTranscriptInputs;
        const ScheduleFacts = context.d_ScheduleFacts;
        const scheduleShape = context.d_scheduleShape;
        const validatePcsProfile = context.d_validatePcsProfile;
        const VmAirAuthority = context.d_VmAirAuthority;
        const SegmentLeafAdmission = context.d_SegmentLeafAdmission;
        const Authority = context.d_Authority;
        const buildAuthorityManifest = context.d_buildAuthorityManifest;
        const initSegmentLeafBundle = context.d_initSegmentLeafBundle;
        const merklePathRowCount = context.d_merklePathRowCount;
        const poseidonCallCount = context.d_poseidonCallCount;
        const traceLogSize = context.d_traceLogSize;

        pub fn initAuthority(
            allocator: std.mem.Allocator,
            circuit: *const circuit_mod.Circuit,
            pcs_circuit: *const pcs_circuit_mod.Circuit,
            trace_tree_heights: []const u32,
            column_log_sizes: []const []const u32,
            schedule_facts: ScheduleFacts,
            vm_air_prepared: ?*const recursion.vm_air_composition_circuit.Prepared,
            verifier_plans: ?VerifierPlans,
            segment_transcript_inputs: ?SegmentTranscriptInputs,
            public_native_sum_lane: ?lowering.Lane,
            authenticated_poseidon_prefix_count: usize,
        ) !Authority {
            try circuit.validate();
            try pcs_circuit.validate();
            if ((vm_air_prepared != null) != (verifier_plans != null) or
                (segment_transcript_inputs != null and vm_air_prepared == null) or
                (segment_transcript_inputs != null and
                    authenticated_poseidon_prefix_count != 0) or
                (public_native_sum_lane != null and
                    (vm_air_prepared == null or segment_transcript_inputs != null)) or
                (authenticated_poseidon_prefix_count != 0 and
                    vm_air_prepared == null))
                return error.AuthorityMismatch;
            if (trace_tree_heights.len != recursion.fixed_profile.TREE_COUNT or
                column_log_sizes.len != trace_tree_heights.len)
                return error.AuthorityMismatch;
            try validatePcsProfile(
                circuit,
                pcs_circuit,
                column_log_sizes,
            );
            var vm_air: ?VmAirAuthority = if (vm_air_prepared) |prepared|
                try VmAirAuthority.init(allocator, prepared)
            else
                null;
            errdefer if (vm_air) |*authority| authority.deinit();
            const pcs_profile = pcs_circuit.profile();
            if (try pcs_profile.sampleCount() != @as(
                usize,
                schedule_facts.sampled_value_count,
            ) or try pcs_profile.columnCount() != @as(
                usize,
                schedule_facts.queried_values_per_query,
            )) {
                return error.AuthorityMismatch;
            }
            const mapping_profile = query_mapping_witness.LaneProfile{
                .query_count = circuit.query_count,
                .lifting_log_size = circuit.lifting_log_size,
                .tree_heights = trace_tree_heights,
                .fri_fold_widths = circuit.fold_widths,
            };
            const query_mapping_reference = try query_mapping_witness.Reference.seal(
                mapping_profile,
                mapping_profile,
            );
            const query_bits_reference = try query_mapping_reference.queryBitsReference();
            const fri_layer_profiles = try allocator.alloc(
                fri_leaf_witness.LayerProfile,
                circuit.fold_widths.len,
            );
            errdefer allocator.free(fri_layer_profiles);
            var folded_bits: u32 = 0;
            for (circuit.fold_widths, fri_layer_profiles) |width, *layer| {
                const fold_step = std.math.log2_int(u32, width);
                const leaf_log_size: u32 = if (fold_step > 1)
                    @min(
                        fold_step,
                        std.math.log2_int(u32, fri_leaf_witness.PACKED_LEAF_SIZE),
                    )
                else
                    0;
                layer.* = .{
                    .width = width,
                    .tree_height = std.math.sub(
                        u32,
                        circuit.lifting_log_size - folded_bits,
                        leaf_log_size,
                    ) catch return error.AuthorityMismatch,
                };
                folded_bits = std.math.add(u32, folded_bits, fold_step) catch
                    return error.ArithmeticOverflow;
            }
            const fri_lane = fri_leaf_witness.LaneProfile{
                .query_count = circuit.query_count,
                .lifting_log_size = circuit.lifting_log_size,
                .layers = fri_layer_profiles,
            };
            const fri_reference = try fri_leaf_witness.Reference.seal(fri_lane, fri_lane);
            const verifier_shape = try scheduleShape(
                circuit,
                trace_tree_heights,
                schedule_facts,
            );
            const vm_schedule = try allocator.create(schedule.Plan);
            errdefer allocator.destroy(vm_schedule);
            vm_schedule.* = try schedule.Plan.initShape(
                allocator,
                if (verifier_plans) |plans|
                    plans.vm.spec
                else
                    schedule.VM_PROGRAM_SPEC_V1,
                verifier_shape,
            );
            errdefer vm_schedule.deinit();
            const recursion_schedule = try allocator.create(schedule.Plan);
            errdefer allocator.destroy(recursion_schedule);
            recursion_schedule.* = try schedule.Plan.initShape(
                allocator,
                if (verifier_plans) |plans|
                    plans.recursion.spec
                else
                    schedule.RECURSION_PROGRAM_SPEC_V1,
                verifier_shape,
            );
            errdefer recursion_schedule.deinit();
            if (verifier_plans) |plans| {
                try plans.vm.validate();
                try plans.recursion.validate();
                if (plans.vm.schema != .vm or
                    plans.recursion.schema != .recursion or
                    !std.meta.eql(plans.vm.spec, vm_schedule.spec) or
                    !std.meta.eql(plans.recursion.spec, recursion_schedule.spec) or
                    !std.meta.eql(
                        plans.vm.authority_digest,
                        vm_schedule.authority_digest,
                    ) or
                    !std.meta.eql(
                        plans.recursion.authority_digest,
                        recursion_schedule.authority_digest,
                    ))
                {
                    return error.AuthorityMismatch;
                }
            }
            var segment_transcript: ?SegmentTranscriptSource = if (segment_transcript_inputs) |inputs|
                try SegmentTranscriptSource.init(
                    allocator,
                    vm_schedule,
                    recursion_schedule,
                    inputs.preprocessing,
                    inputs.prepared,
                    try recursion.segment_transcript_outer_source.PowLogSizes.init(
                        @max(
                            recursion.segment_transcript_outer_source.MIN_LOG_SIZE,
                            try traceLogSize(inputs.prepared.pow_check.invocations.len),
                        ),
                        @max(
                            recursion.segment_transcript_outer_source.MIN_LOG_SIZE,
                            try traceLogSize(inputs.prepared.pow_frame.invocations.len),
                        ),
                    ),
                )
            else
                null;
            errdefer if (segment_transcript) |*source| source.deinit();
            const admitted_segment_leaf_bundle: ?SegmentLeafOuterBundle = if (segment_transcript_inputs) |inputs| blk: {
                const transcript_source = if (segment_transcript) |*source|
                    source
                else
                    unreachable;
                break :blk try initSegmentLeafBundle(
                    vm_schedule,
                    recursion_schedule,
                    inputs,
                    transcript_source,
                );
            } else null;
            var composition_control_preprocessing =
                try composition_control_witness.CompositionPreprocessed.init(
                    allocator,
                    vm_schedule,
                    vm_schedule.spec.air_instruction_count,
                    schedule_facts.sampled_value_count,
                    recursion_schedule,
                    recursion_schedule.spec.air_instruction_count,
                    schedule_facts.sampled_value_count,
                );
            errdefer composition_control_preprocessing.deinit();
            const merkle_lane = merkle_root_witness.LaneProfile{
                .query_count = circuit.query_count,
                .trace_tree_count = @intCast(trace_tree_heights.len),
                .fri_layer_count = @intCast(circuit.fold_widths.len),
            };
            const merkle_root_reference = try merkle_root_witness.Reference.seal(
                merkle_lane,
                merkle_lane,
            );
            var merkle_root_preprocessing = try merkle_root_witness.Preprocessed.init(
                allocator,
                merkle_root_reference,
            );
            errdefer merkle_root_preprocessing.deinit();
            const trace_tree_profiles = try allocator.alloc(
                trace_merkle_witness.TreeProfile,
                trace_tree_heights.len,
            );
            errdefer allocator.free(trace_tree_profiles);
            for (
                trace_tree_profiles,
                trace_tree_heights,
                column_log_sizes,
            ) |*tree, height, logs| {
                if (logs.len == 0) return error.AuthorityMismatch;
                var maximum_log: u32 = 0;
                for (logs) |log_size| {
                    if (log_size == 0 or log_size > height)
                        return error.AuthorityMismatch;
                    maximum_log = @max(maximum_log, log_size);
                }
                if (maximum_log != height) return error.AuthorityMismatch;
                tree.* = .{ .height = height, .column_log_sizes = logs };
            }
            const trace_lane = trace_merkle_witness.LaneProfile{
                .query_count = circuit.query_count,
                .lifting_log_size = circuit.lifting_log_size,
                .trees = trace_tree_profiles,
                .fri_fold_widths = circuit.fold_widths,
            };
            const trace_merkle_reference = try trace_merkle_witness.Reference.seal(
                trace_lane,
                vm_schedule,
                trace_lane,
                recursion_schedule,
            );
            try trace_merkle_reference.validateQueryMapping(query_mapping_reference);
            var trace_merkle_preprocessing = try trace_merkle_witness.Preprocessed.init(
                allocator,
                trace_merkle_reference,
            );
            errdefer trace_merkle_preprocessing.deinit();
            var fri_leaf_preprocessing = try fri_leaf_witness.Preprocessed.init(
                allocator,
                fri_reference,
            );
            errdefer fri_leaf_preprocessing.deinit();
            var fri_node_preprocessing = try fri_node_witness.Preprocessed.init(
                allocator,
                fri_reference,
            );
            errdefer fri_node_preprocessing.deinit();
            var fri_anchor_preprocessing = try fri_anchor_witness.Preprocessed.init(
                allocator,
                fri_reference,
                vm_schedule,
                recursion_schedule,
            );
            errdefer fri_anchor_preprocessing.deinit();
            const control_reference = try control_witness.Reference.seal(
                .{ .plan = vm_schedule, .mapping = mapping_profile },
                .{ .plan = recursion_schedule, .mapping = mapping_profile },
            );
            var control_preprocessing = try control_witness.Preprocessed.init(
                allocator,
                control_reference,
            );
            errdefer control_preprocessing.deinit();
            var query_mapping_preprocessing = try query_mapping_witness.Preprocessed.init(
                allocator,
                query_mapping_reference,
            );
            errdefer query_mapping_preprocessing.deinit();
            var query_bits_preprocessing = try query_bits_witness.Preprocessed.init(
                allocator,
                query_bits_reference,
            );
            errdefer query_bits_preprocessing.deinit();
            const pcs_lane_profile = try pcs_circuit.laneProfile();
            const pcs_lanes = [3]pcs_witness.Lane{
                .{
                    .verifier_id = pcs_witness.SEGMENT_VERIFIER_ID,
                    .circuit_id = PCS_SEGMENT_CIRCUIT_ID,
                    .profile = pcs_lane_profile,
                    .graph = pcs_circuit.graph(),
                    .bindings = pcs_circuit.bindings,
                },
                .{
                    .verifier_id = pcs_witness.LEFT_RECURSION_VERIFIER_ID,
                    .circuit_id = PCS_LEFT_CIRCUIT_ID,
                    .profile = pcs_lane_profile,
                    .graph = pcs_circuit.graph(),
                    .bindings = pcs_circuit.bindings,
                },
                .{
                    .verifier_id = pcs_witness.RIGHT_RECURSION_VERIFIER_ID,
                    .circuit_id = PCS_RIGHT_CIRCUIT_ID,
                    .profile = pcs_lane_profile,
                    .graph = pcs_circuit.graph(),
                    .bindings = pcs_circuit.bindings,
                },
            };
            const pcs_reference = try pcs_witness.Reference.authenticate(
                pcs_lanes,
                pcs_witness.computeReferenceDigest(pcs_lanes),
            );
            var pcs_preprocessing = try pcs_witness.Preprocessed.init(
                allocator,
                pcs_reference,
            );
            errdefer pcs_preprocessing.deinit();
            const reference = try input_witness.Reference.seal(.{
                .{
                    .verifier_id = input_witness.SEGMENT_VERIFIER_ID,
                    .circuit_id = SEGMENT_CIRCUIT_ID,
                    .circuit = circuit,
                },
                .{
                    .verifier_id = input_witness.LEFT_RECURSION_VERIFIER_ID,
                    .circuit_id = LEFT_CIRCUIT_ID,
                    .circuit = circuit,
                },
                .{
                    .verifier_id = input_witness.RIGHT_RECURSION_VERIFIER_ID,
                    .circuit_id = RIGHT_CIRCUIT_ID,
                    .circuit = circuit,
                },
            });
            var input_preprocessing = try input_witness.Preprocessed.init(
                allocator,
                reference,
            );
            errdefer input_preprocessing.deinit();
            // This authority proves a segment leaf, so only segment arithmetic is
            // scheduled. Rows 24 and 29 retain their fixed three-lane input tables
            // (inactive child lanes are constrained to zero), but reserving both
            // binary child graphs in the shared providers would double the largest
            // committed domains without contributing a live relation event. The
            // lowering contract requires both modes, so one authenticated graph is
            // retained as the inactive binary capacity anchor; pair nodes build
            // their own complete binary-mode lowering authority.
            const arithmetic_lanes = try allocator.alloc(
                lowering.Lane,
                3 + @as(usize, @intFromBool(vm_air != null)) +
                    @as(usize, @intFromBool(public_native_sum_lane != null)) +
                    3 * @as(usize, @intFromBool(segment_transcript_inputs != null)),
            );
            errdefer allocator.free(arithmetic_lanes);
            var arithmetic_cursor: usize = 0;
            if (vm_air) |authority| {
                arithmetic_lanes[arithmetic_cursor] = .{
                    .circuit_id = recursion.vm_air_composition_circuit.CIRCUIT_ID,
                    .active_in = .segment,
                    .circuit_identity = authority.prepared.circuit.identity_digest,
                    .graph = authority.prepared.circuit.graph(),
                };
                arithmetic_cursor += 1;
            }
            if (public_native_sum_lane) |lane| {
                arithmetic_lanes[arithmetic_cursor] = lane;
                arithmetic_cursor += 1;
            }
            if (segment_transcript_inputs != null) {
                const bundle = admitted_segment_leaf_bundle.?;
                const bundle_lanes = bundle.loweringLanes();
                @memcpy(
                    arithmetic_lanes[arithmetic_cursor..][0..bundle_lanes.len],
                    &bundle_lanes,
                );
                arithmetic_cursor += bundle_lanes.len;
            }
            arithmetic_lanes[arithmetic_cursor] = .{
                .circuit_id = PCS_SEGMENT_CIRCUIT_ID,
                .active_in = .segment,
                .circuit_identity = pcs_circuit.identity_digest,
                .graph = pcs_circuit.graph(),
            };
            arithmetic_cursor += 1;
            arithmetic_lanes[arithmetic_cursor] = .{
                .circuit_id = SEGMENT_CIRCUIT_ID,
                .active_in = .segment,
                .circuit_identity = circuit.identity_digest,
                .graph = circuit.graph(),
            };
            arithmetic_cursor += 1;
            if (vm_air) |authority| {
                arithmetic_lanes[arithmetic_cursor] = .{
                    .circuit_id = VM_BINARY_CAPACITY_CIRCUIT_ID,
                    .active_in = .binary,
                    .circuit_identity = authority.prepared.circuit.identity_digest,
                    .graph = authority.prepared.circuit.graph(),
                };
            } else {
                arithmetic_lanes[arithmetic_cursor] = .{
                    .circuit_id = LEFT_CIRCUIT_ID,
                    .active_in = .binary,
                    .circuit_identity = circuit.identity_digest,
                    .graph = circuit.graph(),
                };
            }
            arithmetic_cursor += 1;
            std.debug.assert(arithmetic_cursor == arithmetic_lanes.len);
            const arithmetic_reference = try lowering.Reference.seal(arithmetic_lanes);
            var lowering_plan = try lowering.Plan.init(allocator, arithmetic_reference);
            errdefer lowering_plan.deinit();

            var composition_control_definition = try composition_control_air.build(allocator);
            errdefer composition_control_definition.deinit();
            var query_bits_definition = try query_bits_air.build(allocator);
            errdefer query_bits_definition.deinit();
            var query_mapping_definition = try query_mapping_air.build(allocator);
            errdefer query_mapping_definition.deinit();
            var merkle_root_definition = try merkle_root_air.build(allocator);
            errdefer merkle_root_definition.deinit();
            var trace_merkle_definition = try trace_merkle_air.build(allocator);
            errdefer trace_merkle_definition.deinit();
            var fri_leaf_definition = try fri_leaf_air.build(allocator);
            errdefer fri_leaf_definition.deinit();
            var fri_node_definition = try fri_node_air.build(allocator);
            errdefer fri_node_definition.deinit();
            var fri_anchor_definition = try fri_anchor_air.build(allocator);
            errdefer fri_anchor_definition.deinit();
            var control_definition = try control_air.build(allocator);
            errdefer control_definition.deinit();
            var pcs_definition = try pcs_air.build(allocator);
            errdefer pcs_definition.deinit();
            var input_definition = try input_air.build(allocator);
            errdefer input_definition.deinit();
            var multiply_definition = try multiply_air.build(allocator, .generated);
            errdefer multiply_definition.deinit();
            var inverse_definition = try inverse_air.build(allocator, .generated);
            errdefer inverse_definition.deinit();
            var linear_definition = try linear_air.build(allocator, .generated);
            errdefer linear_definition.deinit();
            var merkle_path_definition = try merkle_path_air.build(allocator);
            errdefer merkle_path_definition.deinit();

            const composition_control_relation = try CompositionControlRelation.authenticate(
                &composition_control_definition,
            );
            const query_bits_relation = try QueryBitsRelation.authenticate(
                &query_bits_definition,
            );
            const query_mapping_relation = try QueryMappingRelation.authenticate(
                &query_mapping_definition,
            );
            const merkle_root_relation = try MerkleRootRelation.authenticate(
                &merkle_root_definition,
            );
            const trace_merkle_relation = try TraceMerkleRelation.authenticate(
                &trace_merkle_definition,
            );
            const fri_leaf_relation = try FriLeafRelation.authenticate(&fri_leaf_definition);
            const fri_node_relation = try FriNodeRelation.authenticate(&fri_node_definition);
            const fri_anchor_relation = try FriAnchorRelation.authenticate(
                &fri_anchor_definition,
            );
            const control_relation = try ControlRelation.authenticate(&control_definition);
            const pcs_relation = try PcsRelation.authenticate(&pcs_definition);
            const input_relation = try InputRelation.authenticate(&input_definition);
            const multiply_relation = try MultiplyRelation.authenticate(&multiply_definition);
            const inverse_relation = try InverseRelation.authenticate(&inverse_definition);
            const linear_relation = try LinearRelation.authenticate(&linear_definition);
            const merkle_path_relation = try MerklePathRelation.authenticate(
                &merkle_path_definition,
            );
            const query_bits_binding = try query_bits_witness.Binding.canonical(
                &query_bits_definition,
            );
            const query_mapping_binding = try query_mapping_witness.Binding.canonical(
                &query_mapping_definition,
            );
            const merkle_root_binding = try merkle_root_witness.Binding.canonical(
                &merkle_root_definition,
            );
            const trace_merkle_binding = try trace_merkle_witness.Binding.canonical(
                &trace_merkle_definition,
            );
            const fri_leaf_binding = try fri_leaf_witness.Binding.canonical(
                &fri_leaf_definition,
            );
            const fri_node_binding = try fri_node_witness.Binding.canonical(
                &fri_node_definition,
            );
            const fri_anchor_binding = try fri_anchor_witness.Binding.canonical(
                &fri_anchor_definition,
            );
            const control_binding = try control_witness.Binding.canonical(
                &control_definition,
            );
            const pcs_binding = try pcs_witness.Binding.canonical(&pcs_definition);
            const input_binding = try input_witness.Binding.canonical(&input_definition);
            const multiply_binding = try multiply_witness.Binding.canonical(
                &multiply_definition,
            );
            const inverse_binding = try inverse_witness.Binding.canonical(
                &inverse_definition,
            );
            const linear_binding = try linear_witness.Binding.canonical(&linear_definition);
            const merkle_path_binding = try merkle_path_witness.Binding.canonical(
                &merkle_path_definition,
            );
            const query_bits_executor = try query_bits_witness.Executor.init(
                &query_bits_definition,
                &query_bits_binding,
            );
            const query_mapping_executor = try query_mapping_witness.Executor.init(
                &query_mapping_definition,
                &query_mapping_binding,
            );
            const merkle_root_executor = try merkle_root_witness.Executor.init(
                &merkle_root_definition,
                &merkle_root_binding,
            );
            const trace_merkle_executor = try trace_merkle_witness.Executor.init(
                &trace_merkle_definition,
                &trace_merkle_binding,
            );
            const fri_leaf_executor = try fri_leaf_witness.Executor.init(
                &fri_leaf_definition,
                &fri_leaf_binding,
            );
            const fri_node_executor = try fri_node_witness.Executor.init(
                &fri_node_definition,
                &fri_node_binding,
            );
            const fri_anchor_executor = try fri_anchor_witness.Executor.init(
                &fri_anchor_definition,
                &fri_anchor_binding,
            );
            const control_executor = try control_witness.Executor.init(
                &control_definition,
                &control_binding,
            );
            const pcs_executor = try pcs_witness.Executor.init(
                &pcs_definition,
                &pcs_binding,
            );
            const input_executor = try input_witness.Executor.init(
                &input_definition,
                &input_binding,
            );
            const multiply_executor = try multiply_witness.Executor.init(
                &multiply_definition,
                &multiply_binding,
            );
            const inverse_executor = try inverse_witness.Executor.init(
                &inverse_definition,
                &inverse_binding,
            );
            const linear_executor = try linear_witness.Executor.init(
                &linear_definition,
                &linear_binding,
            );
            const merkle_path_executor = try merkle_path_witness.Executor.init(
                &merkle_path_definition,
                &merkle_path_binding,
            );
            var poseidon2_program = try poseidon2_authority.Authority.init(allocator);
            errdefer poseidon2_program.deinit();
            var poseidon2_row_count_usize = try poseidonCallCount(
                trace_merkle_preprocessing.rows,
                fri_leaf_preprocessing.rows,
                fri_node_preprocessing.rows,
                try merklePathRowCount(
                    trace_tree_heights,
                    circuit.query_count,
                    fri_anchor_preprocessing.rows,
                ),
            );
            if (segment_transcript_inputs) |inputs| {
                poseidon2_row_count_usize = try std.math.add(
                    usize,
                    poseidon2_row_count_usize,
                    inputs.prepared.execution.poseidon_calls.len,
                );
                poseidon2_row_count_usize = try std.math.add(
                    usize,
                    poseidon2_row_count_usize,
                    inputs.public.prepared.poseidonCallCount(inputs.public.leaf),
                );
            } else if (authenticated_poseidon_prefix_count != 0) {
                poseidon2_row_count_usize = try std.math.add(
                    usize,
                    poseidon2_row_count_usize,
                    authenticated_poseidon_prefix_count,
                );
            }
            if (poseidon2_row_count_usize > std.math.maxInt(u32))
                return error.ArithmeticOverflow;
            const poseidon2_row_count: u32 = @intCast(poseidon2_row_count_usize);

            const log_sizes = [LogIndex.count]u32{
                if (vm_air) |authority| authority.prepared.preprocessing.log_size else 0,
                composition_control_preprocessing.log_size,
                query_bits_preprocessing.log_size,
                query_mapping_preprocessing.log_size,
                merkle_root_preprocessing.log_size,
                trace_merkle_preprocessing.log_size,
                pcs_preprocessing.log_size,
                fri_leaf_preprocessing.log_size,
                fri_node_preprocessing.log_size,
                fri_anchor_preprocessing.log_size,
                control_preprocessing.log_size,
                input_preprocessing.log_size,
                try traceLogSize(lowering_plan.multiply_rows.len),
                try traceLogSize(lowering_plan.inverse_rows.len),
                try traceLogSize(lowering_plan.linear_rows.len),
                try traceLogSize(try merklePathRowCount(
                    trace_tree_heights,
                    circuit.query_count,
                    fri_anchor_preprocessing.rows,
                )),
                try traceLogSize(poseidon2_row_count_usize),
            };
            // A VM composition authority can now be prepared independently as
            // the reusable rows-18--34 core for a versioned outer protocol.  Only
            // an admitted V1 segment boundary requests the frozen all-36 manifest.
            const full_roster = segment_transcript_inputs != null;
            const manifest = try buildAuthorityManifest(
                full_roster,
                vm_air,
                log_sizes,
                admitted_segment_leaf_bundle,
            );

            return .{
                .allocator = allocator,
                .circuit = circuit,
                .pcs_circuit = pcs_circuit,
                .query_mapping_reference = query_mapping_reference,
                .query_bits_reference = query_bits_reference,
                .query_mapping_preprocessing = query_mapping_preprocessing,
                .query_bits_preprocessing = query_bits_preprocessing,
                .merkle_root_reference = merkle_root_reference,
                .merkle_root_preprocessing = merkle_root_preprocessing,
                .trace_tree_profiles = trace_tree_profiles,
                .trace_merkle_reference = trace_merkle_reference,
                .trace_merkle_preprocessing = trace_merkle_preprocessing,
                .fri_layer_profiles = fri_layer_profiles,
                .fri_reference = fri_reference,
                .fri_leaf_preprocessing = fri_leaf_preprocessing,
                .fri_node_preprocessing = fri_node_preprocessing,
                .fri_anchor_preprocessing = fri_anchor_preprocessing,
                .vm_schedule = vm_schedule,
                .recursion_schedule = recursion_schedule,
                .composition_control_preprocessing = composition_control_preprocessing,
                .control_reference = control_reference,
                .control_preprocessing = control_preprocessing,
                .pcs_reference = pcs_reference,
                .pcs_preprocessing = pcs_preprocessing,
                .reference = reference,
                .input_preprocessing = input_preprocessing,
                .arithmetic_lanes = arithmetic_lanes,
                .arithmetic_reference = arithmetic_reference,
                .lowering_plan = lowering_plan,
                .vm_air = vm_air,
                .public_native_sum_lane = public_native_sum_lane,
                .segment_transcript_inputs = segment_transcript_inputs,
                .segment_transcript = segment_transcript,
                .segment_leaf_admission = if (segment_transcript_inputs) |inputs|
                    SegmentLeafAdmission.issue(
                        vm_schedule,
                        recursion_schedule,
                        inputs,
                        &manifest,
                    )
                else
                    null,
                .composition_control_definition = composition_control_definition,
                .query_bits_definition = query_bits_definition,
                .query_mapping_definition = query_mapping_definition,
                .merkle_root_definition = merkle_root_definition,
                .trace_merkle_definition = trace_merkle_definition,
                .fri_leaf_definition = fri_leaf_definition,
                .fri_node_definition = fri_node_definition,
                .fri_anchor_definition = fri_anchor_definition,
                .control_definition = control_definition,
                .pcs_definition = pcs_definition,
                .input_definition = input_definition,
                .multiply_definition = multiply_definition,
                .inverse_definition = inverse_definition,
                .linear_definition = linear_definition,
                .merkle_path_definition = merkle_path_definition,
                .composition_control_relation = composition_control_relation,
                .query_bits_relation = query_bits_relation,
                .query_mapping_relation = query_mapping_relation,
                .merkle_root_relation = merkle_root_relation,
                .trace_merkle_relation = trace_merkle_relation,
                .fri_leaf_relation = fri_leaf_relation,
                .fri_node_relation = fri_node_relation,
                .fri_anchor_relation = fri_anchor_relation,
                .control_relation = control_relation,
                .pcs_relation = pcs_relation,
                .input_relation = input_relation,
                .multiply_relation = multiply_relation,
                .inverse_relation = inverse_relation,
                .linear_relation = linear_relation,
                .merkle_path_relation = merkle_path_relation,
                .query_bits_executor = query_bits_executor,
                .query_mapping_executor = query_mapping_executor,
                .merkle_root_executor = merkle_root_executor,
                .trace_merkle_executor = trace_merkle_executor,
                .fri_leaf_executor = fri_leaf_executor,
                .fri_node_executor = fri_node_executor,
                .fri_anchor_executor = fri_anchor_executor,
                .control_executor = control_executor,
                .pcs_executor = pcs_executor,
                .input_executor = input_executor,
                .multiply_executor = multiply_executor,
                .inverse_executor = inverse_executor,
                .linear_executor = linear_executor,
                .merkle_path_executor = merkle_path_executor,
                .poseidon2_program = poseidon2_program,
                .poseidon2_row_count = poseidon2_row_count,
                .manifest = manifest,
                .full_roster = full_roster,
                .log_sizes = log_sizes,
            };
        }
    };
}
