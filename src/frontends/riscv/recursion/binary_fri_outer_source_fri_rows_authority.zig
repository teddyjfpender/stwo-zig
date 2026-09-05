//! Internal shard of binary_fri_outer_source.zig; use the public facade.

const dependency_0 = @import("binary_fri_outer_source_claims.zig");
const dependency_9 = @import("binary_fri_outer_source_validate_captured_against_wire.zig");

const std = dependency_0.std;
const M31 = dependency_0.M31;
const air_digest = dependency_0.air_digest;
const query_bits_air = dependency_0.query_bits_air;
const query_bits_relation = dependency_0.query_bits_relation;
const query_bits_witness = dependency_0.query_bits_witness;
const query_mapping_air = dependency_0.query_mapping_air;
const query_mapping_relation = dependency_0.query_mapping_relation;
const query_mapping_witness = dependency_0.query_mapping_witness;
const merkle_root_air = dependency_0.merkle_root_air;
const merkle_root_relation = dependency_0.merkle_root_relation;
const merkle_root_witness = dependency_0.merkle_root_witness;
const trace_merkle_air = dependency_0.trace_merkle_air;
const trace_merkle_relation = dependency_0.trace_merkle_relation;
const trace_merkle_witness = dependency_0.trace_merkle_witness;
const pcs_air = dependency_0.pcs_air;
const pcs_relation = dependency_0.pcs_relation;
const pcs_witness = dependency_0.pcs_witness;
const fri_leaf_air = dependency_0.fri_leaf_air;
const fri_leaf_relation = dependency_0.fri_leaf_relation;
const fri_leaf_witness = dependency_0.fri_leaf_witness;
const fri_node_air = dependency_0.fri_node_air;
const fri_node_relation = dependency_0.fri_node_relation;
const fri_node_witness = dependency_0.fri_node_witness;
const fri_anchor_air = dependency_0.fri_anchor_air;
const fri_anchor_relation = dependency_0.fri_anchor_relation;
const fri_anchor_witness = dependency_0.fri_anchor_witness;
const fri_control_air = dependency_0.fri_control_air;
const fri_control_relation = dependency_0.fri_control_relation;
const fri_control_witness = dependency_0.fri_control_witness;
const fri_input_air = dependency_0.fri_input_air;
const fri_input_relation = dependency_0.fri_input_relation;
const fri_input_witness = dependency_0.fri_input_witness;
const schedule = dependency_0.schedule;
const LEFT_CHILD = dependency_0.LEFT_CHILD;
const RIGHT_CHILD = dependency_0.RIGHT_CHILD;
const LEFT_RECURSION_VERIFIER_ID = dependency_0.LEFT_RECURSION_VERIFIER_ID;
const RIGHT_RECURSION_VERIFIER_ID = dependency_0.RIGHT_RECURSION_VERIFIER_ID;
const SEGMENT_FRI_CIRCUIT_ID = dependency_0.SEGMENT_FRI_CIRCUIT_ID;
const LEFT_FRI_CIRCUIT_ID = dependency_0.LEFT_FRI_CIRCUIT_ID;
const RIGHT_FRI_CIRCUIT_ID = dependency_0.RIGHT_FRI_CIRCUIT_ID;
const SEGMENT_PCS_CIRCUIT_ID = dependency_0.SEGMENT_PCS_CIRCUIT_ID;
const LEFT_PCS_CIRCUIT_ID = dependency_0.LEFT_PCS_CIRCUIT_ID;
const RIGHT_PCS_CIRCUIT_ID = dependency_0.RIGHT_PCS_CIRCUIT_ID;
const FRI_ROW_COUNT = dependency_0.FRI_ROW_COUNT;
const hashInt = dependency_9.hashInt;

pub const FriRowsAuthority = struct {
    allocator: std.mem.Allocator,

    query_mapping_reference: query_mapping_witness.Reference,
    query_bits_reference: query_bits_witness.Reference,
    merkle_root_reference: merkle_root_witness.Reference,
    trace_tree_profiles: []trace_merkle_witness.TreeProfile,
    trace_merkle_reference: trace_merkle_witness.Reference,
    fri_reference: fri_leaf_witness.Reference,
    control_reference: fri_control_witness.Reference,
    pcs_reference: pcs_witness.Reference,
    input_reference: fri_input_witness.Reference,

    query_bits_preprocessing: query_bits_witness.Preprocessed,
    query_mapping_preprocessing: query_mapping_witness.Preprocessed,
    merkle_root_preprocessing: merkle_root_witness.Preprocessed,
    trace_merkle_preprocessing: trace_merkle_witness.Preprocessed,
    pcs_preprocessing: pcs_witness.Preprocessed,
    fri_leaf_preprocessing: fri_leaf_witness.Preprocessed,
    fri_node_preprocessing: fri_node_witness.Preprocessed,
    fri_anchor_preprocessing: fri_anchor_witness.Preprocessed,
    control_preprocessing: fri_control_witness.Preprocessed,
    input_preprocessing: fri_input_witness.Preprocessed,

    query_bits_definition: query_bits_air.Definition,
    query_mapping_definition: query_mapping_air.Definition,
    merkle_root_definition: merkle_root_air.Definition,
    trace_merkle_definition: trace_merkle_air.Definition,
    pcs_definition: pcs_air.Definition,
    fri_leaf_definition: fri_leaf_air.Definition,
    fri_node_definition: fri_node_air.Definition,
    fri_anchor_definition: fri_anchor_air.Definition,
    control_definition: fri_control_air.Definition,
    input_definition: fri_input_air.Definition,

    query_bits_relation: query_bits_relation.Plan,
    query_mapping_relation: query_mapping_relation.Plan,
    merkle_root_relation: merkle_root_relation.Plan,
    trace_merkle_relation: trace_merkle_relation.Plan,
    pcs_relation: pcs_relation.Plan,
    fri_leaf_relation: fri_leaf_relation.Plan,
    fri_node_relation: fri_node_relation.Plan,
    fri_anchor_relation: fri_anchor_relation.Plan,
    control_relation: fri_control_relation.Plan,
    input_relation: fri_input_relation.Plan,

    query_bits_executor: query_bits_witness.Executor,
    query_mapping_executor: query_mapping_witness.Executor,
    merkle_root_executor: merkle_root_witness.Executor,
    trace_merkle_executor: trace_merkle_witness.Executor,
    pcs_executor: pcs_witness.Executor,
    fri_leaf_executor: fri_leaf_witness.Executor,
    fri_node_executor: fri_node_witness.Executor,
    fri_anchor_executor: fri_anchor_witness.Executor,
    control_executor: fri_control_witness.Executor,
    input_executor: fri_input_witness.Executor,

    inactive_fri_evaluation: fri_input_witness.Evaluation,
    inactive_pcs_evaluation: @import("air/pcs_deep_circuit.zig").Evaluation,
    pcs_input_storage: []M31,
    pcs_inputs: pcs_witness.InputWitness,
    log_sizes: [FRI_ROW_COUNT]u32,
    authority_digest: air_digest.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        children: anytype,
    ) !FriRowsAuthority {
        const left = children[LEFT_CHILD].capture;
        const right = children[RIGHT_CHILD].capture;

        return initFromProfiles(
            allocator,
            vm_plan,
            recursion_plan,
            left,
            right,
            true,
        );
    }

    /// Builds the same profile-authenticated rows 20--29 authority while
    /// selecting no child proof lane. The verified template contributes only
    /// circuit/VK geometry; none of its proof witness enters the result.
    pub fn initInactiveFromTemplate(
        allocator: std.mem.Allocator,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        template: anytype,
    ) !FriRowsAuthority {
        return initFromProfiles(
            allocator,
            vm_plan,
            recursion_plan,
            template,
            template,
            false,
        );
    }

    fn initFromProfiles(
        allocator: std.mem.Allocator,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        left: anytype,
        right: anytype,
        active_children: bool,
    ) !FriRowsAuthority {
        const mapping_profile = query_mapping_witness.LaneProfile{
            .query_count = left.circuit.query_count,
            .lifting_log_size = left.circuit.lifting_log_size,
            .tree_heights = left.trace_tree_heights,
            .fri_fold_widths = left.circuit.fold_widths,
        };
        const query_mapping_reference = try query_mapping_witness.Reference.seal(
            mapping_profile,
            mapping_profile,
        );
        const query_bits_reference = try query_mapping_reference.queryBitsReference();
        const merkle_lane = merkle_root_witness.LaneProfile{
            .query_count = left.circuit.query_count,
            .trace_tree_count = @intCast(left.trace_tree_heights.len),
            .fri_layer_count = @intCast(left.circuit.fold_widths.len),
        };
        const merkle_root_reference = try merkle_root_witness.Reference.seal(
            merkle_lane,
            merkle_lane,
        );

        const trace_tree_profiles = try allocator.alloc(
            trace_merkle_witness.TreeProfile,
            left.trace_tree_heights.len,
        );
        errdefer allocator.free(trace_tree_profiles);
        for (
            trace_tree_profiles,
            left.trace_tree_heights,
            left.column_log_sizes,
        ) |*profile, height, logs| profile.* = .{
            .height = height,
            .column_log_sizes = logs,
        };
        const trace_lane = trace_merkle_witness.LaneProfile{
            .query_count = left.circuit.query_count,
            .lifting_log_size = left.circuit.lifting_log_size,
            .trees = trace_tree_profiles,
            .fri_fold_widths = left.circuit.fold_widths,
        };
        const trace_merkle_reference = try trace_merkle_witness.Reference.seal(
            trace_lane,
            vm_plan,
            trace_lane,
            recursion_plan,
        );
        try trace_merkle_reference.validateQueryMapping(query_mapping_reference);

        const fri_lane = fri_leaf_witness.LaneProfile{
            .query_count = left.circuit.query_count,
            .lifting_log_size = left.circuit.lifting_log_size,
            .layers = left.fri_layer_profiles,
        };
        const fri_reference = try fri_leaf_witness.Reference.seal(fri_lane, fri_lane);
        const control_reference = try fri_control_witness.Reference.seal(
            .{ .plan = vm_plan, .mapping = mapping_profile },
            .{ .plan = recursion_plan, .mapping = mapping_profile },
        );

        const left_pcs_profile = try left.pcs_circuit.laneProfile();
        const right_pcs_profile = try right.pcs_circuit.laneProfile();
        const pcs_lanes = [3]pcs_witness.Lane{
            .{
                .verifier_id = pcs_witness.SEGMENT_VERIFIER_ID,
                .circuit_id = SEGMENT_PCS_CIRCUIT_ID,
                .profile = left_pcs_profile,
                .graph = left.pcs_circuit.graph(),
                .bindings = left.pcs_circuit.bindings,
            },
            .{
                .verifier_id = pcs_witness.LEFT_RECURSION_VERIFIER_ID,
                .circuit_id = LEFT_PCS_CIRCUIT_ID,
                .profile = left_pcs_profile,
                .graph = left.pcs_circuit.graph(),
                .bindings = left.pcs_circuit.bindings,
            },
            .{
                .verifier_id = pcs_witness.RIGHT_RECURSION_VERIFIER_ID,
                .circuit_id = RIGHT_PCS_CIRCUIT_ID,
                .profile = right_pcs_profile,
                .graph = right.pcs_circuit.graph(),
                .bindings = right.pcs_circuit.bindings,
            },
        };
        const pcs_reference = try pcs_witness.Reference.authenticate(
            pcs_lanes,
            pcs_witness.computeReferenceDigest(pcs_lanes),
        );
        const input_reference = try fri_input_witness.Reference.seal(.{
            .{
                .verifier_id = fri_input_witness.SEGMENT_VERIFIER_ID,
                .circuit_id = SEGMENT_FRI_CIRCUIT_ID,
                .circuit = &left.circuit,
            },
            .{
                .verifier_id = fri_input_witness.LEFT_RECURSION_VERIFIER_ID,
                .circuit_id = LEFT_FRI_CIRCUIT_ID,
                .circuit = &left.circuit,
            },
            .{
                .verifier_id = fri_input_witness.RIGHT_RECURSION_VERIFIER_ID,
                .circuit_id = RIGHT_FRI_CIRCUIT_ID,
                .circuit = &right.circuit,
            },
        });

        var query_bits_preprocessing = try query_bits_witness.Preprocessed.init(
            allocator,
            query_bits_reference,
        );
        errdefer query_bits_preprocessing.deinit();
        var query_mapping_preprocessing = try query_mapping_witness.Preprocessed.init(
            allocator,
            query_mapping_reference,
        );
        errdefer query_mapping_preprocessing.deinit();
        var merkle_root_preprocessing = try merkle_root_witness.Preprocessed.init(
            allocator,
            merkle_root_reference,
        );
        errdefer merkle_root_preprocessing.deinit();
        var trace_merkle_preprocessing = try trace_merkle_witness.Preprocessed.init(
            allocator,
            trace_merkle_reference,
        );
        errdefer trace_merkle_preprocessing.deinit();
        var pcs_preprocessing = try pcs_witness.Preprocessed.init(
            allocator,
            pcs_reference,
        );
        errdefer pcs_preprocessing.deinit();
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
            vm_plan,
            recursion_plan,
        );
        errdefer fri_anchor_preprocessing.deinit();
        var control_preprocessing = try fri_control_witness.Preprocessed.init(
            allocator,
            control_reference,
        );
        errdefer control_preprocessing.deinit();
        var input_preprocessing = try fri_input_witness.Preprocessed.init(
            allocator,
            input_reference,
        );
        errdefer input_preprocessing.deinit();

        var query_bits_definition = try query_bits_air.build(allocator);
        errdefer query_bits_definition.deinit();
        var query_mapping_definition = try query_mapping_air.build(allocator);
        errdefer query_mapping_definition.deinit();
        var merkle_root_definition = try merkle_root_air.build(allocator);
        errdefer merkle_root_definition.deinit();
        var trace_merkle_definition = try trace_merkle_air.build(allocator);
        errdefer trace_merkle_definition.deinit();
        var pcs_definition = try pcs_air.build(allocator);
        errdefer pcs_definition.deinit();
        var fri_leaf_definition = try fri_leaf_air.build(allocator);
        errdefer fri_leaf_definition.deinit();
        var fri_node_definition = try fri_node_air.build(allocator);
        errdefer fri_node_definition.deinit();
        var fri_anchor_definition = try fri_anchor_air.build(allocator);
        errdefer fri_anchor_definition.deinit();
        var control_definition = try fri_control_air.build(allocator);
        errdefer control_definition.deinit();
        var input_definition = try fri_input_air.build(allocator);
        errdefer input_definition.deinit();

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
        const pcs_binding = try pcs_witness.Binding.canonical(&pcs_definition);
        const fri_leaf_binding = try fri_leaf_witness.Binding.canonical(
            &fri_leaf_definition,
        );
        const fri_node_binding = try fri_node_witness.Binding.canonical(
            &fri_node_definition,
        );
        const fri_anchor_binding = try fri_anchor_witness.Binding.canonical(
            &fri_anchor_definition,
        );
        const control_binding = try fri_control_witness.Binding.canonical(
            &control_definition,
        );
        const input_binding = try fri_input_witness.Binding.canonical(&input_definition);

        var inactive_fri_evaluation = try left.evaluateInactive();
        errdefer inactive_fri_evaluation.deinit();
        var inactive_pcs_evaluation = try left.evaluatePcsInactive();
        errdefer inactive_pcs_evaluation.deinit();

        const pcs_input_count = left.pcs_circuit.bindings.len;
        if (right.pcs_circuit.bindings.len != pcs_input_count)
            return error.ProfileMismatch;
        const pcs_input_storage = try allocator.alloc(M31, 3 * pcs_input_count);
        errdefer allocator.free(pcs_input_storage);
        const segment_pcs_inputs = pcs_input_storage[0..pcs_input_count];
        const left_pcs_inputs = pcs_input_storage[pcs_input_count..][0..pcs_input_count];
        const right_pcs_inputs = pcs_input_storage[2 * pcs_input_count ..][0..pcs_input_count];
        try left.pcs_circuit.inputValuesInto(
            &inactive_pcs_evaluation,
            segment_pcs_inputs,
        );
        try left.pcs_circuit.inputValuesInto(
            if (active_children) &left.pcs_evaluation else &inactive_pcs_evaluation,
            left_pcs_inputs,
        );
        try right.pcs_circuit.inputValuesInto(
            if (active_children) &right.pcs_evaluation else &inactive_pcs_evaluation,
            right_pcs_inputs,
        );
        const pcs_inputs = pcs_witness.InputWitness{ .lanes = .{
            .{
                .verifier_id = pcs_witness.SEGMENT_VERIFIER_ID,
                .circuit_id = SEGMENT_PCS_CIRCUIT_ID,
                .graph_digest = left.pcs_circuit.graph_digest,
                .input_values = segment_pcs_inputs,
            },
            .{
                .verifier_id = pcs_witness.LEFT_RECURSION_VERIFIER_ID,
                .circuit_id = LEFT_PCS_CIRCUIT_ID,
                .graph_digest = left.pcs_circuit.graph_digest,
                .input_values = left_pcs_inputs,
            },
            .{
                .verifier_id = pcs_witness.RIGHT_RECURSION_VERIFIER_ID,
                .circuit_id = RIGHT_PCS_CIRCUIT_ID,
                .graph_digest = right.pcs_circuit.graph_digest,
                .input_values = right_pcs_inputs,
            },
        } };

        var result = FriRowsAuthority{
            .allocator = allocator,
            .query_mapping_reference = query_mapping_reference,
            .query_bits_reference = query_bits_reference,
            .merkle_root_reference = merkle_root_reference,
            .trace_tree_profiles = trace_tree_profiles,
            .trace_merkle_reference = trace_merkle_reference,
            .fri_reference = fri_reference,
            .control_reference = control_reference,
            .pcs_reference = pcs_reference,
            .input_reference = input_reference,
            .query_bits_preprocessing = query_bits_preprocessing,
            .query_mapping_preprocessing = query_mapping_preprocessing,
            .merkle_root_preprocessing = merkle_root_preprocessing,
            .trace_merkle_preprocessing = trace_merkle_preprocessing,
            .pcs_preprocessing = pcs_preprocessing,
            .fri_leaf_preprocessing = fri_leaf_preprocessing,
            .fri_node_preprocessing = fri_node_preprocessing,
            .fri_anchor_preprocessing = fri_anchor_preprocessing,
            .control_preprocessing = control_preprocessing,
            .input_preprocessing = input_preprocessing,
            .query_bits_definition = query_bits_definition,
            .query_mapping_definition = query_mapping_definition,
            .merkle_root_definition = merkle_root_definition,
            .trace_merkle_definition = trace_merkle_definition,
            .pcs_definition = pcs_definition,
            .fri_leaf_definition = fri_leaf_definition,
            .fri_node_definition = fri_node_definition,
            .fri_anchor_definition = fri_anchor_definition,
            .control_definition = control_definition,
            .input_definition = input_definition,
            .query_bits_relation = try query_bits_relation.authenticate(
                &query_bits_definition,
            ),
            .query_mapping_relation = try query_mapping_relation.authenticate(
                &query_mapping_definition,
            ),
            .merkle_root_relation = try merkle_root_relation.authenticate(
                &merkle_root_definition,
            ),
            .trace_merkle_relation = try trace_merkle_relation.authenticate(
                &trace_merkle_definition,
            ),
            .pcs_relation = try pcs_relation.authenticate(&pcs_definition),
            .fri_leaf_relation = try fri_leaf_relation.authenticate(
                &fri_leaf_definition,
            ),
            .fri_node_relation = try fri_node_relation.authenticate(
                &fri_node_definition,
            ),
            .fri_anchor_relation = try fri_anchor_relation.authenticate(
                &fri_anchor_definition,
            ),
            .control_relation = try fri_control_relation.authenticate(
                &control_definition,
            ),
            .input_relation = try fri_input_relation.authenticate(
                &input_definition,
            ),
            .query_bits_executor = try query_bits_witness.Executor.init(
                &query_bits_definition,
                &query_bits_binding,
            ),
            .query_mapping_executor = try query_mapping_witness.Executor.init(
                &query_mapping_definition,
                &query_mapping_binding,
            ),
            .merkle_root_executor = try merkle_root_witness.Executor.init(
                &merkle_root_definition,
                &merkle_root_binding,
            ),
            .trace_merkle_executor = try trace_merkle_witness.Executor.init(
                &trace_merkle_definition,
                &trace_merkle_binding,
            ),
            .pcs_executor = try pcs_witness.Executor.init(
                &pcs_definition,
                &pcs_binding,
            ),
            .fri_leaf_executor = try fri_leaf_witness.Executor.init(
                &fri_leaf_definition,
                &fri_leaf_binding,
            ),
            .fri_node_executor = try fri_node_witness.Executor.init(
                &fri_node_definition,
                &fri_node_binding,
            ),
            .fri_anchor_executor = try fri_anchor_witness.Executor.init(
                &fri_anchor_definition,
                &fri_anchor_binding,
            ),
            .control_executor = try fri_control_witness.Executor.init(
                &control_definition,
                &control_binding,
            ),
            .input_executor = try fri_input_witness.Executor.init(
                &input_definition,
                &input_binding,
            ),
            .inactive_fri_evaluation = inactive_fri_evaluation,
            .inactive_pcs_evaluation = inactive_pcs_evaluation,
            .pcs_input_storage = pcs_input_storage,
            .pcs_inputs = pcs_inputs,
            .log_sizes = .{
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
            },
            .authority_digest = undefined,
        };
        result.authority_digest = friRowsAuthorityDigest(&result);
        try result.validateProfiles(
            vm_plan,
            recursion_plan,
            left,
            right,
            active_children,
        );
        return result;
    }

    pub fn deinit(self: *FriRowsAuthority) void {
        self.allocator.free(self.pcs_input_storage);
        self.inactive_pcs_evaluation.deinit();
        self.inactive_fri_evaluation.deinit();
        self.input_definition.deinit();
        self.control_definition.deinit();
        self.fri_anchor_definition.deinit();
        self.fri_node_definition.deinit();
        self.fri_leaf_definition.deinit();
        self.pcs_definition.deinit();
        self.trace_merkle_definition.deinit();
        self.merkle_root_definition.deinit();
        self.query_mapping_definition.deinit();
        self.query_bits_definition.deinit();
        self.input_preprocessing.deinit();
        self.control_preprocessing.deinit();
        self.fri_anchor_preprocessing.deinit();
        self.fri_node_preprocessing.deinit();
        self.fri_leaf_preprocessing.deinit();
        self.pcs_preprocessing.deinit();
        self.trace_merkle_preprocessing.deinit();
        self.merkle_root_preprocessing.deinit();
        self.query_mapping_preprocessing.deinit();
        self.query_bits_preprocessing.deinit();
        self.allocator.free(self.trace_tree_profiles);
        self.* = undefined;
    }

    pub fn validate(
        self: *const FriRowsAuthority,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        children: anytype,
    ) !void {
        return self.validateProfiles(
            vm_plan,
            recursion_plan,
            children[LEFT_CHILD].capture,
            children[RIGHT_CHILD].capture,
            true,
        );
    }

    pub fn validateInactiveTemplate(
        self: *const FriRowsAuthority,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        template: anytype,
    ) !void {
        return self.validateProfiles(
            vm_plan,
            recursion_plan,
            template,
            template,
            false,
        );
    }

    fn validateProfiles(
        self: *const FriRowsAuthority,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        left: anytype,
        right: anytype,
        active_children: bool,
    ) !void {
        try self.query_mapping_reference.validate();
        try self.query_bits_reference.validate();
        try self.merkle_root_reference.validate();
        try self.trace_merkle_reference.validate();
        try self.fri_reference.validate();
        try self.control_reference.validate();
        try self.pcs_reference.validate();
        try self.input_reference.validate();
        try self.query_bits_preprocessing.validateAgainst(self.query_bits_reference);
        try self.query_mapping_preprocessing.validateAgainst(self.query_mapping_reference);
        try self.merkle_root_preprocessing.validateAgainst(self.merkle_root_reference);
        try self.trace_merkle_preprocessing.validateAgainst(self.trace_merkle_reference);
        try self.pcs_preprocessing.validateAgainst(self.pcs_reference);
        try self.fri_leaf_preprocessing.validateAgainst(self.fri_reference);
        try self.fri_node_preprocessing.validateAgainst(self.fri_reference);
        try self.fri_anchor_preprocessing.validateAgainst(
            self.fri_reference,
            vm_plan,
            recursion_plan,
        );
        try self.control_preprocessing.validateAgainst(self.control_reference);
        try self.input_preprocessing.validateAgainst(self.input_reference);
        try self.query_bits_relation.validateAgainst(
            &self.query_bits_definition.arena,
            query_bits_air.SEMANTIC_DIGEST,
            self.query_bits_definition.events,
        );
        try self.query_mapping_relation.validateAgainst(
            &self.query_mapping_definition.arena,
            query_mapping_air.SEMANTIC_DIGEST,
            self.query_mapping_definition.events,
        );
        try self.merkle_root_relation.validateAgainst(
            &self.merkle_root_definition.arena,
            merkle_root_air.SEMANTIC_DIGEST,
            self.merkle_root_definition.events,
        );
        try self.trace_merkle_relation.validateAgainst(
            &self.trace_merkle_definition.arena,
            trace_merkle_air.SEMANTIC_DIGEST,
            self.trace_merkle_definition.events,
        );
        try self.pcs_relation.validateAgainst(
            &self.pcs_definition.arena,
            pcs_air.SEMANTIC_DIGEST,
            self.pcs_definition.events,
        );
        try self.fri_leaf_relation.validateAgainst(
            &self.fri_leaf_definition.arena,
            fri_leaf_air.SEMANTIC_DIGEST,
            self.fri_leaf_definition.events,
        );
        try self.fri_node_relation.validateAgainst(
            &self.fri_node_definition.arena,
            fri_node_air.SEMANTIC_DIGEST,
            self.fri_node_definition.events,
        );
        try self.fri_anchor_relation.validateAgainst(
            &self.fri_anchor_definition.arena,
            fri_anchor_air.SEMANTIC_DIGEST,
            self.fri_anchor_definition.events,
        );
        try self.control_relation.validateAgainst(
            &self.control_definition.arena,
            fri_control_air.SEMANTIC_DIGEST,
            self.control_definition.events,
        );
        try self.input_relation.validateAgainst(
            &self.input_definition.arena,
            fri_input_air.SEMANTIC_DIGEST,
            self.input_definition.events,
        );
        try self.inactive_fri_evaluation.validateAgainst(&left.circuit);
        try self.inactive_pcs_evaluation.validateAgainst(&left.pcs_circuit);
        if (!std.mem.eql(u8, &left.circuit.profile_digest, &right.circuit.profile_digest) or
            !std.mem.eql(
                u8,
                &left.pcs_circuit.profile_digest,
                &right.pcs_circuit.profile_digest,
            )) return error.ProfileMismatch;
        const pcs_input_count = left.pcs_circuit.bindings.len;
        if (right.pcs_circuit.bindings.len != pcs_input_count or
            self.pcs_input_storage.len != 3 * pcs_input_count)
        {
            return error.ProfileMismatch;
        }
        if (!active_children) {
            const segment = self.pcs_input_storage[0..pcs_input_count];
            const left_inputs = self.pcs_input_storage[pcs_input_count..][0..pcs_input_count];
            const right_inputs = self.pcs_input_storage[2 * pcs_input_count ..][0..pcs_input_count];
            if (!m31SliceEql(segment, left_inputs) or
                !m31SliceEql(segment, right_inputs))
            {
                return error.SourceAuthorityMismatch;
            }
        }
        const expected_logs = [FRI_ROW_COUNT]u32{
            self.query_bits_preprocessing.log_size,
            self.query_mapping_preprocessing.log_size,
            self.merkle_root_preprocessing.log_size,
            self.trace_merkle_preprocessing.log_size,
            self.pcs_preprocessing.log_size,
            self.fri_leaf_preprocessing.log_size,
            self.fri_node_preprocessing.log_size,
            self.fri_anchor_preprocessing.log_size,
            self.control_preprocessing.log_size,
            self.input_preprocessing.log_size,
        };
        if (!std.meta.eql(self.log_sizes, expected_logs) or
            !std.mem.eql(u8, &self.authority_digest, &friRowsAuthorityDigest(self)))
        {
            return error.SourceAuthorityMismatch;
        }
    }
};

fn m31SliceEql(left: []const M31, right: []const M31) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!a.eql(b)) return false;
    return true;
}

pub fn friRowsAuthorityDigest(rows: *const FriRowsAuthority) air_digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/binary-fri-rows-20-29/v1\x00");
    const reference_digests = [_]air_digest.Digest{
        rows.query_bits_reference.authority_digest,
        rows.query_mapping_reference.authority_digest,
        rows.merkle_root_reference.authority_digest,
        rows.trace_merkle_reference.authority_digest,
        rows.pcs_reference.authority_digest,
        rows.fri_reference.authority_digest,
        rows.control_reference.authority_digest,
        rows.input_reference.authority_digest,
    };
    for (reference_digests) |value| hash.update(&value);
    const preprocessing_digests = [_]air_digest.Digest{
        rows.query_bits_preprocessing.authority_digest,
        rows.query_mapping_preprocessing.authority_digest,
        rows.merkle_root_preprocessing.authority_digest,
        rows.trace_merkle_preprocessing.authority_digest,
        rows.pcs_preprocessing.authority_digest,
        rows.fri_leaf_preprocessing.authority_digest,
        rows.fri_node_preprocessing.authority_digest,
        rows.fri_anchor_preprocessing.authority_digest,
        rows.control_preprocessing.authority_digest,
        rows.input_preprocessing.authority_digest,
    };
    for (preprocessing_digests) |value| hash.update(&value);
    const binding_digests = [_]air_digest.Digest{
        rows.query_bits_executor.binding_digest,
        rows.query_mapping_executor.binding_digest,
        rows.merkle_root_executor.binding_digest,
        rows.trace_merkle_executor.binding_digest,
        rows.pcs_executor.binding_digest,
        rows.fri_leaf_executor.binding_digest,
        rows.fri_node_executor.binding_digest,
        rows.fri_anchor_executor.binding_digest,
        rows.control_executor.binding_digest,
        rows.input_executor.binding_digest,
    };
    for (binding_digests) |value| hash.update(&value);
    inline for (.{
        rows.query_bits_relation,
        rows.query_mapping_relation,
        rows.merkle_root_relation,
        rows.trace_merkle_relation,
        rows.pcs_relation,
        rows.fri_leaf_relation,
        rows.fri_node_relation,
        rows.fri_anchor_relation,
        rows.control_relation,
        rows.input_relation,
    }) |plan| {
        hashInt(&hash, u16, plan.format_version);
        hash.update(&plan.semantic_digest);
        hash.update(&plan.registry_order_digest);
        hashInt(&hash, u16, plan.compiled_node_count);
    }
    hash.update(&rows.inactive_fri_evaluation.circuit_identity);
    hash.update(&rows.inactive_pcs_evaluation.circuit_identity);
    for (rows.log_sizes) |log_size| hashInt(&hash, u32, log_size);
    for (rows.pcs_input_storage) |word| hashInt(&hash, u32, word.toU32());
    return hash.finalResult();
}
