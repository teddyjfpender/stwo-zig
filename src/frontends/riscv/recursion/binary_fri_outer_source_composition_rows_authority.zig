//! Internal shard of binary_fri_outer_source.zig; use the public facade.

const dependency_0 = @import("binary_fri_outer_source_claims.zig");
const dependency_1 = @import("binary_fri_outer_source_trusted_composition_profile_v1.zig");
const dependency_8 = @import("binary_fri_outer_source_composition_source_value.zig");
const dependency_9 = @import("binary_fri_outer_source_validate_captured_against_wire.zig");

const std = dependency_0.std;
const M31 = dependency_0.M31;
const air_digest = dependency_0.air_digest;
const protocol = dependency_0.protocol;
const composition = dependency_0.composition;
const composition_input_air = dependency_0.composition_input_air;
const composition_input_relation = dependency_0.composition_input_relation;
const composition_input_witness = dependency_0.composition_input_witness;
const composition_control_air = dependency_0.composition_control_air;
const composition_control_witness = dependency_0.composition_control_witness;
const lowering = dependency_0.lowering;
const schedule = dependency_0.schedule;
const universal = dependency_0.universal;
const CompositionControlRelation = dependency_0.CompositionControlRelation;
const CHILD_COUNT = dependency_0.CHILD_COUNT;
const LEFT_CHILD = dependency_0.LEFT_CHILD;
const LEFT_RECURSION_VERIFIER_ID = dependency_0.LEFT_RECURSION_VERIFIER_ID;
const RIGHT_RECURSION_VERIFIER_ID = dependency_0.RIGHT_RECURSION_VERIFIER_ID;
const VM_COMPOSITION_CAPACITY_CIRCUIT_ID = dependency_0.VM_COMPOSITION_CAPACITY_CIRCUIT_ID;
const COMPOSITION_ROW_COUNT = dependency_0.COMPOSITION_ROW_COUNT;
const compositionStatementScope = dependency_1.compositionStatementScope;
const VM_CAPACITY_NODES = dependency_1.VM_CAPACITY_NODES;
const VM_CAPACITY_OUTPUTS = dependency_1.VM_CAPACITY_OUTPUTS;
const validateCompositionInputs = dependency_8.validateCompositionInputs;
const validateGraphEvaluation = dependency_8.validateGraphEvaluation;
const materializeRecorderScheduleValues = dependency_8.materializeRecorderScheduleValues;
const validateRecorderScheduleValues = dependency_8.validateRecorderScheduleValues;
const materializeCompositionScheduleValues = dependency_8.materializeCompositionScheduleValues;
const validateCompositionScheduleValues = dependency_8.validateCompositionScheduleValues;
const hashInt = dependency_9.hashInt;

pub const VM_CAPACITY_BINDINGS = [_]composition.VmInputBinding{
    .{ .node_id = 0, .source = .segment_selector },
    .{ .node_id = 1, .source = .{ .composition_randomness = 0 } },
    .{ .node_id = 2, .source = .{ .composition_randomness = 1 } },
    .{ .node_id = 3, .source = .{ .composition_randomness = 2 } },
    .{ .node_id = 4, .source = .{ .composition_randomness = 3 } },
    .{ .node_id = 5, .source = .{ .oods_point = 0 } },
    .{ .node_id = 6, .source = .{ .oods_point = 1 } },
    .{ .node_id = 7, .source = .{ .oods_point = 2 } },
    .{ .node_id = 8, .source = .{ .oods_point = 3 } },
};

/// Exact rows 18--19 authority.  Row 18 is compiled from two root-admitted
/// recorder graphs and their source bindings.  Every bound graph input is
/// compared with the successful native verifier's fixed wire, transcript
/// draw, statement words, or capture before its schedule value is retained.
/// The VM lane is a protocol-owned one-input capacity graph and is inactive
/// for a binary proof; it exists solely because the universal row ABI carries
/// all proof kinds in one authenticated schedule.
pub const CompositionRowsAuthority = struct {
    const ReferenceStorage = struct {
        recursion_lanes: [CHILD_COUNT]composition.RecursionLane,
        anchors: [CHILD_COUNT]composition.AnchorLane,
    };

    allocator: std.mem.Allocator,
    /// The authenticated reference borrows these arrays. Heap ownership is
    /// deliberate: embedding them directly in this by-value return type would
    /// leave `reference` pointing into a moved stack frame in optimized builds.
    reference_storage: *ReferenceStorage,
    reference: composition.Reference,
    input_preprocessing: composition_input_witness.Preprocessed,
    control_preprocessing: composition_control_witness.CompositionPreprocessed,
    input_definition: composition_input_air.Definition,
    control_definition: composition_control_air.Definition,
    input_relation: composition_input_relation.Plan,
    control_relation: CompositionControlRelation.Plan,
    input_executor: composition_input_witness.Executor,
    schedule_values: []M31,
    log_sizes: [COMPOSITION_ROW_COUNT]u32,
    authority_digest: air_digest.Digest,

    /// Version-neutral row-18/19 seam for recorder-owned graphs.  Integration
    /// code must obtain both lanes from an opaque finalized recorder and both
    /// evaluations from that recorder's proof-kind-specific evaluation API;
    /// this constructor then revalidates the graphs/results and reuses the
    /// exact V1 schedule/control compilation rather than cloning either AIR.
    pub fn initFromAuthenticatedRecorderLanes(
        allocator: std.mem.Allocator,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        sampled_value_count: u32,
        lanes: [CHILD_COUNT]composition.RecursionLane,
        evaluations: [CHILD_COUNT]lowering.Evaluation,
    ) !CompositionRowsAuthority {
        const reference_storage = try allocator.create(ReferenceStorage);
        errdefer allocator.destroy(reference_storage);
        for (lanes, evaluations, 0..) |lane, evaluation, child_index| {
            const expected_verifier_id: u32 = if (child_index == LEFT_CHILD)
                LEFT_RECURSION_VERIFIER_ID
            else
                RIGHT_RECURSION_VERIFIER_ID;
            if (lane.verifier_id != expected_verifier_id or
                lane.statement_scope != compositionStatementScope(child_index))
            {
                return error.CompositionAuthorityMismatch;
            }
            try validateGraphEvaluation(lane.graph, evaluation);
            reference_storage.recursion_lanes[child_index] = lane;
            reference_storage.anchors[child_index] = .{
                .circuit_id = lane.circuit_id,
                .graph = lane.graph,
                .active_in = .BINARY,
            };
        }

        const vm_graph_digest = composition.computeGraphDigest(
            &VM_CAPACITY_NODES,
            &VM_CAPACITY_OUTPUTS,
        );
        const vm_graph = try composition.CircuitGraph.authenticate(
            &VM_CAPACITY_NODES,
            &VM_CAPACITY_OUTPUTS,
            vm_graph_digest,
        );
        const vm_lane = composition.VmLane{
            .circuit_id = VM_COMPOSITION_CAPACITY_CIRCUIT_ID,
            .graph = vm_graph,
            .profile = .{
                .sampled_value_count = 0,
                .claimed_sum_count = 0,
                .relation_challenge_count = 0,
            },
            .bindings = &VM_CAPACITY_BINDINGS,
        };
        const reference_digest = composition.computeReferenceDigest(
            vm_lane,
            &reference_storage.recursion_lanes,
            &reference_storage.anchors,
        );
        const reference = try composition.Reference.authenticate(
            vm_lane,
            &reference_storage.recursion_lanes,
            &reference_storage.anchors,
            reference_digest,
        );

        var input_preprocessing = try composition_input_witness.Preprocessed
            .initFromReference(allocator, &reference);
        errdefer input_preprocessing.deinit();
        var control_preprocessing = try composition_control_witness
            .CompositionPreprocessed.init(
            allocator,
            vm_plan,
            vm_plan.spec.air_instruction_count,
            sampled_value_count,
            recursion_plan,
            recursion_plan.spec.air_instruction_count,
            sampled_value_count,
        );
        errdefer control_preprocessing.deinit();
        var input_definition = try composition_input_air.build(allocator);
        errdefer input_definition.deinit();
        var control_definition = try composition_control_air.build(allocator);
        errdefer control_definition.deinit();
        const input_binding = try composition_input_witness.Binding.canonical(
            &input_definition,
        );
        const schedule_values = try allocator.alloc(
            M31,
            input_preprocessing.rows.len,
        );
        errdefer allocator.free(schedule_values);
        try materializeRecorderScheduleValues(
            evaluations,
            input_preprocessing.rows,
            schedule_values,
        );

        var result = CompositionRowsAuthority{
            .allocator = allocator,
            .reference_storage = reference_storage,
            .reference = reference,
            .input_preprocessing = input_preprocessing,
            .control_preprocessing = control_preprocessing,
            .input_definition = input_definition,
            .control_definition = control_definition,
            .input_relation = try composition_input_relation.authenticate(
                &input_definition,
            ),
            .control_relation = try CompositionControlRelation.authenticate(
                &control_definition,
            ),
            .input_executor = try composition_input_witness.Executor.init(
                &input_definition,
                &input_binding,
            ),
            .schedule_values = schedule_values,
            .log_sizes = .{
                input_preprocessing.log_size,
                control_preprocessing.log_size,
            },
            .authority_digest = undefined,
        };
        result.authority_digest = compositionRowsAuthorityDigest(&result);
        try result.validateAuthenticatedRecorderLanes(evaluations);
        return result;
    }

    pub fn init(
        allocator: std.mem.Allocator,
        pair: anytype,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        children: anytype,
    ) !CompositionRowsAuthority {
        const reference_storage = try allocator.create(ReferenceStorage);
        errdefer allocator.destroy(reference_storage);
        for (children, 0..) |child, child_index| {
            const authority = child.composition orelse
                return error.MissingCompositionAuthority;
            const trusted = child.trusted_composition_profile orelse
                return error.MissingCompositionAuthority;
            if (!trusted.row18_input_authority)
                return error.MissingCompositionAuthority;
            try validateCompositionInputs(pair, child, child_index, trusted);
            reference_storage.recursion_lanes[child_index] = .{
                .verifier_id = authority.verifier_id,
                .circuit_id = authority.circuit_id,
                .statement_scope = compositionStatementScope(child_index),
                .graph = authority.graph,
                .profile = trusted.input_profile,
                .bindings = trusted.input_bindings,
            };
            reference_storage.anchors[child_index] = .{
                .circuit_id = authority.circuit_id,
                .graph = authority.graph,
                .active_in = .BINARY,
            };
        }

        const vm_graph_digest = composition.computeGraphDigest(
            &VM_CAPACITY_NODES,
            &VM_CAPACITY_OUTPUTS,
        );
        const vm_graph = try composition.CircuitGraph.authenticate(
            &VM_CAPACITY_NODES,
            &VM_CAPACITY_OUTPUTS,
            vm_graph_digest,
        );
        const vm_lane = composition.VmLane{
            .circuit_id = VM_COMPOSITION_CAPACITY_CIRCUIT_ID,
            .graph = vm_graph,
            .profile = .{
                .sampled_value_count = 0,
                .claimed_sum_count = 0,
                .relation_challenge_count = 0,
            },
            .bindings = &VM_CAPACITY_BINDINGS,
        };
        const reference_digest = composition.computeReferenceDigest(
            vm_lane,
            &reference_storage.recursion_lanes,
            &reference_storage.anchors,
        );
        const reference = try composition.Reference.authenticate(
            vm_lane,
            &reference_storage.recursion_lanes,
            &reference_storage.anchors,
            reference_digest,
        );

        var input_preprocessing = try composition_input_witness.Preprocessed
            .initFromReference(allocator, &reference);
        errdefer input_preprocessing.deinit();
        const sampled_value_count: u32 = @intCast(
            children[LEFT_CHILD].capture.sampled_values.len,
        );
        var control_preprocessing = try composition_control_witness
            .CompositionPreprocessed.init(
            allocator,
            vm_plan,
            vm_plan.spec.air_instruction_count,
            sampled_value_count,
            recursion_plan,
            recursion_plan.spec.air_instruction_count,
            sampled_value_count,
        );
        errdefer control_preprocessing.deinit();
        var input_definition = try composition_input_air.build(allocator);
        errdefer input_definition.deinit();
        var control_definition = try composition_control_air.build(allocator);
        errdefer control_definition.deinit();
        const input_binding = try composition_input_witness.Binding.canonical(
            &input_definition,
        );
        const schedule_values = try allocator.alloc(
            M31,
            input_preprocessing.rows.len,
        );
        errdefer allocator.free(schedule_values);
        try materializeCompositionScheduleValues(
            pair,
            children,
            input_preprocessing.rows,
            schedule_values,
        );

        var result = CompositionRowsAuthority{
            .allocator = allocator,
            .reference_storage = reference_storage,
            .reference = reference,
            .input_preprocessing = input_preprocessing,
            .control_preprocessing = control_preprocessing,
            .input_definition = input_definition,
            .control_definition = control_definition,
            .input_relation = try composition_input_relation.authenticate(
                &input_definition,
            ),
            .control_relation = try CompositionControlRelation.authenticate(
                &control_definition,
            ),
            .input_executor = try composition_input_witness.Executor.init(
                &input_definition,
                &input_binding,
            ),
            .schedule_values = schedule_values,
            .log_sizes = .{
                input_preprocessing.log_size,
                control_preprocessing.log_size,
            },
            .authority_digest = undefined,
        };
        result.authority_digest = compositionRowsAuthorityDigest(&result);
        try result.validate(pair, vm_plan, recursion_plan, children);
        return result;
    }

    pub fn deinit(self: *CompositionRowsAuthority) void {
        self.allocator.free(self.schedule_values);
        self.control_definition.deinit();
        self.input_definition.deinit();
        self.control_preprocessing.deinit();
        self.input_preprocessing.deinit();
        self.allocator.destroy(self.reference_storage);
        self.* = undefined;
    }

    pub fn validateAuthenticatedRecorderLanes(
        self: *const CompositionRowsAuthority,
        evaluations: [CHILD_COUNT]lowering.Evaluation,
    ) !void {
        try self.reference.validate();
        try self.input_preprocessing.validate();
        try self.input_definition.validate();
        try self.control_definition.validate();
        try self.input_relation.validateAgainst(
            &self.input_definition.arena,
            composition_input_air.SEMANTIC_DIGEST,
            self.input_definition.events,
        );
        try self.control_relation.validateAgainst(
            &self.control_definition.arena,
            composition_control_air.SEMANTIC_DIGEST,
            .{self.control_definition.event},
        );
        const expected_binding = try composition_input_witness.Binding.canonical(
            &self.input_definition,
        );
        if (!std.meta.eql(self.input_executor.binding, expected_binding) or
            self.schedule_values.len != self.input_preprocessing.rows.len or
            !std.meta.eql(self.log_sizes, [COMPOSITION_ROW_COUNT]u32{
                self.input_preprocessing.log_size,
                self.control_preprocessing.log_size,
            }))
        {
            return error.SourceAuthorityMismatch;
        }
        for (self.reference_storage.recursion_lanes, evaluations) |
            lane,
            evaluation,
        | try validateGraphEvaluation(lane.graph, evaluation);
        try validateRecorderScheduleValues(
            evaluations,
            self.input_preprocessing.rows,
            self.schedule_values,
        );
        if (!std.mem.eql(
            u8,
            &self.authority_digest,
            &compositionRowsAuthorityDigest(self),
        )) return error.SourceAuthorityMismatch;
    }

    /// Failure-atomic owned clone for a second proof-profile schedule using
    /// the same authenticated recorder lanes and retained evaluations. This
    /// is intentionally a semantic reconstruction, not a shallow copy: every
    /// allocation and AIR owner belongs exclusively to the returned value.
    pub fn cloneWithAuthenticatedSchedule(
        self: *const CompositionRowsAuthority,
        allocator: std.mem.Allocator,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        sampled_value_count: u32,
        evaluations: [CHILD_COUNT]lowering.Evaluation,
    ) !CompositionRowsAuthority {
        try self.validateAuthenticatedRecorderLanes(evaluations);
        const lanes = self.reference_storage.recursion_lanes;
        var result = try CompositionRowsAuthority
            .initFromAuthenticatedRecorderLanes(
            allocator,
            vm_plan,
            recursion_plan,
            sampled_value_count,
            lanes,
            evaluations,
        );
        errdefer result.deinit();
        try result.control_preprocessing.validateAgainst(
            vm_plan,
            recursion_plan,
        );
        try result.validateAuthenticatedRecorderLanes(evaluations);
        return result;
    }

    pub fn validate(
        self: *const CompositionRowsAuthority,
        pair: anytype,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        children: anytype,
    ) !void {
        try self.reference.validate();
        try self.input_preprocessing.validate();
        try self.control_preprocessing.validateAgainst(vm_plan, recursion_plan);
        try self.input_definition.validate();
        try self.control_definition.validate();
        try self.input_relation.validateAgainst(
            &self.input_definition.arena,
            composition_input_air.SEMANTIC_DIGEST,
            self.input_definition.events,
        );
        try self.control_relation.validateAgainst(
            &self.control_definition.arena,
            composition_control_air.SEMANTIC_DIGEST,
            .{self.control_definition.event},
        );
        const expected_binding = try composition_input_witness.Binding.canonical(
            &self.input_definition,
        );
        if (!std.meta.eql(self.input_executor.binding, expected_binding) or
            self.schedule_values.len != self.input_preprocessing.rows.len or
            !std.meta.eql(self.log_sizes, [COMPOSITION_ROW_COUNT]u32{
                self.input_preprocessing.log_size,
                self.control_preprocessing.log_size,
            }))
        {
            return error.SourceAuthorityMismatch;
        }
        for (children, 0..) |child, child_index| {
            const trusted = child.trusted_composition_profile orelse
                return error.MissingCompositionAuthority;
            try validateCompositionInputs(pair, child, child_index, trusted);
        }
        try validateCompositionScheduleValues(
            pair,
            children,
            self.input_preprocessing.rows,
            self.schedule_values,
        );
        if (!std.mem.eql(
            u8,
            &self.authority_digest,
            &compositionRowsAuthorityDigest(self),
        )) return error.SourceAuthorityMismatch;
    }
};

pub fn compositionRowsAuthorityDigest(
    rows: *const CompositionRowsAuthority,
) air_digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/binary-fri-rows-18-19/v1\x00");
    hash.update(&rows.reference.identity_digest);
    hash.update(&rows.input_preprocessing.authority_digest);
    for (rows.control_preprocessing.vm_schedule_digest) |word|
        hashInt(&hash, u32, word);
    for (rows.control_preprocessing.recursion_schedule_digest) |word|
        hashInt(&hash, u32, word);
    hash.update(&rows.input_executor.binding_digest);
    hashInt(&hash, u16, rows.input_relation.format_version);
    hash.update(&rows.input_relation.semantic_digest);
    hash.update(&rows.input_relation.registry_order_digest);
    hashInt(&hash, u16, rows.control_relation.format_version);
    hash.update(&rows.control_relation.semantic_digest);
    hash.update(&rows.control_relation.registry_order_digest);
    for (rows.log_sizes) |log_size| hashInt(&hash, u32, log_size);
    for (rows.schedule_values) |value| hashInt(&hash, u32, value.toU32());
    return hash.finalResult();
}
