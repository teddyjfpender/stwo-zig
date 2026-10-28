//! Typed PCS/FRI checks for one detached child. The owner retains copied capture
//! and program geometry; selected logical rows borrow only this immutable owner.
//! This is a preparation inventory, not a recursive proof or closure receipt.
const std = @import("std");
const core = @import("stwo_core");
const recursion = struct {
    const air = struct {
        const composition_circuit = @import("air/composition_circuit.zig");
        const control_witness = @import("air/control_witness.zig");
        const direct_constraint_program = @import("air/direct_constraint_program.zig");
        const fri_merkle_anchor = @import("air/fri_merkle_anchor.zig");
        const fri_merkle_anchor_witness = @import("air/fri_merkle_anchor_witness.zig");
        const fri_merkle_leaf = @import("air/fri_merkle_leaf.zig");
        const fri_merkle_leaf_witness = @import("air/fri_merkle_leaf_witness.zig");
        const fri_merkle_node = @import("air/fri_merkle_node.zig");
        const fri_merkle_node_witness = @import("air/fri_merkle_node_witness.zig");
        const fri_verifier_circuit = @import("air/fri_verifier_circuit.zig");
        const fri_verifier_control = @import("air/fri_verifier_control.zig");
        const fri_verifier_control_witness = @import("air/fri_verifier_control_witness.zig");
        const fri_verifier_input = @import("air/fri_verifier_input.zig");
        const fri_verifier_input_witness = @import("air/fri_verifier_input_witness.zig");
        const merkle_path = @import("air/merkle_path.zig");
        const merkle_path_relation = @import("air/merkle_path_relation.zig");
        const merkle_path_witness = @import("air/merkle_path_witness.zig");
        const merkle_root = @import("air/merkle_root.zig");
        const merkle_root_witness = @import("air/merkle_root_witness.zig");
        const pcs_deep_circuit = @import("air/pcs_deep_circuit.zig");
        const pcs_deep_input = @import("air/pcs_deep_input.zig");
        const pcs_deep_input_witness = @import("air/pcs_deep_input_witness.zig");
        const query_bits = @import("air/query_bits.zig");
        const query_bits_witness = @import("air/query_bits_witness.zig");
        const query_mapping = @import("air/query_mapping.zig");
        const query_mapping_witness = @import("air/query_mapping_witness.zig");
        const trace_merkle = @import("air/trace_merkle.zig");
        const trace_merkle_witness = @import("air/trace_merkle_witness.zig");
        const universal_challenges = @import("air/universal_challenges.zig");
        const verifier_schedule = @import("air/verifier_schedule.zig");
    };
    const binary_fri_outer_source = @import("binary_fri_outer_source.zig");
    const captured_fri = @import("captured_fri.zig");
    const fixed_profile = @import("fixed_profile.zig");
    const protocol = @import("protocol.zig");
};
const air = recursion.air;
const schedule = air.verifier_schedule;
const fixed = recursion.fixed_profile;
const source = recursion.binary_fri_outer_source;
const key_shape = @import("detached_pcs_key_shape_v1.zig");
const key_geometry = @import("detached_pcs_key_geometry_v1.zig");
const device_interaction = @import("air/framework_device_interaction.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const ProviderCall = @import("../air/lang/typed_poseidon2_witness.zig").Call;
const Digest = recursion.protocol.Digest;
const W = struct {
    const query_bits = air.query_bits_witness;
    const query_mapping = air.query_mapping_witness;
    const merkle_root = air.merkle_root_witness;
    const trace_merkle = air.trace_merkle_witness;
    const pcs_deep = air.pcs_deep_input_witness;
    const fri_leaf = air.fri_merkle_leaf_witness;
    const fri_node = air.fri_merkle_node_witness;
    const fri_anchor = air.fri_merkle_anchor_witness;
    const fri_control = air.fri_verifier_control_witness;
    const fri_input = air.fri_verifier_input_witness;
};
const A = struct {
    const query_bits = air.query_bits;
    const query_mapping = air.query_mapping;
    const merkle_root = air.merkle_root;
    const trace_merkle = air.trace_merkle;
    const pcs_deep = air.pcs_deep_input;
    const fri_leaf = air.fri_merkle_leaf;
    const fri_node = air.fri_merkle_node;
    const fri_anchor = air.fri_merkle_anchor;
    const fri_control = air.fri_verifier_control;
    const fri_input = air.fri_verifier_input;
};
fn Row(comptime Air: type) type {
    return [Air.LOGICAL_INPUT_COUNT]M31;
}
pub const View = struct {
    query_bits: []const Row(A.query_bits),
    query_mapping: []const Row(A.query_mapping),
    merkle_root: []const Row(A.merkle_root),
    trace_merkle: []const Row(A.trace_merkle),
    pcs_deep: []const Row(A.pcs_deep),
    fri_leaf: []const Row(A.fri_leaf),
    fri_node: []const Row(A.fri_node),
    fri_anchor: []const Row(A.fri_anchor),
    fri_control: []const Row(A.fri_control),
    fri_input: []const Row(A.fri_input),
    control: []const air.control_witness.Row,
    merkle_path: []const Row(air.merkle_path),
    provider: []const ProviderCall,
    provider_outputs: []const [16]u32,
    pcs_metadata: []const W.pcs_deep.Row,
    fri_metadata: []const W.fri_input.Row,
};
pub const OwnedV1 = opaque {
    const Storage = struct {
        allocator: std.mem.Allocator,
        arena: std.heap.ArenaAllocator,
        capture: recursion.captured_fri.Owned,
        vm_plan: schedule.Plan,
        recursion_plan: schedule.Plan,
        rows: source.FriRowsAuthority,
        view_value: View,
        lane: u32,
    };
    fn storage(self: *const OwnedV1) *const Storage {
        return @ptrCast(@alignCast(self));
    }
    pub fn init(allocator: std.mem.Allocator, child: anytype, lane: u32) !*OwnedV1 {
        return initWithLaneSelection(allocator, child, lane, true, null);
    }
    pub fn initWithCache(allocator: std.mem.Allocator, child: anytype, lane: u32, cache: ?*@import("air/pcs_deep_plan_cache.zig").Cache) !*OwnedV1 {
        return initWithLaneSelection(allocator, child, lane, true, cache);
    }
    fn initWithLaneSelection(allocator: std.mem.Allocator, child: anytype, lane: u32, comptime selected_lane_only: bool, cache: ?*@import("air/pcs_deep_plan_cache.zig").Cache) !*OwnedV1 {
        if (!selected_lane_only and !@import("builtin").is_test)
            @compileError("discarded-lane preparation is an independent test oracle only");
        if (lane != 1 and lane != 2) return error.InvalidDetachedPcsLane;
        const value = try allocator.create(Storage);
        errdefer allocator.destroy(value);
        value.allocator = allocator;
        value.arena = std.heap.ArenaAllocator.init(allocator);
        errdefer value.arena.deinit();
        const owned = value.arena.allocator();
        value.lane = lane;
        var timer = if (std.process.hasEnvVarConstant("STWO_RISCV_RECURSIVE_PARENT_PROFILE")) @as(?std.time.Timer, try std.time.Timer.start()) else null;
        value.capture = try child.preparePcsWithCache(owned, cache);
        errdefer value.capture.deinit();
        const capture_ns = if (timer) |*t| t.lap() else 0;
        value.vm_plan = try makePlan(owned, child, &value.capture, .vm);
        value.recursion_plan = try makePlan(owned, child, &value.capture, .recursion);
        const plans_ns = if (timer) |*t| t.lap() else 0;
        // Both template lanes use this child's independently admitted geometry.
        // Only the selected lane is exported; the other lane is never proved.
        const Child = struct { capture: *const recursion.captured_fri.Owned };
        value.rows = try source.FriRowsAuthority.init(owned, &value.vm_plan, &value.recursion_plan, [2]Child{ .{ .capture = &value.capture }, .{ .capture = &value.capture } });
        const authority_ns = if (timer) |*t| t.lap() else 0;
        try buildRows(value, child, selected_lane_only);
        const rows_ns = if (timer) |*t| t.lap() else 0;
        if (timer != null) std.debug.print("DETACHED_PARENT_PCS_PHASE lane={d} selected_lane_only={} capture_ns={d} plans_ns={d} authority_ns={d} rows_ns={d}\n", .{ lane, selected_lane_only, capture_ns, plans_ns, authority_ns, rows_ns });
        return @ptrCast(value);
    }
    pub fn deinit(self: *OwnedV1) void {
        const value: *Storage = @ptrCast(@alignCast(self));
        const allocator = value.allocator;
        value.capture.deinit();
        value.arena.deinit();
        allocator.destroy(value);
    }
    pub fn view(self: *const OwnedV1) View {
        return self.storage().view_value;
    }
    pub fn pcsGraph(self: *const OwnedV1) air.composition_circuit.CircuitGraph {
        return self.storage().capture.pcs_circuit.graph();
    }
    pub fn friGraph(self: *const OwnedV1) air.composition_circuit.CircuitGraph {
        return self.storage().capture.circuit.graph();
    }
    pub fn pcsBindings(self: *const OwnedV1) []const air.pcs_deep_circuit.InputBinding {
        return self.storage().capture.pcs_circuit.view().bindings;
    }
    pub fn friBindings(self: *const OwnedV1) []const air.fri_verifier_circuit.InputBinding {
        return self.storage().capture.circuit.bindings;
    }
    pub fn pcsValues(self: *const OwnedV1) []const QM31 {
        return self.storage().capture.pcs_evaluation.view().values;
    }
    pub fn friValues(self: *const OwnedV1) []const QM31 {
        return self.storage().capture.evaluation.values;
    }
};

fn makePlan(allocator: std.mem.Allocator, child: anytype, capture: *const recursion.captured_fri.Owned, schema: schedule.Schema) !schedule.Plan {
    const key = child.key();
    const shape = try key_shape.scheduleShape(allocator, key);
    var geometry = try key_geometry.GeometryV1.init(allocator, key);
    defer geometry.deinit();
    try geometry.validateCaptured(capture);
    if (capture.trace_tree_heights.len != fixed.TREE_COUNT)
        return error.DetachedPcsTreeCount;
    if (!std.mem.eql(u32, capture.trace_tree_heights, &shape.tree_heights))
        return error.DetachedPcsKeyTreeHeightMismatch;
    if (capture.circuit.lifting_log_size != shape.tree_heights[fixed.TREE_COUNT - 1])
        return error.DetachedPcsKeyLiftingMismatch;
    if (capture.interaction_pow_bits != shape.interaction_pow_bits or
        capture.pcs_pow_bits != shape.pcs_pow_bits)
        return error.DetachedPcsKeyPowMismatch;
    if (capture.circuit.query_count != shape.query_count)
        return error.DetachedPcsKeyQueryCountMismatch;
    if (capture.sampled_value_count != shape.sampled_value_count)
        return error.DetachedPcsKeySampleCountMismatch;
    if (child.claims().values.len != shape.claimed_sum_count)
        return error.DetachedPcsKeyClaimCountMismatch;
    return schedule.Plan.initShape(allocator, try schedule.ProgramSpec.init(schema, air.universal_challenges.RELATION_COUNT, 1, key.manifest.total_constraints, air.universal_challenges.RELATION_COUNT), shape);
}

fn Columns(comptime Witness: type) type {
    return struct {
        columns: [Witness.MAIN_COLUMN_COUNT][]M31,
        fn init(allocator: std.mem.Allocator, log_size: u32) !@This() {
            const height = @as(usize, 1) << @intCast(log_size);
            const values = try allocator.alloc(M31, Witness.MAIN_COLUMN_COUNT * height);
            var result: @This() = undefined;
            for (&result.columns, 0..) |*column, index| column.* = values[index * height ..][0..height];
            return result;
        }
    };
}
fn selectRows(comptime Air: type, allocator: std.mem.Allocator, lane: u32, metadata: anytype, columns: anytype, exemplar: Row(Air)) ![]const Row(Air) {
    var count: usize = 0;
    for (metadata) |row| count += @intFromBool(row.verifier_id == lane);
    const result = try allocator.alloc(Row(Air), count);
    var at: usize = 0;
    for (metadata, 0..) |row, index| {
        if (row.verifier_id != lane) continue;
        for (columns, 0..) |column, col| result[at][col] = column[index];
        result[at][Air.PHYSICAL_MAIN_COLUMN_COUNT..][0..Air.PREPROCESSED_COLUMN_COUNT].* = row.values();
        @memcpy(result[at][Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.PREPROCESSED_COLUMN_COUNT ..], exemplar[Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.PREPROCESSED_COLUMN_COUNT ..]);
        at += 1;
    }
    return result;
}
fn selectedMetadata(comptime T: type, allocator: std.mem.Allocator, lane: u32, rows: []const T) ![]const T {
    var result: std.ArrayList(T) = .empty;
    for (rows) |row| if (row.verifier_id == lane) try result.append(allocator, row);
    return result.toOwnedSlice(allocator);
}

pub fn controlRowsFromKey(allocator: std.mem.Allocator, key: anytype, lane: u32) ![]air.control_witness.Row {
    if (lane != 1 and lane != 2) return error.InvalidDetachedPcsLane;
    var plan = try key_shape.planFromKey(allocator, key, .recursion);
    defer plan.deinit();
    return controlRowsFromPlan(allocator, &plan, lane);
}

fn controlRowsFromPlan(allocator: std.mem.Allocator, plan: *const schedule.Plan, lane: u32) ![]air.control_witness.Row {
    var control: std.ArrayList(air.control_witness.Row) = .empty;
    errdefer control.deinit(allocator);
    for (plan.steps, 0..) |step, sequence| switch (step) {
        .verify_trace_merkle_path, .evaluate_deep_quotient, .verify_fri_merkle_path, .fold_fri, .verify_last_layer => {
            const encoded = step.encode();
            try control.append(allocator, .{ .segment_mask = 0, .binary_mask = 1, .verifier_id = lane, .sequence = std.math.cast(u32, sequence) orelse return error.ArithmeticOverflow, .tag = encoded.tag, .args = encoded.args, .terminal_mask = 0 });
        },
        else => {},
    };
    return control.toOwnedSlice(allocator);
}
fn buildRows(value: *OwnedV1.Storage, child: anytype, comptime selected_lane_only: bool) !void {
    const allocator = value.arena.allocator();
    var scratch_arena = std.heap.ArenaAllocator.init(value.allocator);
    defer scratch_arena.deinit();
    const scratch = scratch_arena.allocator();
    const capture = &value.capture;
    const prepared = &value.rows;
    const full_query_draws = try scratch.alloc(M31, capture.raw_queries.len);
    try child.writeRawQueryDraws(full_query_draws);
    const query = W.query_bits.QueryWitness{ .binary_node = .{ .left = full_query_draws, .right = full_query_draws } };
    const roots = W.merkle_root.RootWitness{ .binary_node = .{ .left = .{ .trace = capture.trace_roots, .fri = capture.fri_roots }, .right = .{ .trace = capture.trace_roots, .fri = capture.fri_roots } } };
    const trace = W.trace_merkle.OpeningWitness{ .binary_node = .{ .left = .{ .queried_values = capture.queried_values, .raw_queries = capture.raw_queries }, .right = .{ .queried_values = capture.queried_values, .raw_queries = capture.raw_queries } } };
    const fri = W.fri_leaf.OpeningWitness{ .binary_node = .{ .left = .{ .raw_queries = capture.raw_queries, .layers = capture.fri_layer_openings }, .right = .{ .raw_queries = capture.raw_queries, .layers = capture.fri_layer_openings } } };
    const evaluations = W.fri_input.Evaluations{ .segment = &prepared.inactive_fri_evaluation, .left = &capture.evaluation, .right = &capture.evaluation };
    var query_bits = try Columns(W.query_bits).init(scratch, prepared.query_bits_preprocessing.log_size);
    try prepared.query_bits_executor.generateMainInto(&prepared.query_bits_preprocessing, prepared.query_bits_reference, &query_bits.columns, query);
    value.view_value.query_bits = try selectRows(A.query_bits, allocator, value.lane, prepared.query_bits_preprocessing.rows, query_bits.columns, try W.query_bits.logicalRow(prepared.query_bits_preprocessing.rows[0], query, try W.query_bits.parameterValues(prepared.query_bits_reference, .binary_node)));
    var query_mapping = try Columns(W.query_mapping).init(scratch, prepared.query_mapping_preprocessing.log_size);
    try prepared.query_mapping_executor.generateMainInto(&prepared.query_mapping_preprocessing, prepared.query_mapping_reference, &query_mapping.columns, query);
    value.view_value.query_mapping = try selectRows(A.query_mapping, allocator, value.lane, prepared.query_mapping_preprocessing.rows, query_mapping.columns, try W.query_mapping.logicalRow(prepared.query_mapping_preprocessing.rows[0], query));
    var merkle_root = try Columns(W.merkle_root).init(scratch, prepared.merkle_root_preprocessing.log_size);
    try prepared.merkle_root_executor.generateMainInto(&prepared.merkle_root_preprocessing, prepared.merkle_root_reference, &merkle_root.columns, roots);
    value.view_value.merkle_root = try selectRows(A.merkle_root, allocator, value.lane, prepared.merkle_root_preprocessing.rows, merkle_root.columns, try W.merkle_root.logicalRow(prepared.merkle_root_preprocessing.rows[0], roots));
    if (selected_lane_only) {
        value.view_value.trace_merkle = try prepared.trace_merkle_executor.generateLogicalForLane(allocator, &prepared.trace_merkle_preprocessing, prepared.trace_merkle_reference, trace, value.lane);
    } else {
        var trace_merkle = try Columns(W.trace_merkle).init(scratch, prepared.trace_merkle_preprocessing.log_size);
        try prepared.trace_merkle_executor.generateMainInto(&prepared.trace_merkle_preprocessing, prepared.trace_merkle_reference, &trace_merkle.columns, trace);
        value.view_value.trace_merkle = try selectRows(A.trace_merkle, allocator, value.lane, prepared.trace_merkle_preprocessing.rows, trace_merkle.columns, try W.trace_merkle.logicalRow(prepared.trace_merkle_reference, &prepared.trace_merkle_preprocessing, 0, trace));
    }
    if (selected_lane_only) {
        value.view_value.pcs_deep = try prepared.pcs_executor.generateLogicalForLane(allocator, &prepared.pcs_preprocessing, prepared.pcs_reference, prepared.pcs_inputs, .binary_node, value.lane);
    } else {
        var pcs_deep = try Columns(W.pcs_deep).init(scratch, prepared.pcs_preprocessing.log_size);
        try prepared.pcs_executor.generateMainInto(&prepared.pcs_preprocessing, prepared.pcs_reference, &pcs_deep.columns, prepared.pcs_inputs, .binary_node);
        value.view_value.pcs_deep = try selectRows(A.pcs_deep, allocator, value.lane, prepared.pcs_preprocessing.rows, pcs_deep.columns, try W.pcs_deep.logicalRow(prepared.pcs_reference, &prepared.pcs_preprocessing, 0, prepared.pcs_inputs, .binary_node));
    }
    if (selected_lane_only) {
        value.view_value.fri_leaf = try prepared.fri_leaf_executor.generateLogicalForLane(allocator, &prepared.fri_leaf_preprocessing, prepared.fri_reference, fri, value.lane);
    } else {
        var fri_leaf = try Columns(W.fri_leaf).init(scratch, prepared.fri_leaf_preprocessing.log_size);
        try prepared.fri_leaf_executor.generateMainInto(&prepared.fri_leaf_preprocessing, prepared.fri_reference, &fri_leaf.columns, fri);
        value.view_value.fri_leaf = try selectRows(A.fri_leaf, allocator, value.lane, prepared.fri_leaf_preprocessing.rows, fri_leaf.columns, try W.fri_leaf.logicalRow(prepared.fri_reference, &prepared.fri_leaf_preprocessing, 0, fri));
    }
    if (selected_lane_only) {
        value.view_value.fri_node = try prepared.fri_node_executor.generateLogicalForLane(allocator, &prepared.fri_node_preprocessing, prepared.fri_reference, fri, value.lane);
    } else {
        var fri_node = try Columns(W.fri_node).init(scratch, prepared.fri_node_preprocessing.log_size);
        try prepared.fri_node_executor.generateMainInto(&prepared.fri_node_preprocessing, prepared.fri_reference, &fri_node.columns, fri);
        value.view_value.fri_node = try selectRows(A.fri_node, allocator, value.lane, prepared.fri_node_preprocessing.rows, fri_node.columns, W.fri_node.logicalInputs(@splat(M31.zero()), @splat(M31.zero()), .binary_node));
    }
    if (selected_lane_only) {
        value.view_value.fri_anchor = try prepared.fri_anchor_executor.generateLogicalForLane(allocator, &prepared.fri_anchor_preprocessing, prepared.fri_reference, &value.vm_plan, &value.recursion_plan, fri, value.lane);
    } else {
        var fri_anchor = try Columns(W.fri_anchor).init(scratch, prepared.fri_anchor_preprocessing.log_size);
        try prepared.fri_anchor_executor.generateMainInto(&prepared.fri_anchor_preprocessing, prepared.fri_reference, &value.vm_plan, &value.recursion_plan, &fri_anchor.columns, fri);
        value.view_value.fri_anchor = try selectRows(A.fri_anchor, allocator, value.lane, prepared.fri_anchor_preprocessing.rows, fri_anchor.columns, try W.fri_anchor.logicalRow(prepared.fri_reference, &prepared.fri_anchor_preprocessing, &value.vm_plan, &value.recursion_plan, 0, fri));
    }
    var fri_control = try Columns(W.fri_control).init(scratch, prepared.control_preprocessing.log_size);
    try prepared.control_executor.generateMainInto(&prepared.control_preprocessing, prepared.control_reference, &fri_control.columns, query);
    value.view_value.fri_control = try selectRows(A.fri_control, allocator, value.lane, prepared.control_preprocessing.rows, fri_control.columns, try W.fri_control.logicalRow(prepared.control_reference, &prepared.control_preprocessing, 0, query));
    if (selected_lane_only) {
        value.view_value.fri_input = try prepared.input_executor.generateLogicalForLane(allocator, &prepared.input_preprocessing, prepared.input_reference, evaluations, .binary_node, value.lane);
    } else {
        var fri_input = try Columns(W.fri_input).init(scratch, prepared.input_preprocessing.log_size);
        try prepared.input_executor.generateMainInto(&prepared.input_preprocessing, prepared.input_reference, &fri_input.columns, evaluations, .binary_node);
        value.view_value.fri_input = try selectRows(A.fri_input, allocator, value.lane, prepared.input_preprocessing.rows, fri_input.columns, try W.fri_input.logicalRow(prepared.input_reference, &prepared.input_preprocessing, 0, evaluations, .binary_node));
    }
    value.view_value.pcs_metadata = try selectedMetadata(W.pcs_deep.Row, allocator, value.lane, prepared.pcs_preprocessing.rows);
    value.view_value.fri_metadata = try selectedMetadata(W.fri_input.Row, allocator, value.lane, prepared.input_preprocessing.rows);
    value.view_value.control = try controlRowsFromPlan(allocator, &value.recursion_plan, value.lane);
    try buildPathsAndProvider(value);
}

fn appendPath(allocator: std.mem.Allocator, rows: *std.ArrayList(Row(air.merkle_path)), tree_id: u32, position: u32, leaf: Digest, siblings: []const Digest, expected_root: Digest) !void {
    const witness = air.merkle_path_witness;
    const steps = try allocator.alloc(witness.PathStep, siblings.len);
    defer allocator.free(steps);
    for (steps, 0..) |*step, depth| {
        const from_leaf = siblings.len - depth - 1;
        step.* = .{ .direction = (position >> @as(u5, @intCast(from_leaf))) & 1, .sibling = siblings[from_leaf] };
    }
    var path = try witness.PreparedPath.init(allocator, tree_id, 0, 0, leaf, steps);
    defer path.deinit();
    if (!std.meta.eql(path.root, expected_root)) return error.DetachedPcsPathRootMismatch;
    for (path.rows) |invocation| try rows.append(allocator, try witness.logicalRow(invocation));
}

fn buildPathsAndProvider(value: *OwnedV1.Storage) !void {
    const allocator = value.arena.allocator();
    const capture = &value.capture;
    const prepared = &value.rows;
    var paths: std.ArrayList(Row(air.merkle_path)) = .empty;
    var logical_index: usize = 0;
    var leaf_count: usize = 0;
    for (prepared.trace_merkle_preprocessing.rows) |metadata| {
        if (metadata.verifier_id != value.lane) continue;
        const row = value.view_value.trace_merkle[logical_index];
        logical_index += 1;
        if (metadata.last != 1) continue;
        const height = capture.trace_tree_heights[metadata.tree];
        const siblings = capture.trace_siblings[metadata.tree][metadata.query * height ..][0..height];
        var leaf: Digest = undefined;
        for (&leaf, row[@intFromEnum(W.trace_merkle.MainSource.output_0)..][0..8]) |*word, scalar| word.* = scalar.toU32();
        try appendPath(allocator, &paths, try W.merkle_root.traceTreeId(value.lane, metadata.tree), row[@intFromEnum(W.trace_merkle.MainSource.position)].toU32(), leaf, siblings, capture.trace_roots[metadata.tree]);
        leaf_count += 1;
    }
    if (leaf_count != capture.raw_queries.len * capture.trace_tree_heights.len) return error.DetachedPcsLeafCoverageMismatch;
    logical_index = 0;
    leaf_count = 0;
    for (prepared.fri_anchor_preprocessing.rows) |metadata| {
        if (metadata.verifier_id != value.lane) continue;
        const row = value.view_value.fri_anchor[logical_index];
        logical_index += 1;
        const all_siblings = capture.fri_siblings[metadata.layer];
        if (all_siblings.len % capture.raw_queries.len != 0) return error.DetachedPcsPathShapeMismatch;
        const height = all_siblings.len / capture.raw_queries.len;
        const siblings = all_siblings[metadata.query * height ..][0..height];
        var leaf: Digest = undefined;
        for (&leaf, row[@intFromEnum(W.fri_anchor.MainSource.digest_0)..][0..8]) |*word, scalar| word.* = scalar.toU32();
        try appendPath(allocator, &paths, try W.merkle_root.friTreeId(value.lane, metadata.layer), row[@intFromEnum(W.fri_anchor.MainSource.position)].toU32(), leaf, siblings, capture.fri_roots[metadata.layer]);
        leaf_count += 1;
    }
    if (leaf_count != capture.raw_queries.len * capture.fri_roots.len) return error.DetachedPcsLeafCoverageMismatch;
    value.view_value.merkle_path = try paths.toOwnedSlice(allocator);
    // Full provider inputs AND expected outputs come from the typed relation
    // plan's actual 32-word requests. No parallel sponge or tuple description.
    var calls: std.ArrayList(ProviderCall) = .empty;
    var outputs: std.ArrayList([16]u32) = .empty;
    try appendProvider(allocator, &calls, &outputs, &prepared.trace_merkle_relation, value.view_value.trace_merkle);
    try appendProvider(allocator, &calls, &outputs, &prepared.fri_leaf_relation, value.view_value.fri_leaf);
    try appendProvider(allocator, &calls, &outputs, &prepared.fri_node_relation, value.view_value.fri_node);
    var path_definition = try air.merkle_path.build(allocator);
    defer path_definition.deinit();
    const path_plan = try air.merkle_path_relation.authenticate(&path_definition);
    try appendProvider(allocator, &calls, &outputs, &path_plan, value.view_value.merkle_path);
    value.view_value.provider = try calls.toOwnedSlice(allocator);
    value.view_value.provider_outputs = try outputs.toOwnedSlice(allocator);
}

fn appendProvider(allocator: std.mem.Allocator, calls: *std.ArrayList(ProviderCall), outputs: *std.ArrayList([16]u32), plan: anytype, rows: anytype) !void {
    for (rows) |row| for (plan.preparedEntries(row)) |entry| {
        if (entry.domain != .poseidon2_io or entry.numerator.isZero()) continue;
        if (entry.role != .request or entry.arity != 32 or !entry.numerator.eql(QM31.one().neg())) return error.DetachedPcsProviderMultiplicityMismatch;
        var call: ProviderCall = .{ .input = undefined, .io = true };
        var output: [16]u32 = undefined;
        for (&call.input, entry.values[0..16]) |*word, scalar| word.* = (try scalar.tryIntoM31()).toU32();
        for (&output, entry.values[16..32]) |*word, scalar| word.* = (try scalar.tryIntoM31()).toU32();
        try calls.append(allocator, call);
        try outputs.append(allocator, output);
    };
}

pub fn testKeyTemplateParity(allocator: std.mem.Allocator, child: anytype) !void {
    var template = try @import("detached_pcs_key_template_v1.zig").TemplateV1.init(allocator, child.key());
    defer template.deinit();
    var captured = try child.preparePcs(allocator);
    defer captured.deinit();
    try template.geometry.validateCaptured(&captured);
    try std.testing.expectEqualSlices(u8, &captured.circuit.profile_digest, &template.circuit.profile_digest);
    try std.testing.expectEqualSlices(u8, &captured.circuit.graph_digest, &template.circuit.graph_digest);
    try std.testing.expectEqualSlices(u8, &captured.circuit.identity_digest, &template.circuit.identity_digest);
    const captured_pcs = captured.pcs_circuit.view();
    const key_pcs = template.pcs_circuit.view();
    try std.testing.expectEqualSlices(u8, &captured_pcs.profile_digest, &key_pcs.profile_digest);
    try std.testing.expectEqualSlices(u8, &captured_pcs.graph_digest, &key_pcs.graph_digest);
    try std.testing.expectEqualSlices(u8, &captured_pcs.identity_digest, &key_pcs.identity_digest);
    try std.testing.expectEqualSlices(u32, captured.trace_tree_heights, template.trace_tree_heights);
    try std.testing.expectEqualDeep(captured.fri_layer_profiles, template.fri_layer_profiles);
    var inactive_fri = try template.evaluateInactive();
    defer inactive_fri.deinit();
    try inactive_fri.validateAgainst(&template.circuit);
    var inactive_pcs = try template.evaluatePcsInactive();
    defer inactive_pcs.deinit();
    try inactive_pcs.validateAgainst(&template.pcs_circuit);

    var vm_plan = try key_shape.planFromKey(allocator, child.key(), .vm);
    defer vm_plan.deinit();
    var recursion_plan = try key_shape.planFromKey(allocator, child.key(), .recursion);
    defer recursion_plan.deinit();
    var from_key = try source.FriRowsAuthority.initInactiveFromTemplate(allocator, &vm_plan, &recursion_plan, &template);
    defer from_key.deinit();
    const Child = struct { capture: *const recursion.captured_fri.Owned };
    var from_capture = try source.FriRowsAuthority.init(allocator, &vm_plan, &recursion_plan, [2]Child{ .{ .capture = &captured }, .{ .capture = &captured } });
    defer from_capture.deinit();
    try std.testing.expectEqualDeep(from_capture.log_sizes, from_key.log_sizes);
    inline for (.{
        "query_bits_preprocessing",
        "query_mapping_preprocessing",
        "merkle_root_preprocessing",
        "trace_merkle_preprocessing",
        "pcs_preprocessing",
        "fri_leaf_preprocessing",
        "fri_node_preprocessing",
        "fri_anchor_preprocessing",
        "control_preprocessing",
        "input_preprocessing",
    }) |field| {
        const actual = @field(from_capture, field);
        const rebuilt = @field(from_key, field);
        try std.testing.expectEqual(actual.log_size, rebuilt.log_size);
        try std.testing.expectEqualDeep(actual.rows, rebuilt.rows);
    }
    // Exercise the committed-row mapping and zero padding used by the parent,
    // with no child proof values on the key-derived side.
    const left = try OwnedV1.init(allocator, child, 1);
    defer left.deinit();
    const right = try OwnedV1.init(allocator, child, 2);
    defer right.deinit();
    const left_view = left.view();
    const right_view = right.view();
    for ([_]u32{ 1, 2 }, [_][]const air.control_witness.Row{ left_view.control, right_view.control }) |lane, captured_control| {
        const fixed_control = try controlRowsFromKey(allocator, child.key(), lane);
        defer allocator.free(fixed_control);
        try std.testing.expectEqualDeep(captured_control, fixed_control);
    }
    inline for (.{
        .{ "query_bits", "query_bits_preprocessing" },
        .{ "query_mapping", "query_mapping_preprocessing" },
        .{ "merkle_root", "merkle_root_preprocessing" },
        .{ "trace_merkle", "trace_merkle_preprocessing" },
        .{ "pcs_deep", "pcs_preprocessing" },
        .{ "fri_leaf", "fri_leaf_preprocessing" },
        .{ "fri_node", "fri_node_preprocessing" },
        .{ "fri_anchor", "fri_anchor_preprocessing" },
        .{ "fri_control", "control_preprocessing" },
        .{ "fri_input", "input_preprocessing" },
    }) |fields| try testFixedPairProjection(
        allocator,
        @field(A, fields[0]),
        @field(from_key, fields[1]).rows,
        @field(from_key, fields[1]).rows,
        @field(left_view, fields[0]),
        @field(right_view, fields[0]),
    );
}

pub fn testKeyTemplatePairParity(allocator: std.mem.Allocator, left_child: anytype, right_child: anytype) !void {
    var left_template = try @import("detached_pcs_key_template_v1.zig").TemplateV1.init(allocator, left_child.key());
    defer left_template.deinit();
    var right_template = try @import("detached_pcs_key_template_v1.zig").TemplateV1.init(allocator, right_child.key());
    defer right_template.deinit();
    var left_vm = try key_shape.planFromKey(allocator, left_child.key(), .vm);
    defer left_vm.deinit();
    var left_recursion = try key_shape.planFromKey(allocator, left_child.key(), .recursion);
    defer left_recursion.deinit();
    var right_vm = try key_shape.planFromKey(allocator, right_child.key(), .vm);
    defer right_vm.deinit();
    var right_recursion = try key_shape.planFromKey(allocator, right_child.key(), .recursion);
    defer right_recursion.deinit();
    var left_fixed = try source.FriRowsAuthority.initInactiveFromTemplate(allocator, &left_vm, &left_recursion, &left_template);
    defer left_fixed.deinit();
    var right_fixed = try source.FriRowsAuthority.initInactiveFromTemplate(allocator, &right_vm, &right_recursion, &right_template);
    defer right_fixed.deinit();
    const left = try OwnedV1.init(allocator, left_child, 1);
    defer left.deinit();
    const right = try OwnedV1.init(allocator, right_child, 2);
    defer right.deinit();
    const left_view = left.view();
    const right_view = right.view();
    inline for (.{
        .{ "query_bits", "query_bits_preprocessing" },
        .{ "query_mapping", "query_mapping_preprocessing" },
        .{ "merkle_root", "merkle_root_preprocessing" },
        .{ "trace_merkle", "trace_merkle_preprocessing" },
        .{ "pcs_deep", "pcs_preprocessing" },
        .{ "fri_leaf", "fri_leaf_preprocessing" },
        .{ "fri_node", "fri_node_preprocessing" },
        .{ "fri_anchor", "fri_anchor_preprocessing" },
        .{ "fri_control", "control_preprocessing" },
        .{ "fri_input", "input_preprocessing" },
    }) |fields| try testFixedPairProjection(
        allocator,
        @field(A, fields[0]),
        @field(left_fixed, fields[1]).rows,
        @field(right_fixed, fields[1]).rows,
        @field(left_view, fields[0]),
        @field(right_view, fields[0]),
    );
}

fn testFixedPairProjection(allocator: std.mem.Allocator, comptime Air: type, left_metadata: anytype, right_metadata: anytype, left: []const Row(Air), right: []const Row(Air)) !void {
    const count = try std.math.add(usize, left.len, right.len);
    if (count > @as(usize, 1) << 28) return error.DetachedPcsFixedDestinationMismatch;
    const log_size = @max(4, std.math.log2_int_ceil(usize, @max(count, 1)));
    const height: usize = @as(usize, 1) << @intCast(log_size);
    const combined = try allocator.alloc(Row(Air), count);
    defer allocator.free(combined);
    @memcpy(combined[0..left.len], left);
    @memcpy(combined[left.len..], right);
    const expected = try allocator.alloc([]M31, Air.PREPROCESSED_COLUMN_COUNT);
    defer allocator.free(expected);
    const rebuilt = try allocator.alloc([]M31, Air.PREPROCESSED_COLUMN_COUNT);
    defer allocator.free(rebuilt);
    for (expected, rebuilt) |*a, *b| {
        a.* = try allocator.alloc(M31, height);
        b.* = try allocator.alloc(M31, height);
    }
    defer for (expected, rebuilt) |a, b| {
        allocator.free(a);
        allocator.free(b);
    };
    for (expected) |column| @memset(column, M31.zero());
    device_interaction.writeColumns(Air, combined, log_size, 0, expected);
    try @import("detached_pcs_fixed_projection_v1.zig").fillPair(Air, left_metadata, right_metadata, log_size, rebuilt);
    for (expected, rebuilt) |a, b| try std.testing.expectEqualSlices(M31, a, b);
}

pub fn testFromVerifiedChild(allocator: std.mem.Allocator, child: anytype) !void {
    try testKeyTemplateParity(allocator, child);
    for ([_]u32{ 1, 2 }) |lane| {
        const owner = try OwnedV1.initWithLaneSelection(allocator, child, lane, false, null);
        defer owner.deinit();
        const view_value = owner.view();
        if (lane == 1) {
            // Detached PCS lanes currently have no cross-circuit graph exports.
            // This census is test-only and does not change production lowering.
            const census = try @import("air/detached_pcs_opening_plan.zig").census(allocator, &owner.storage().capture.pcs_circuit, &.{});
            const json = try std.json.Stringify.valueAlloc(allocator, census, .{});
            defer allocator.free(json);
            std.debug.print("DETACHED_PCS_OPENING_CENSUS {s}\n", .{json});
        }
        const selected = try OwnedV1.init(allocator, child, lane);
        defer selected.deinit();
        try std.testing.expectEqualDeep(view_value, selected.view());
        inline for (.{ "query_bits", "query_mapping", "merkle_root", "trace_merkle", "pcs_deep", "fri_leaf", "fri_node", "fri_anchor", "fri_control", "fri_input" }) |name|
            try checkLogicalRows(allocator, @field(A, name), @field(view_value, name));
        try checkLogicalRows(allocator, air.merkle_path, view_value.merkle_path);
        for (view_value.provider, view_value.provider_outputs) |call, output| {
            var state: [16]M31 = undefined;
            for (&state, call.input) |*word, native| word.* = M31.fromCanonical(native);
            @import("../air/memory_commitment/poseidon2.zig").permute(&state);
            for (state, output) |actual, expected| try std.testing.expectEqual(expected, actual.toU32());
        }
        const raw_draws = try allocator.alloc(M31, child.captureView().raw_queries.len);
        defer allocator.free(raw_draws);
        try child.writeRawQueryDraws(raw_draws);
        var high_bits_seen = false;
        for (view_value.query_bits, raw_draws, child.captureView().raw_queries) |row, draw, reduced| {
            try std.testing.expectEqual(draw, row[1]);
            if (draw.toU32() != reduced) {
                high_bits_seen = true;
                var masked_row = row;
                masked_row[1] = M31.fromCanonical(@intCast(reduced));
                try std.testing.expectError(error.DetachedPcsConstraintMismatch, checkLogicalRows(allocator, A.query_bits, &.{masked_row}));
            }
        }
        try std.testing.expect(high_bits_seen);
        var changed = view_value.query_bits[0];
        changed[3] = M31.fromCanonical(2); // A genuine query-bit row, invalid boolean.
        try std.testing.expectError(error.DetachedPcsConstraintMismatch, checkLogicalRows(allocator, A.query_bits, &.{changed}));
        try std.testing.expectEqual(view_value.pcs_deep.len, view_value.pcs_metadata.len);
        try std.testing.expectEqual(view_value.fri_input.len, view_value.fri_metadata.len);
        std.debug.print("SEGMENT_V2_DETACHED_PCS_CHECKS lane={d} query_rows={d} trace_rows={d} fri_leaf_rows={d} path_rows={d} provider_calls={d} pcs_inputs={d} fri_inputs={d} parent_proof_verified=false\n", .{ lane, view_value.query_bits.len, view_value.trace_merkle.len, view_value.fri_leaf.len, view_value.merkle_path.len, view_value.provider.len, view_value.pcs_metadata.len, view_value.fri_metadata.len });
    }
}

pub fn checkLogicalRows(allocator: std.mem.Allocator, comptime Air: type, rows: []const Row(Air)) !void {
    var definition = try Air.build(allocator);
    defer definition.deinit();
    const direct = air.direct_constraint_program;
    const compiled = try direct.authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
    var scratch: [direct.MAX_NODES]M31 = undefined;
    var roots: [Air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    for (rows) |row| {
        try compiled.evaluateBaseInto(&row, &scratch, &roots);
        for (roots) |root| if (!root.isZero()) return error.DetachedPcsConstraintMismatch;
    }
}
