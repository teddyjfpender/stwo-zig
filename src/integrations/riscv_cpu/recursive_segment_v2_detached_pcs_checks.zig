//! Typed PCS/FRI checks for one detached child. The owner retains copied capture
//! and program geometry; selected logical rows borrow only this immutable owner.
//! This is a preparation inventory, not a recursive proof or closure receipt.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const recursion = frontend.recursion;
const air = recursion.air;
const child_mod = @import("recursive_segment_v2_detached_child_transcript.zig");
const schedule = air.verifier_schedule;
const fixed = recursion.fixed_profile;
const source = recursion.binary_fri_outer_source;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const ProviderCall = recursion.segment_transcript_outer_source_v2.ProviderCall;
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
        return initWithLaneSelection(allocator, child, lane, false);
    }
    fn initWithLaneSelection(allocator: std.mem.Allocator, child: anytype, lane: u32, comptime selected_lane_only: bool) !*OwnedV1 {
        if (lane != 1 and lane != 2) return error.InvalidDetachedPcsLane;
        const value = try allocator.create(Storage);
        errdefer allocator.destroy(value);
        value.allocator = allocator;
        value.arena = std.heap.ArenaAllocator.init(allocator);
        errdefer value.arena.deinit();
        const owned = value.arena.allocator();
        value.lane = lane;
        var timer = if (std.process.hasEnvVarConstant("STWO_RISCV_RECURSIVE_PARENT_PROFILE")) @as(?std.time.Timer, try std.time.Timer.start()) else null;
        value.capture = try child.preparePcs(owned);
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
    if (capture.trace_tree_heights.len != fixed.TREE_COUNT) return error.DetachedPcsTreeCount;
    var heights: [fixed.TREE_COUNT]u32 = undefined;
    @memcpy(&heights, capture.trace_tree_heights);
    const identity = try key.identity();
    const channel = recursion.poseidon2_channel;
    const shape = schedule.ScheduleShape{
        .protocol_id = channel.hashBytes("detached-segment-pcs-checks/v1", 0x44504331),
        .shape_id = channel.hashBytes(&identity, 0x44504731),
        .interaction_pow_bits = capture.interaction_pow_bits,
        .pcs_pow_bits = capture.pcs_pow_bits,
        .query_count = capture.circuit.query_count,
        .table_count = key.manifest.roster_count,
        .claimed_sum_count = @intCast(child.claims().values.len),
        .sampled_value_count = capture.sampled_value_count,
        .tree_heights = heights,
        .fri = try fixed.FriSchedule.init(capture.circuit.lifting_log_size - key.pcs_config.fri_config.log_blowup_factor, key.pcs_config.fri_config),
    };
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
    var trace_merkle = try Columns(W.trace_merkle).init(scratch, prepared.trace_merkle_preprocessing.log_size);
    if (selected_lane_only)
        try prepared.trace_merkle_executor.generateMainForLaneInto(&prepared.trace_merkle_preprocessing, prepared.trace_merkle_reference, &trace_merkle.columns, trace, value.lane)
    else
        try prepared.trace_merkle_executor.generateMainInto(&prepared.trace_merkle_preprocessing, prepared.trace_merkle_reference, &trace_merkle.columns, trace);
    value.view_value.trace_merkle = try selectRows(A.trace_merkle, allocator, value.lane, prepared.trace_merkle_preprocessing.rows, trace_merkle.columns, try W.trace_merkle.logicalRow(prepared.trace_merkle_reference, &prepared.trace_merkle_preprocessing, 0, trace));
    var pcs_deep = try Columns(W.pcs_deep).init(scratch, prepared.pcs_preprocessing.log_size);
    try prepared.pcs_executor.generateMainInto(&prepared.pcs_preprocessing, prepared.pcs_reference, &pcs_deep.columns, prepared.pcs_inputs, .binary_node);
    value.view_value.pcs_deep = try selectRows(A.pcs_deep, allocator, value.lane, prepared.pcs_preprocessing.rows, pcs_deep.columns, try W.pcs_deep.logicalRow(prepared.pcs_reference, &prepared.pcs_preprocessing, 0, prepared.pcs_inputs, .binary_node));
    var fri_leaf = try Columns(W.fri_leaf).init(scratch, prepared.fri_leaf_preprocessing.log_size);
    if (selected_lane_only)
        try prepared.fri_leaf_executor.generateMainForLaneInto(&prepared.fri_leaf_preprocessing, prepared.fri_reference, &fri_leaf.columns, fri, value.lane)
    else
        try prepared.fri_leaf_executor.generateMainInto(&prepared.fri_leaf_preprocessing, prepared.fri_reference, &fri_leaf.columns, fri);
    value.view_value.fri_leaf = try selectRows(A.fri_leaf, allocator, value.lane, prepared.fri_leaf_preprocessing.rows, fri_leaf.columns, try W.fri_leaf.logicalRow(prepared.fri_reference, &prepared.fri_leaf_preprocessing, 0, fri));
    var fri_node = try Columns(W.fri_node).init(scratch, prepared.fri_node_preprocessing.log_size);
    if (selected_lane_only)
        try prepared.fri_node_executor.generateMainForLaneInto(&prepared.fri_node_preprocessing, prepared.fri_reference, &fri_node.columns, fri, value.lane)
    else
        try prepared.fri_node_executor.generateMainInto(&prepared.fri_node_preprocessing, prepared.fri_reference, &fri_node.columns, fri);
    value.view_value.fri_node = try selectRows(A.fri_node, allocator, value.lane, prepared.fri_node_preprocessing.rows, fri_node.columns, W.fri_node.logicalInputs(@splat(M31.zero()), @splat(M31.zero()), .binary_node));
    var fri_anchor = try Columns(W.fri_anchor).init(scratch, prepared.fri_anchor_preprocessing.log_size);
    if (selected_lane_only)
        try prepared.fri_anchor_executor.generateMainForLaneInto(&prepared.fri_anchor_preprocessing, prepared.fri_reference, &value.vm_plan, &value.recursion_plan, &fri_anchor.columns, fri, value.lane)
    else
        try prepared.fri_anchor_executor.generateMainInto(&prepared.fri_anchor_preprocessing, prepared.fri_reference, &value.vm_plan, &value.recursion_plan, &fri_anchor.columns, fri);
    value.view_value.fri_anchor = try selectRows(A.fri_anchor, allocator, value.lane, prepared.fri_anchor_preprocessing.rows, fri_anchor.columns, try W.fri_anchor.logicalRow(prepared.fri_reference, &prepared.fri_anchor_preprocessing, &value.vm_plan, &value.recursion_plan, 0, fri));
    var fri_control = try Columns(W.fri_control).init(scratch, prepared.control_preprocessing.log_size);
    try prepared.control_executor.generateMainInto(&prepared.control_preprocessing, prepared.control_reference, &fri_control.columns, query);
    value.view_value.fri_control = try selectRows(A.fri_control, allocator, value.lane, prepared.control_preprocessing.rows, fri_control.columns, try W.fri_control.logicalRow(prepared.control_reference, &prepared.control_preprocessing, 0, query));
    var fri_input = try Columns(W.fri_input).init(scratch, prepared.input_preprocessing.log_size);
    try prepared.input_executor.generateMainInto(&prepared.input_preprocessing, prepared.input_reference, &fri_input.columns, evaluations, .binary_node);
    value.view_value.fri_input = try selectRows(A.fri_input, allocator, value.lane, prepared.input_preprocessing.rows, fri_input.columns, try W.fri_input.logicalRow(prepared.input_reference, &prepared.input_preprocessing, 0, evaluations, .binary_node));
    value.view_value.pcs_metadata = try selectedMetadata(W.pcs_deep.Row, allocator, value.lane, prepared.pcs_preprocessing.rows);
    value.view_value.fri_metadata = try selectedMetadata(W.fri_input.Row, allocator, value.lane, prepared.input_preprocessing.rows);
    var control: std.ArrayList(air.control_witness.Row) = .empty;
    for (value.recursion_plan.steps, 0..) |step, sequence| switch (step) {
        .verify_trace_merkle_path, .evaluate_deep_quotient, .verify_fri_merkle_path, .fold_fri, .verify_last_layer => {
            const encoded = step.encode();
            try control.append(allocator, .{ .segment_mask = 0, .binary_mask = 1, .verifier_id = value.lane, .sequence = @intCast(sequence), .tag = encoded.tag, .args = encoded.args, .terminal_mask = 0 });
        },
        else => {},
    };
    value.view_value.control = try control.toOwnedSlice(allocator);
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

pub fn testFromVerifiedChild(allocator: std.mem.Allocator, child: anytype) !void {
    for ([_]u32{ 1, 2 }) |lane| {
        const owner = try OwnedV1.init(allocator, child, lane);
        defer owner.deinit();
        const view_value = owner.view();
        const selected = try OwnedV1.initWithLaneSelection(allocator, child, lane, true);
        defer selected.deinit();
        try std.testing.expectEqualDeep(view_value, selected.view());
        inline for (.{ "query_bits", "query_mapping", "merkle_root", "trace_merkle", "pcs_deep", "fri_leaf", "fri_node", "fri_anchor", "fri_control", "fri_input" }) |name|
            try checkLogicalRows(allocator, @field(A, name), @field(view_value, name));
        try checkLogicalRows(allocator, air.merkle_path, view_value.merkle_path);
        for (view_value.provider, view_value.provider_outputs) |call, output| {
            var state: [16]M31 = undefined;
            for (&state, call.input) |*word, native| word.* = M31.fromCanonical(native);
            frontend.air.memory_commitment.poseidon2.permute(&state);
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
