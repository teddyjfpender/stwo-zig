//! Verifier-owned, value-independent Merkle-root preprocessing for V6 row 22.
//!
//! Only the admitted query/tree/FRI cardinalities enter this writer. Root
//! digests, transcript words and a child proof are never accepted as inputs.
//! This is a candidate fixed writer, not a proof-key admission gate.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const profile_mod = @import("air/segment_leaf_wrapper_template_v6.zig");
const source = @import("air/merkle_root_witness.zig");
const air = @import("air/merkle_root.zig");
const framework = @import("air/framework_interaction.zig");
const Geometry = @import("air/universal_manifest_contract.zig").Geometry;

pub const ROW: u8 = 22;
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const COLUMN_COUNT = air.PREPROCESSED_COLUMN_COUNT;

/// V6's core profile owns counts and tree heights, but does not own the
/// complete shape of these sibling schedules. None may be copied from a child
/// proof into a fixed key. Keep their missing admission contracts explicit.
pub const MissingShape = enum {
    tree_column_log_sizes_and_recursion_control_plan, // 23 trace Merkle
    pcs_deep_circuit_graph_and_input_use_counts, // 24 PCS DEEP
    fri_layer_tree_heights_and_opening_layout, // 25--26 leaf and node
    fri_anchor_control_and_path_schedule, // 27 anchor
    recursion_verifier_control_plan, // 28 control
    fri_circuit_graph_and_input_use_counts, // 29 FRI input
    arithmetic_circuit_graph_and_input_use_counts, // 30--32
};

pub fn missingShape(row: u8) !?MissingShape {
    return switch (row) {
        22 => null,
        23 => .tree_column_log_sizes_and_recursion_control_plan,
        24 => .pcs_deep_circuit_graph_and_input_use_counts,
        25, 26 => .fri_layer_tree_heights_and_opening_layout,
        27 => .fri_anchor_control_and_path_schedule,
        28 => .recursion_verifier_control_plan,
        29 => .fri_circuit_graph_and_input_use_counts,
        30, 31, 32 => .arithmetic_circuit_graph_and_input_use_counts,
        else => error.NotCoreFixedRowV6,
    };
}

pub fn requireShapeAdmitted(row: u8) !void {
    if (try missingShape(row) != null) return error.CoreFixedShapeNotAdmittedV6;
}

pub const Shape = struct {
    vm_queries: u32,
    vm_trees: u32,
    vm_fri_layers: u32,
    recursion_queries: u32,
    recursion_trees: u32,
    recursion_fri_layers: u32,
    log_size: u32,

    pub fn init(profile: *const profile_mod.CoreProfileV6) !Shape {
        _ = try profile.reference();
        const vm = try lane(profile.vm);
        const recursion = try lane(profile.recursion);
        _ = try source.Reference.seal(vm, recursion);
        const count = try rowCount(vm, recursion);
        const log_size: u32 = @max(source.MIN_LOG_SIZE, @as(u32, @intCast(std.math.log2_int_ceil(usize, count))));
        if (log_size > source.MAX_LOG_SIZE) return error.MerkleRootFixedGeometryMismatchV6;
        return .{
            .vm_queries = vm.query_count,
            .vm_trees = vm.trace_tree_count,
            .vm_fri_layers = vm.fri_layer_count,
            .recursion_queries = recursion.query_count,
            .recursion_trees = recursion.trace_tree_count,
            .recursion_fri_layers = recursion.fri_layer_count,
            .log_size = log_size,
        };
    }

    pub fn validateAgainst(self: Shape, profile: *const profile_mod.CoreProfileV6) !void {
        const rebuilt = try init(profile);
        if (!std.meta.eql(self, rebuilt)) return error.MerkleRootShapeMismatchV6;
    }

    pub fn validate(self: Shape) !void {
        const root_reference = try self.reference();
        const count = try rowCount(root_reference.vm, root_reference.recursion);
        const canonical_log: u32 = @max(source.MIN_LOG_SIZE, @as(u32, @intCast(std.math.log2_int_ceil(usize, count))));
        if (self.log_size != canonical_log or self.log_size > source.MAX_LOG_SIZE)
            return error.MerkleRootFixedGeometryMismatchV6;
    }

    pub fn validatePlacement(self: Shape, geometry: Geometry) !void {
        try self.validate();
        if (geometry.roster_row != ROW or geometry.log_size != self.log_size or
            geometry.preprocessed_columns != COLUMN_COUNT or
            !std.meta.eql(geometry.semantic_digest, air.SEMANTIC_DIGEST))
            return error.MerkleRootFixedGeometryMismatchV6;
    }

    /// Physical Tree0 order, with every padded cell zero. Destination must be
    /// fresh so a stale proof cannot contribute hidden fixed values.
    pub fn writePhysical(self: Shape, columns: [][]M31) !void {
        try self.validate();
        if (columns.len != COLUMN_COUNT or self.log_size >= @bitSizeOf(usize))
            return error.MerkleRootFixedGeometryMismatchV6;
        const capacity = @as(usize, 1) << @intCast(self.log_size);
        for (columns) |column| {
            if (column.len != capacity) return error.MerkleRootFixedGeometryMismatchV6;
            for (column) |word| if (!word.isZero()) return error.MerkleRootDestinationNotFreshV6;
        }
        var logical: usize = 0;
        try self.writeLane(columns, &logical, self.vm_queries, self.vm_trees, self.vm_fri_layers, 0, 1, 0);
        try self.writeLane(columns, &logical, self.recursion_queries, self.recursion_trees, self.recursion_fri_layers, 1, 0, 1);
        try self.writeLane(columns, &logical, self.recursion_queries, self.recursion_trees, self.recursion_fri_layers, 2, 0, 1);
        std.debug.assert(logical <= capacity);
    }

    fn writeLane(self: Shape, columns: [][]M31, logical: *usize, queries: u32, trees: u32, fri_layers: u32, verifier: u32, segment: u32, binary: u32) !void {
        for (0..trees) |item| {
            self.put(columns, logical.*, .{
                .row_mask = 1,
                .segment_mask = segment,
                .binary_mask = binary,
                .verifier_id = verifier,
                .source = .trace,
                .item = @intCast(item),
                .tree_id = try source.traceTreeId(verifier, item),
                .path_count = queries,
            });
            logical.* += 1;
        }
        for (0..fri_layers) |item| {
            self.put(columns, logical.*, .{
                .row_mask = 1,
                .segment_mask = segment,
                .binary_mask = binary,
                .verifier_id = verifier,
                .source = .fri,
                .item = @intCast(item),
                .tree_id = try source.friTreeId(verifier, item),
                .path_count = queries,
            });
            logical.* += 1;
        }
    }

    fn put(self: Shape, columns: [][]M31, logical: usize, row: source.Row) void {
        const physical = framework.committedRow(logical, self.log_size);
        for (row.values(), columns) |value, column| column[physical] = value;
    }

    fn reference(self: Shape) !source.Reference {
        return source.Reference.seal(
            .{ .query_count = self.vm_queries, .trace_tree_count = self.vm_trees, .fri_layer_count = self.vm_fri_layers },
            .{ .query_count = self.recursion_queries, .trace_tree_count = self.recursion_trees, .fri_layer_count = self.recursion_fri_layers },
        );
    }
};

fn rowCount(vm: source.LaneProfile, recursion: source.LaneProfile) !usize {
    const vm_rows = try std.math.add(usize, vm.trace_tree_count, vm.fri_layer_count);
    const recursion_rows = try std.math.add(usize, recursion.trace_tree_count, recursion.fri_layer_count);
    return std.math.add(usize, vm_rows, try std.math.mul(usize, recursion_rows, 2));
}

fn lane(profile: profile_mod.CoreLaneV6) !source.LaneProfile {
    if (profile.tree_count == 0 or profile.fri_count == 0)
        return error.InvalidMerkleRootProfileV6;
    return .{
        .query_count = profile.query_count,
        .trace_tree_count = profile.tree_count,
        .fri_layer_count = profile.fri_count,
    };
}

test "row 22 fixed Tree0 columns match native source for distinct root values" {
    const allocator = std.testing.allocator;
    const fixture = @import("segment_profile.zig");
    const vm = fixture.circuitProfile();
    const profile = try profile_mod.CoreProfileV6.init(
        .{ .query_count = vm.query_count, .lifting_log_size = vm.lifting_log_size, .tree_heights = &fixture.TREE_HEIGHTS, .fri_fold_widths = vm.fold_widths },
        .{ .query_count = vm.query_count, .lifting_log_size = vm.lifting_log_size, .tree_heights = &fixture.TREE_HEIGHTS, .fri_fold_widths = vm.fold_widths },
    );
    const shape = try Shape.init(&profile);
    var geometry = Geometry{
        .roster_row = ROW,
        .log_size = shape.log_size,
        .preprocessed_columns = COLUMN_COUNT,
        .main_columns = air.PHYSICAL_MAIN_COLUMN_COUNT,
        .interaction_columns = air.INTERACTION_COLUMN_COUNT,
        .direct_constraints = air.DIRECT_CONSTRAINT_COUNT,
        .interaction_batches = air.INTERACTION_BATCH_COUNT,
        .protocol_constraint_degree = air.MAXIMUM_CONSTRAINT_DEGREE,
        .profiled_constraint_degree = air.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = air.SEMANTIC_DIGEST,
    };
    try shape.validatePlacement(geometry);
    geometry.log_size += 1;
    try std.testing.expectError(error.MerkleRootFixedGeometryMismatchV6, shape.validatePlacement(geometry));
    const reference = try shape.reference();
    var native = try source.Preprocessed.init(allocator, reference);
    defer native.deinit();
    try std.testing.expectEqual(native.log_size, shape.log_size);
    const capacity = @as(usize, 1) << @intCast(shape.log_size);
    var columns: [COLUMN_COUNT][]M31 = undefined;
    for (&columns) |*column| column.* = try allocator.alloc(M31, capacity);
    defer for (columns) |column| allocator.free(column);
    for (&columns) |*column| @memset(column.*, M31.zero());
    try shape.writePhysical(&columns);

    // The same native fixed schedule is used with both root-value sets. The
    // test compares every physical column and padded cell, not only active rows.
    for ([_]u32{ 7, 71 }) |root_seed| {
        const witness = source.RootWitness{ .segment_leaf = .{
            .trace = try rootDigests(allocator, profile.vm.tree_count, root_seed),
            .fri = try rootDigests(allocator, profile.vm.fri_count, root_seed + 100),
        } };
        defer allocator.free(witness.segment_leaf.trace);
        defer allocator.free(witness.segment_leaf.fri);
        for (native.rows) |row| _ = try source.mainRow(row, witness);
        for (0..capacity) |logical| {
            const physical = framework.committedRow(logical, shape.log_size);
            const expected = if (logical < native.rows.len) native.rows[logical].values() else [_]M31{M31.zero()} ** COLUMN_COUNT;
            for (columns, expected) |column, word| try std.testing.expect(column[physical].eql(word));
        }
        try std.testing.expectEqual(@as(usize, profile.vm.tree_count), witness.segment_leaf.trace.len);
    }
    try std.testing.expectError(error.MerkleRootDestinationNotFreshV6, shape.writePhysical(&columns));
    var changed = shape;
    changed.recursion_queries += 1;
    try std.testing.expectError(error.MerkleRootShapeMismatchV6, changed.validateAgainst(&profile));
    changed = shape;
    changed.log_size += 1;
    try std.testing.expectError(error.MerkleRootShapeMismatchV6, changed.validateAgainst(&profile));
    try std.testing.expectError(error.MerkleRootFixedGeometryMismatchV6, changed.writePhysical(&columns));
    for (23..33) |row| {
        try std.testing.expect((try missingShape(@intCast(row))) != null);
        try std.testing.expectError(error.CoreFixedShapeNotAdmittedV6, requireShapeAdmitted(@intCast(row)));
    }
}

fn rootDigests(allocator: std.mem.Allocator, count: usize, seed: u32) ![]source.Digest {
    const result = try allocator.alloc(source.Digest, count);
    for (result, 0..) |*root, index| {
        for (root, 0..) |*word, part| word.* = seed + @as(u32, @intCast(index * 8 + part));
    }
    return result;
}
