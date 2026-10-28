//! Proof-free detached-parent Tree 0 writer. Child keys select every fixed
//! source row; the parent manifest supplies the proposed physical placement,
//! which must subsequently be checked against an independently derived seal.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const child_mod = @import("detached_child_capture_v1.zig");
const cohort = @import("detached_parent_prepared_v1.zig");
const base = @import("detached_parent_fixed_base_v1.zig");
const arithmetic = @import("detached_parent_arithmetic_v1.zig");
const pcs_template = @import("detached_pcs_key_template_v1.zig");
const pcs_shape = @import("detached_pcs_key_shape_v1.zig");
const pcs_source = @import("binary_fri_outer_source.zig");
const pcs_projection = @import("detached_pcs_fixed_projection_v1.zig");
const fixed_tables = @import("detached_parent_fixed_tables_v1.zig");
const device = @import("air/framework_device_interaction.zig");
const framework = @import("air/framework_interaction.zig");
const pcs_airs = struct {
    const query_bits = @import("air/query_bits.zig");
    const query_mapping = @import("air/query_mapping.zig");
    const merkle_root = @import("air/merkle_root.zig");
    const trace_merkle = @import("air/trace_merkle.zig");
    const pcs_deep = @import("air/pcs_deep_input.zig");
    const fri_leaf = @import("air/fri_merkle_leaf.zig");
    const fri_node = @import("air/fri_merkle_node.zig");
    const fri_anchor = @import("air/fri_merkle_anchor.zig");
    const fri_control = @import("air/fri_verifier_control.zig");
    const fri_input = @import("air/fri_verifier_input.zig");
};

pub fn fillFromChildKeys(comptime family: child_mod.Family, allocator: std.mem.Allocator, keys: anytype, mode: @import("span_continuation_v1.zig").Mode, manifest: *const cohort.manifest_mod.Manifest, destination: [][]M31) !void {
    var stage: []const u8 = "preflight";
    var stage_row: usize = 0;
    errdefer if (@import("builtin").is_test) std.debug.print("DETACHED_PARENT_KEY_TREE0_BUILD_ERROR stage={s} row={d}\n", .{ stage, stage_row });
    try preflight(manifest, destination);
    for (destination) |column| @memset(column, M31.zero());
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    stage = "base";
    var fixed_base = try base.OwnedV1.init(family, a, keys);
    defer fixed_base.deinit();
    try fixed_base.fillPreprocessedInto(manifest, destination);

    stage = "graph";
    var graph = try arithmetic.fixedFromChildKeys(family, a, keys, mode);
    defer graph.deinit();
    stage_row = 11;
    try fillLogical(11, graph.input_rows, manifest, destination);
    stage_row = 12;
    try fillLogical(12, graph.poseidon_rows, manifest, destination);
    stage_row = 13;
    try fillLogical(13, graph.wire_rows, manifest, destination);
    const arithmetic_rows = [_]usize{ 14, 30, 31, 32 };
    inline for (arithmetic_rows, 0..) |row, slot| {
        stage_row = row;
        try fillCompact(row, graph.arithmetic.fixed[slot], manifest, destination);
    }

    stage = "pcs";
    var templates: [2]pcs_template.TemplateV1 = undefined;
    var vm_plans: [2]@import("air/verifier_schedule.zig").Plan = undefined;
    var recursion_plans: [2]@import("air/verifier_schedule.zig").Plan = undefined;
    var fixed_pcs: [2]pcs_source.FriRowsAuthority = undefined;
    inline for (0..2) |index| {
        templates[index] = try pcs_template.TemplateV1.init(a, keys[index]);
        vm_plans[index] = try pcs_shape.planFromKey(a, keys[index], .vm);
        recursion_plans[index] = try pcs_shape.planFromKey(a, keys[index], .recursion);
        fixed_pcs[index] = try pcs_source.FriRowsAuthority.initInactiveFromTemplate(a, &vm_plans[index], &recursion_plans[index], &templates[index]);
    }
    inline for (.{
        .{ 20, pcs_airs.query_bits, "query_bits_preprocessing" },
        .{ 21, pcs_airs.query_mapping, "query_mapping_preprocessing" },
        .{ 22, pcs_airs.merkle_root, "merkle_root_preprocessing" },
        .{ 23, pcs_airs.trace_merkle, "trace_merkle_preprocessing" },
        .{ 24, pcs_airs.pcs_deep, "pcs_preprocessing" },
        .{ 25, pcs_airs.fri_leaf, "fri_leaf_preprocessing" },
        .{ 26, pcs_airs.fri_node, "fri_node_preprocessing" },
        .{ 27, pcs_airs.fri_anchor, "fri_anchor_preprocessing" },
        .{ 28, pcs_airs.fri_control, "control_preprocessing" },
        .{ 29, pcs_airs.fri_input, "input_preprocessing" },
    }) |entry| {
        const row: usize = entry[0];
        stage_row = row;
        const Air = entry[1];
        const placement = try placementFor(row, Air, manifest, destination);
        try pcs_projection.fillPair(Air, @field(fixed_pcs[0], entry[2]).rows, @field(fixed_pcs[1], entry[2]).rows, placement.geometry.log_size, destination[placement.preprocessed_offset..][0..Air.PREPROCESSED_COLUMN_COUNT]);
    }
    stage = "tables";
    stage_row = 34;
    try fixed_tables.fillFromManifest(manifest, destination);
}

fn preflight(manifest: *const cohort.manifest_mod.Manifest, destination: [][]M31) !void {
    try manifest.validate();
    if (destination.len != manifest.total_preprocessed_columns) return error.DetachedParentDestinationMismatch;
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const placement = manifest.placements[row] orelse return error.DetachedParentManifestMismatch;
        if (placement.geometry.log_size >= @bitSizeOf(usize) or placement.preprocessed_offset + placement.geometry.preprocessed_columns > destination.len)
            return error.DetachedParentDestinationMismatch;
        const height: usize = @as(usize, 1) << @intCast(placement.geometry.log_size);
        for (destination[placement.preprocessed_offset..][0..placement.geometry.preprocessed_columns]) |column|
            if (column.len != height) return error.DetachedParentDestinationMismatch;
    }
}

fn placementFor(comptime row: usize, comptime Air: type, manifest: *const cohort.manifest_mod.Manifest, destination: [][]M31) !cohort.manifest_mod.Placement {
    const placement = manifest.placements[row] orelse return error.DetachedParentManifestMismatch;
    if (placement.geometry.preprocessed_columns != Air.PREPROCESSED_COLUMN_COUNT or
        placement.geometry.log_size >= @bitSizeOf(usize) or
        placement.preprocessed_offset + Air.PREPROCESSED_COLUMN_COUNT > destination.len)
        return error.DetachedParentDestinationMismatch;
    return placement;
}

fn fillLogical(comptime row: usize, rows: []const [cohort.LOGICAL_ROWS[cohort.logicalIndex(row)].Air.LOGICAL_INPUT_COUNT]M31, manifest: *const cohort.manifest_mod.Manifest, destination: [][]M31) !void {
    const Air = cohort.LOGICAL_ROWS[cohort.logicalIndex(row)].Air;
    const placement = try placementFor(row, Air, manifest, destination);
    const height = @as(usize, 1) << @intCast(placement.geometry.log_size);
    if (rows.len > height) return error.DetachedParentDestinationMismatch;
    device.writeColumns(Air, rows, placement.geometry.log_size, 0, destination[placement.preprocessed_offset..][0..Air.PREPROCESSED_COLUMN_COUNT]);
}

fn fillCompact(comptime row: usize, rows: anytype, manifest: *const cohort.manifest_mod.Manifest, destination: [][]M31) !void {
    const Air = cohort.LOGICAL_ROWS[cohort.logicalIndex(row)].Air;
    const placement = try placementFor(row, Air, manifest, destination);
    const height = @as(usize, 1) << @intCast(placement.geometry.log_size);
    // Compact fixed rows also carry proof-kind parameters after the committed
    // preprocessed fields. Those parameters are bound by the component, not
    // written into Tree 0.
    if (rows.len > height or Air.PREPROCESSED_COLUMN_COUNT > Air.LOGICAL_INPUT_COUNT - Air.PHYSICAL_MAIN_COLUMN_COUNT)
        return error.DetachedParentDestinationMismatch;
    const columns = destination[placement.preprocessed_offset..][0..Air.PREPROCESSED_COLUMN_COUNT];
    for (rows, 0..) |fixed, logical| {
        const committed = framework.committedRow(logical, placement.geometry.log_size);
        for (columns, fixed[0..Air.PREPROCESSED_COLUMN_COUNT]) |column, word| column[committed] = word;
    }
}

const Columns = struct {
    allocator: std.mem.Allocator,
    columns: [][]M31,
    pub fn init(allocator: std.mem.Allocator, manifest: *const cohort.manifest_mod.Manifest) !Columns {
        const columns = try allocator.alloc([]M31, manifest.total_preprocessed_columns);
        errdefer allocator.free(columns);
        var filled: usize = 0;
        errdefer for (columns[0..filled]) |column| allocator.free(column);
        for (manifest.roster_rows[0..manifest.roster_count]) |row| {
            const placement = manifest.placements[row].?;
            for (columns[placement.preprocessed_offset..][0..placement.geometry.preprocessed_columns]) |*column| {
                column.* = try allocator.alloc(M31, @as(usize, 1) << @intCast(placement.geometry.log_size));
                filled += 1;
            }
        }
        if (filled != columns.len) return error.DetachedParentManifestMismatch;
        return .{ .allocator = allocator, .columns = columns };
    }
    pub fn deinit(self: *Columns) void {
        for (self.columns) |column| self.allocator.free(column);
        self.allocator.free(self.columns);
        self.* = undefined;
    }
};

pub fn testAgainstVerifiedChildren(comptime family: child_mod.Family, allocator: std.mem.Allocator, children: [2]*const child_mod.OwnedFor(family), mode: @import("span_continuation_v1.zig").Mode) !void {
    return testAgainstVerifiedChildrenWithRoot(family, allocator, children, mode, null);
}

pub fn testAgainstVerifiedChildrenWithRoot(comptime family: child_mod.Family, allocator: std.mem.Allocator, children: [2]*const child_mod.OwnedFor(family), mode: @import("span_continuation_v1.zig").Mode, comptime root_check: anytype) !void {
    const preparation = @import("detached_parent_preparation_v1.zig");
    var prepared = if (family == .segment) blk: {
        const left = try @import("detached_boundary_key_shape_v1.zig").SegmentShapeV1.init(allocator, children[0].key());
        const right = try @import("detached_boundary_key_shape_v1.zig").SegmentShapeV1.init(allocator, children[1].key());
        break :blk try preparation.prepareWithMode(allocator, children, .{
            .sections = .{ .{ .counts = children[0].key().retained_section_counts }, .{ .counts = children[1].key().retained_section_counts } },
            .memory = .{ left.memory, right.memory },
        }, mode, null);
    } else try preparation.prepareParents(allocator, children, mode, null);
    defer prepared.deinit();
    const manifest = prepared.cohort.manifest();
    var expected = try Columns.init(allocator, manifest);
    defer expected.deinit();
    try prepared.cohort.fillPreprocessedInto(expected.columns);
    var rebuilt = try Columns.init(allocator, manifest);
    defer rebuilt.deinit();
    try fillFromChildKeys(family, allocator, .{ children[0].key(), children[1].key() }, mode, manifest, rebuilt.columns);
    for (expected.columns, rebuilt.columns, 0..) |left, right, index| {
        if (left.len != right.len) return error.DetachedParentFixedRecipeMismatch;
        for (left, right, 0..) |actual, candidate, cell| if (!actual.eql(candidate)) {
            std.debug.print("DETACHED_PARENT_KEY_TREE0_COLUMN_MISMATCH column={d} cell={d} expected={d} actual={d}\n", .{ index, cell, actual.toU32(), candidate.toU32() });
            return error.DetachedParentFixedRecipeMismatch;
        };
    }
    if (comptime @TypeOf(root_check) != @TypeOf(null)) {
        const parameters = prepared.cohort.parameters();
        try root_check(family, allocator, .{ children[0].key(), children[1].key() }, mode, manifest, &parameters, expected.columns);
    }
}
