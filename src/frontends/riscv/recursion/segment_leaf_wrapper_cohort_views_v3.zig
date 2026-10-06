//! Zero-copy column views for rebuilding the V2 native verifier inside a
//! direct recursive leaf. Only obsolete row 34 receives scratch storage.
//!
//! This is physical tree assembly, not a 39-row proof prefix. The V2 owners
//! regenerate their rows under the direct wrapper's relation challenges;
//! the direct cohort writes its enlarged row 34 and appended rows separately.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const manifest_mod = @import("air/segment_outer_adapter_manifest_v2.zig");

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const BASE_ROWS: usize = manifest_mod.COMPONENT_COUNT;
pub const REPLACED_ROW: usize = 34;
pub const Placement = manifest_mod.Placement;

pub const Views = struct {
    allocator: std.mem.Allocator,
    tree: usize,
    columns: [][]M31,
    old_provider_scratch: []M31,

    /// Both manifests must already be independently validated. This checks
    /// that every reused row has identical typed geometry and maps its V2
    /// source offset to the direct cohort's destination offset. No prior V2
    /// proof columns are copied or admitted here.
    pub fn init(
        allocator: std.mem.Allocator,
        source: *const manifest_mod.Manifest,
        target_placements: []const ?Placement,
        target_columns: [][]M31,
        tree: usize,
    ) !Views {
        try source.validate();
        return initMapped(allocator, &source.placements, target_placements, target_columns, tree);
    }

    /// Versioned direct roster entry point. The plan owns the target offsets
    /// and must validate before any borrowed destination is exposed to V2.
    pub fn initForPlan(
        allocator: std.mem.Allocator,
        source: *const manifest_mod.Manifest,
        plan: anytype,
        target_columns: [][]M31,
        tree: usize,
    ) !Views {
        try plan.validate();
        const geometry = if (comptime @hasField(@TypeOf(plan.*), "geometry")) &plan.geometry else plan;
        return init(allocator, source, &geometry.placements, target_columns, tree);
    }

    pub fn deinit(self: *Views) void {
        self.allocator.free(self.old_provider_scratch);
        self.allocator.free(self.columns);
        self.* = undefined;
    }

    pub fn fillPreprocessedFromV2(self: *Views, cohort: anytype) !void {
        if (self.tree != manifest_mod.PREPROCESSED_TREE_INDEX)
            return error.WrongV3Tree;
        try cohort.fillPreprocessedInto(cohort.manifest(), self.columns);
    }

    pub fn fillMainFromV2(self: *Views, cohort: anytype) !void {
        if (self.tree != manifest_mod.MAIN_TREE_INDEX)
            return error.WrongV3Tree;
        try cohort.fillMainInto(cohort.manifest(), self.columns);
    }
};

fn initMapped(
    allocator: std.mem.Allocator,
    source: []const ?Placement,
    target: []const ?Placement,
    destination: [][]M31,
    tree: usize,
) !Views {
    if (source.len < BASE_ROWS or target.len < BASE_ROWS or tree >= manifest_mod.TREE_COUNT)
        return error.V3BaseViewShapeMismatch;
    var source_total: usize = 0;
    for (source[0..BASE_ROWS]) |maybe_item| {
        const item = maybe_item orelse return error.V3BaseViewShapeMismatch;
        const end = try std.math.add(usize, offset(item, tree), count(item, tree));
        source_total = @max(source_total, end);
    }
    const columns = try allocator.alloc([]M31, source_total);
    errdefer allocator.free(columns);
    const old_provider = source[REPLACED_ROW].?;
    const scratch_count = count(old_provider, tree);
    const scratch_rows = @as(usize, 1) << @intCast(old_provider.geometry.log_size);
    const scratch_size = try std.math.mul(usize, scratch_count, scratch_rows);
    const scratch = try allocator.alloc(M31, scratch_size);
    errdefer allocator.free(scratch);
    @memset(scratch, M31.zero());
    for (source[0..BASE_ROWS], 0..) |maybe_old, row| {
        const old = maybe_old orelse return error.V3BaseViewShapeMismatch;
        const newer = target[row] orelse return error.V3BaseViewShapeMismatch;
        if (newer.geometry.roster_row != row) return error.V3BaseViewGeometryMismatch;
        const old_start = offset(old, tree);
        const n = count(old, tree);
        if (old_start + n > columns.len) return error.V3BaseViewShapeMismatch;
        if (row == REPLACED_ROW) {
            for (0..n) |i| columns[old_start + i] = scratch[i * scratch_rows ..][0..scratch_rows];
            continue;
        }
        if (!std.meta.eql(old.geometry, newer.geometry))
            return error.V3BaseViewGeometryMismatch;
        const new_start = offset(newer, tree);
        if (new_start + n > destination.len) return error.V3BaseViewShapeMismatch;
        const rows = @as(usize, 1) << @intCast(old.geometry.log_size);
        for (0..n) |i| {
            const target_column = destination[new_start + i];
            if (target_column.len != rows) return error.V3BaseViewShapeMismatch;
            columns[old_start + i] = target_column;
        }
    }
    return .{
        .allocator = allocator,
        .tree = tree,
        .columns = columns,
        .old_provider_scratch = scratch,
    };
}

fn offset(item: Placement, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => item.preprocessed_offset,
        manifest_mod.MAIN_TREE_INDEX => item.main_offset,
        manifest_mod.INTERACTION_TREE_INDEX => item.interaction_offset,
        else => unreachable,
    };
}

fn count(item: Placement, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => item.geometry.preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => item.geometry.main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => item.geometry.interaction_columns,
        else => unreachable,
    };
}

test "direct leaf views reuse V2 rows without copying old row34" {
    const allocator = std.testing.allocator;
    var source: [BASE_ROWS]?Placement = undefined;
    var target: [BASE_ROWS]?Placement = undefined;
    var source_at: u32 = 0;
    var target_at: u32 = 0;
    for (0..BASE_ROWS) |row| {
        const old_cols: u16 = if (row == REPLACED_ROW) 2 else 1;
        const new_cols: u16 = if (row == REPLACED_ROW) 3 else 1;
        const old_log: u32 = if (row == REPLACED_ROW) 5 else 4;
        const new_log: u32 = if (row == REPLACED_ROW) 6 else 4;
        const old = fakePlacement(@intCast(row), source_at, old_cols, old_log);
        source[row] = old;
        target[row] = fakePlacement(@intCast(row), target_at, new_cols, new_log);
        source_at += old_cols;
        target_at += new_cols;
    }
    const MockPlan = struct {
        placements: [BASE_ROWS]?Placement,
        fn validate(_: *const @This()) !void {}
    };
    const mock_plan = MockPlan{ .placements = target };
    var invalid_source: manifest_mod.Manifest = undefined;
    invalid_source.format_version = 0;
    try std.testing.expectError(
        error.IncompleteRoster,
        Views.initForPlan(allocator, &invalid_source, &mock_plan, &.{}, manifest_mod.MAIN_TREE_INDEX),
    );
    const destination = try allocator.alloc([]M31, target_at);
    defer allocator.free(destination);
    for (destination, 0..) |*column, i| {
        column.* = try allocator.alloc(M31, if (i == REPLACED_ROW or i == REPLACED_ROW + 1 or i == REPLACED_ROW + 2) 64 else 16);
        @memset(column.*, M31.zero());
    }
    defer for (destination) |column| allocator.free(column);
    var views = try initMapped(allocator, &source, &target, destination, manifest_mod.MAIN_TREE_INDEX);
    defer views.deinit();
    try std.testing.expectEqual(@as(usize, source_at), views.columns.len);
    const MockOwner = struct {
        fn manifest(_: *@This()) u8 {
            return 39;
        }
        fn fillPreprocessedInto(_: *@This(), _: u8, _: [][]M31) !void {}
        fn fillMainInto(_: *@This(), manifest_id: u8, columns: [][]M31) !void {
            if (manifest_id != 39) return error.BadMockManifest;
            columns[10][0] = M31.fromCanonical(17);
            columns[REPLACED_ROW][0] = M31.fromCanonical(23);
        }
    };
    var mock = MockOwner{};
    try views.fillMainFromV2(&mock);
    try std.testing.expectEqual(@as(u32, 17), destination[10][0].toU32());
    try std.testing.expectEqual(@as(u32, 23), views.old_provider_scratch[0].toU32());
    try std.testing.expect(destination[REPLACED_ROW][0].isZero());
    try std.testing.expectError(error.WrongV3Tree, views.fillPreprocessedFromV2(&mock));

    const pp_destination = try allocator.alloc([]M31, BASE_ROWS);
    defer allocator.free(pp_destination);
    for (pp_destination, 0..) |*column, row| {
        column.* = try allocator.alloc(M31, if (row == REPLACED_ROW) 64 else 16);
        @memset(column.*, M31.zero());
    }
    defer for (pp_destination) |column| allocator.free(column);
    var pp_views = try initMapped(allocator, &source, &target, pp_destination, manifest_mod.PREPROCESSED_TREE_INDEX);
    defer pp_views.deinit();
    pp_views.columns[10][0] = M31.fromCanonical(31);
    pp_views.columns[REPLACED_ROW][0] = M31.fromCanonical(37);
    try std.testing.expectEqual(@as(u32, 31), pp_destination[10][0].toU32());
    try std.testing.expect(pp_destination[REPLACED_ROW][0].isZero());
    try std.testing.expectEqual(@as(u32, 37), pp_views.old_provider_scratch[0].toU32());
    target[12].?.geometry.log_size += 1;
    try std.testing.expectError(error.V3BaseViewGeometryMismatch, initMapped(allocator, &source, &target, destination, manifest_mod.MAIN_TREE_INDEX));
}

fn fakePlacement(row: u8, main_offset: u32, main_columns: u16, log_size: u32) Placement {
    return .{
        .geometry = .{
            .roster_row = row,
            .log_size = log_size,
            .preprocessed_columns = 1,
            .main_columns = main_columns,
            .interaction_columns = 4,
            .direct_constraints = 1,
            .interaction_batches = 1,
            .protocol_constraint_degree = 2,
            .profiled_constraint_degree = 2,
            .semantic_digest = @splat(0),
        },
        .preprocessed_offset = row,
        .main_offset = main_offset,
        .interaction_offset = @as(u32, row) * 4,
        .constraint_offset = 0,
        .claimed_sum_index = row,
    };
}
