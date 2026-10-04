const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Air = @import("../scalar_wire_source.zig");
const Binding = @import("../universal_relation_binding.zig").Binding(Air);
const framework = @import("../framework_interaction.zig");
const Runtime = framework.Runtime(Binding.Runtime);
const columns = @import("../blake3_row_columns.zig");
test "BLAKE3 memory update proves compact fixed projection matches every parent cohort" {
    const a = std.testing.allocator;
    const storage = @import("../blake3_parent_row_storage.zig");
    const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
    inline for (storage.Airs) |Cohort| {
        var rows: [3]Cohort.Row = undefined;
        var fixed: [3]storage.FixedRow(Cohort) = undefined;
        for (&rows, &fixed, 0..) |*row, *metadata, i| {
            for (row, 0..) |*value, j| value.* = M.fromU64(1 + i * 1000 + j);
            metadata.* = storage.compactFixed(Cohort, row.*);
            try std.testing.expectEqualSlices(M, row[Cohort.PHYSICAL_MAIN_COLUMN_COUNT..], metadata);
        }
        var control: std.ArrayList(Column) = .empty;
        defer {
            for (control.items) |column| a.free(column.values);
            control.deinit(a);
        }
        var compact: std.ArrayList(Column) = .empty;
        defer {
            for (compact.items) |column| a.free(column.values);
            compact.deinit(a);
        }
        try columns.project(Cohort, a, &rows, 2, 0, &control);
        try columns.projectFixed(Cohort, a, &fixed, 2, &compact);
        try std.testing.expectEqual(control.items.len, compact.items.len);
        for (control.items, compact.items) |expected, actual| {
            try std.testing.expectEqual(expected.log_size, actual.log_size);
            try std.testing.expectEqualSlices(M, expected.values, actual.values);
        }
        try std.testing.expect(@sizeOf(storage.FixedRow(Cohort)) < @sizeOf(Cohort.Row));
    }
}
test "BLAKE3 memory update proves compact parent metadata preserves interactions and rejects invalid storage" {
    const a = std.testing.allocator;
    var definition = try Air.build(a);
    defer definition.deinit();
    const plan = try Binding.authenticate(&definition);
    const rows = [_]Air.Row{
        try Air.logicalRow(101, 0, 1, M.fromCanonical(17)),
        try Air.logicalRow(101, 1, 2, M.fromCanonical(23)),
        try Air.logicalRow(102, 0, 1, M.fromCanonical(42)),
    };
    const width = Air.LOGICAL_INPUT_COUNT - Air.PHYSICAL_MAIN_COLUMN_COUNT;
    var metadata: [rows.len * width]M = undefined;
    for (rows, 0..) |row, i| @memcpy(metadata[i * width ..][0..width], row[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
    var projected: std.ArrayList(@import("stwo_prover_engine").pcs.ColumnEvaluation) = .empty;
    defer {
        for (projected.items) |column| a.free(column.values);
        projected.deinit(a);
    }
    try columns.project(Air, a, &rows, 3, 1, &projected);
    const view = try columns.compactColumnView(Air, projected.items, &metadata, rows.len, 3);
    for (rows, 0..) |row, i| try std.testing.expectEqualDeep(row, view.read(i, 3));
    const relations = @import("../universal_challenges.zig").UniversalRelations.dummy();
    var oracle = try Runtime.generatePreparedWithPadding(a, &plan, &rows, 3, &relations, @splat(M.zero()));
    defer oracle.deinit(a);
    var actual = try Runtime.generatePreparedFromColumns(a, &plan, view, 3, &relations, @splat(M.zero()));
    defer actual.deinit(a);
    try std.testing.expect(oracle.claimed_sum.eql(actual.claimed_sum));
    for (oracle.columns, actual.columns) |left, right| try std.testing.expectEqualSlices(M, left, right);
    var bad = view;
    bad.metadata = &rows;
    try std.testing.expectError(error.InvalidTraceShape, bad.validate(3));
    bad = view;
    bad.compact_metadata = metadata[0 .. metadata.len - 1];
    try std.testing.expectError(error.InvalidTraceShape, bad.validate(3));
    bad = view;
    bad.main_count = Air.LOGICAL_INPUT_COUNT + 1;
    try std.testing.expectError(error.InvalidTraceShape, bad.validate(3));
    var workspace = try Runtime.Workspace.init(a, 3);
    defer workspace.deinit();
    try std.testing.checkAllAllocationFailures(a, checkOwned, .{ &workspace, &plan, view, &relations, &oracle });
    // Exercise windows across live rows, the live/padding boundary, and padding.
    for (0..4) |tile_log| {
        var tiled_workspace = try Runtime.Workspace.init(a, @intCast(tile_log));
        defer tiled_workspace.deinit();
        try std.testing.checkAllAllocationFailures(a, checkOwnedTiled, .{ &tiled_workspace, &plan, view, &relations, &oracle });
    }
    const alias = std.mem.bytesAsSlice(M, std.mem.sliceAsBytes(workspace.scratch));
    bad = view;
    bad.compact_metadata = alias[0..metadata.len];
    try std.testing.expectError(error.DestinationAlias, Runtime.generatePreparedFromColumnsWithWorkspace(a, &workspace, &plan, bad, 3, &relations, @splat(M.zero())));
}

fn checkOwned(a: std.mem.Allocator, workspace: *Runtime.Workspace, plan: *const Binding.Plan, view: Runtime.ColumnRows, relations: *const @import("../universal_challenges.zig").UniversalRelations, oracle: *const Runtime.Interaction) !void {
    var owned = try Runtime.generatePreparedOwnedColumnsWithWorkspace(a, workspace, plan, view, 3, relations, @splat(M.zero()));
    defer owned.deinit(a);
    try std.testing.expect(oracle.claimed_sum.eql(owned.claimed_sum));
    for (oracle.columns, owned.columns) |left, right| try std.testing.expectEqualSlices(M, left, right);
}

fn checkOwnedTiled(a: std.mem.Allocator, workspace: *Runtime.Workspace, plan: *const Binding.Plan, view: Runtime.ColumnRows, relations: *const @import("../universal_challenges.zig").UniversalRelations, oracle: *const Runtime.Interaction) !void {
    var owned = try Runtime.generatePreparedOwnedColumnsTiledWithWorkspace(a, workspace, plan, view, 3, relations, @splat(M.zero()));
    defer owned.deinit(a);
    try std.testing.expect(oracle.claimed_sum.eql(owned.claimed_sum));
    for (oracle.columns, owned.columns) |left, right| try std.testing.expectEqualSlices(M, left, right);
}

test "BLAKE3 memory update proves table projection cleans up allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, tableProjectionFailureCase, .{});
}
fn tableProjectionFailureCase(a: std.mem.Allocator) !void {
    var projected: std.ArrayList(@import("stwo_prover_engine").pcs.ColumnEvaluation) = .empty;
    defer {
        for (projected.items) |column| a.free(column.values);
        projected.deinit(a);
    }
    try columns.tablePreprocessed(a, .range_check_8_8, &projected);
}
