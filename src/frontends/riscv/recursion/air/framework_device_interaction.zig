//! Backend-neutral ingress for typed interaction generation. Admitted plans
//! own equations; this adapter only projects logical rows into committed columns.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const binding = @import("universal_relation_binding.zig");
const exporter = @import("framework_polynomial_export_v1.zig");
const framework = @import("framework_interaction.zig");

/// Destination is already zeroed so absent logical rows retain AIR padding.
pub fn writeColumns(comptime Air: type, rows: []const [Air.LOGICAL_INPUT_COUNT]M31, log: u32, tree: usize, destination: []const []M31) void {
    const start = if (tree == 0) Air.PHYSICAL_MAIN_COLUMN_COUNT else 0;
    for (rows, 0..) |row, logical| {
        const physical = framework.committedRow(logical, log);
        for (destination, 0..) |column, index| column[physical] = row[start + index];
    }
}

pub fn generateInto(
    comptime Backend: type,
    comptime Air: type,
    allocator: std.mem.Allocator,
    direct: *const @import("direct_constraint_program.zig").Program,
    plan: *const binding.Binding(Air).Plan,
    rows: []const [Air.LOGICAL_INPUT_COUNT]M31,
    profile: []const M31,
    log: u32,
    relations: *const @import("universal_challenges.zig").UniversalRelations,
    destination: []const []M31,
) !QM31 {
    if (log == 0 or log > 24) return error.InvalidTraceShape;
    const size = @as(usize, 1) << @intCast(log);
    const counts = [_]usize{ Air.PREPROCESSED_COLUMN_COUNT, Air.PHYSICAL_MAIN_COLUMN_COUNT, Air.INTERACTION_COLUMN_COUNT };
    if (rows.len > size or profile.len != Air.LOGICAL_INPUT_COUNT - counts[0] - counts[1])
        return error.InvalidTraceShape;
    var program = try exporter.exportLocalPrepared(Air, allocator, direct, plan);
    defer program.deinit();
    const parameters = try exporter.exportRelationParameters(allocator, plan, relations);
    defer allocator.free(parameters);
    const storage = try allocator.alloc(M31, try std.math.mul(usize, counts[0] + counts[1], size));
    defer allocator.free(storage);
    @memset(storage, M31.zero());
    var columns: [Air.PREPROCESSED_COLUMN_COUNT + Air.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&columns, 0..) |*column, index| column.* = storage[index * size ..][0..size];
    const sources = [2][]const []M31{ columns[0..counts[0]], columns[counts[0]..] };
    for (sources, 0..) |tree, index| writeColumns(Air, rows, log, index, tree);
    return Backend.generateFrameworkInteractionInto(allocator, &program, &counts, sources, .{
        .trace_log_size = log,
        .profile_values = profile,
        .relation_values = parameters,
    }, destination) catch |err| switch (err) {
        error.FrameworkInteractionZeroDenominator => error.ZeroDenominator,
        else => err,
    };
}
