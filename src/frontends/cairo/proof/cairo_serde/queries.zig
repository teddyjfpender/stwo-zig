//! The queried values as the Cairo verifier reads them: per tree, every
//! column's value at query 0, then at query 1, and so on, the trace and
//! interaction trees stably sorted by column log size first
//! (`interop_felt_json.sortAndTransposeQueriedValues`, shared with the
//! circuit-recursion root proof).

const std = @import("std");
const composition = @import("../../witness/composition_bundle.zig");
const layout = @import("../layout.zig");
const felt_json = @import("interop_felt_json");
const M31 = @import("stwo_core").fields.m31.M31;

pub fn write(
    allocator: std.mem.Allocator,
    felts: anytype,
    queried_values: anytype,
    bundle: *const composition.Bundle,
) !void {
    const trees = queried_values.items;
    if (trees.len != felt_json.n_queried_trees) return error.InvalidQueriedValueTrees;
    for (trees) |columns| if (columns.len == 0) return error.InvalidQueriedValueShape;

    var views: [felt_json.n_queried_trees][]const []const M31 = undefined;
    for (&views, trees) |*view, columns| view.* = columns;
    const trace_logs = try layout.treeLogs(allocator, bundle, 1, trees[1].len);
    defer allocator.free(trace_logs);
    const interaction_logs = try layout.treeLogs(allocator, bundle, 2, trees[2].len);
    defer allocator.free(interaction_logs);
    const transposed = felt_json.sortAndTransposeQueriedValues(allocator, views, trace_logs, interaction_logs) catch |err| switch (err) {
        error.ShapeMismatch => return error.InvalidQueriedValueShape,
        error.OutOfMemory => return error.OutOfMemory,
    };
    defer for (transposed) |tree| allocator.free(tree);

    try felts.felt(transposed.len);
    for (transposed) |tree| try felts.m31Vec(tree);
}
