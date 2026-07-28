const std = @import("std");
const arena_plan = @import("stwo_backend_contracts").arena_plan;
const composition_bundle = @import("stwo_cairo_frontend").witness.composition_bundle;
const geometry_mod = @import("stwo_cairo_metal_integration").runtime_decommit_geometry;

test "runtime decommit geometry derives Fib and exact SN2 shapes from admitted artifacts" {
    try runCase(.{
        .source_log = 21,
        .columns = .{ 17, 31, 1, 8 },
        .trace_leaf_logs = .{ 26, 21, 21, 21 },
        .fri_leaf_logs = &.{ 19, 16, 13, 10, 7, 4, 1 },
    });
    try runCase(.{
        .source_log = 24,
        .columns = .{ 161, 3449, 2268, 8 },
        .trace_leaf_logs = .{ 26, 24, 24, 24 },
        .fri_leaf_logs = &.{ 22, 19, 16, 13, 10, 7, 4, 1 },
    });
}

const Case = struct {
    source_log: u32,
    columns: [4]u32,
    trace_leaf_logs: [4]u32,
    fri_leaf_logs: []const u32,
};

fn runCase(case: Case) !void {
    const allocator = std.testing.allocator;
    var encoded = std.ArrayList(u8).empty;
    defer encoded.deinit(allocator);
    var bindings = std.ArrayList(arena_plan.Binding).empty;
    defer bindings.deinit(allocator);
    try encoded.append(allocator, '[');
    var word_cursor: u64 = 0;

    try appendEntry(allocator, &encoded, &bindings, &word_cursor, "QuotientTile", 0, (@as(u64, 1) << @intCast(case.source_log)) * 4);
    inline for (.{ "PreprocessedCoefficients", "BaseCoefficients", "InteractionCoefficients", "CompositionCoefficients" }, 0..) |name, tree| {
        for (0..case.columns[tree]) |column| {
            try appendEntry(allocator, &encoded, &bindings, &word_cursor, name, @intCast(column), 1);
        }
    }
    for (case.trace_leaf_logs, 0..) |leaf_log, tree| {
        const tree_ordinal = @as(u32, @intCast(tree)) << 16;
        try appendEntry(allocator, &encoded, &bindings, &word_cursor, "DecommitTraceRetainedPointers", tree_ordinal, (leaf_log + 1) * 2);
        try appendEntry(allocator, &encoded, &bindings, &word_cursor, "DecommitTraceSparseOffsets", tree_ordinal, 4);
    }
    for (case.fri_leaf_logs, 0..) |leaf_log, round| {
        const tree_ordinal = @as(u32, @intCast(4 + round)) << 16;
        try appendEntry(allocator, &encoded, &bindings, &word_cursor, "DecommitFriRetainedPointers", tree_ordinal, (leaf_log + 1) * 2);
        try appendEntry(allocator, &encoded, &bindings, &word_cursor, "FriFoldingChallenge", @intCast(round), 4);
        if (round != 0)
            try appendEntry(allocator, &encoded, &bindings, &word_cursor, "FriRetainedEvaluation", @intCast(round), 4);
    }
    try appendEntry(allocator, &encoded, &bindings, &word_cursor, "FriFinalCoefficients", 0, 8);
    try encoded.append(allocator, ']');

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, encoded.items, .{});
    defer parsed.deinit();
    var empty_slots: [0]arena_plan.Slot = .{};
    var empty_actions: [0]arena_plan.Action = .{};
    var empty_offsets: [0]usize = .{};
    const plan = arena_plan.Plan{
        .allocator = allocator,
        .bindings = bindings.items,
        .slots = &empty_slots,
        .actions = &empty_actions,
        .action_offsets = &empty_offsets,
        .total_bytes = word_cursor * 4,
        .peak_live_bytes = word_cursor * 4,
        .plan_hash = 1,
    };

    var spans = [_]composition_bundle.TraceSpan{
        .{ .tree = 0, .start = 0, .end = 0 },
        .{ .tree = 1, .start = 0, .end = case.columns[1] },
        .{ .tree = 2, .start = 0, .end = case.columns[2] },
    };
    var preprocessed = [_]u32{case.columns[0] - 1};
    var denominators = [_]u32{1};
    var ext_sources: [0]composition_bundle.ExtSource = .{};
    var parts: [0]composition_bundle.Part = .{};
    var components = [_]composition_bundle.Component{.{
        .label = @constCast("test"),
        .instance = 0,
        .trace_log_size = case.source_log,
        .evaluation_log_size = case.source_log,
        .n_constraints = 1,
        .random_coefficient_offset = 0,
        .trace_spans = &spans,
        .preprocessed_indices = &preprocessed,
        .denominator_inverses = &denominators,
        .ext_sources = &ext_sources,
        .parts = &parts,
    }};
    const composition = composition_bundle.Bundle{
        .allocator = allocator,
        .max_kernel_instructions = 1,
        .total_constraints = 1,
        .max_evaluation_log_size = case.source_log,
        .plan_hash = 1,
        .components = &components,
    };

    var owned = try geometry_mod.OwnedProofDecommitGeometry.init(
        allocator,
        parsed.value.array.items,
        plan,
        composition,
    );
    defer owned.deinit();
    const geometry = owned.geometry();
    try std.testing.expectEqualSlices(u32, &case.columns, &.{
        geometry.trace_trees[0].column_count,
        geometry.trace_trees[1].column_count,
        geometry.trace_trees[2].column_count,
        geometry.trace_trees[3].column_count,
    });
    try std.testing.expectEqual(case.fri_leaf_logs.len, geometry.fri_trees.len);
    for (geometry.fri_trees, case.fri_leaf_logs) |tree, leaf_log|
        try std.testing.expectEqual(leaf_log, tree.leaf_log);

    var drifted = composition;
    drifted.max_evaluation_log_size -= 1;
    try std.testing.expectError(
        geometry_mod.Error.InvalidCompositionGeometry,
        geometry_mod.OwnedProofDecommitGeometry.init(
            allocator,
            parsed.value.array.items,
            plan,
            drifted,
        ),
    );
}

fn appendEntry(
    allocator: std.mem.Allocator,
    encoded: *std.ArrayList(u8),
    bindings: *std.ArrayList(arena_plan.Binding),
    word_cursor: *u64,
    purpose: []const u8,
    ordinal: u32,
    words: u64,
) !void {
    const logical_id = std.math.cast(u32, bindings.items.len + 1) orelse return error.InvalidCardinality;
    try encoded.writer(allocator).print(
        "{s}{{\"purpose\":\"{s}\",\"ordinal\":{},\"id\":{}}}",
        .{ if (bindings.items.len == 0) "" else ",", purpose, ordinal, logical_id },
    );
    try bindings.append(allocator, .{
        .logical_id = logical_id,
        .slot = logical_id,
        .offset_bytes = word_cursor.* * 4,
        .size_bytes = words * 4,
        .materialization = .resident,
        .occupied = [_]u64{0} ** (arena_plan.max_ticks / 64),
    });
    word_cursor.* += words;
}
