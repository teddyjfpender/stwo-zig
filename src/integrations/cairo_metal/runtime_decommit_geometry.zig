//! Cross-authentication of captured schedules and Cairo evaluator geometry.

const std = @import("std");
const arena_plan = @import("stwo_backend_contracts").arena_plan;
const fri_geometry = @import("stwo_core").fri.geometry;
const composition_bundle = @import("stwo_cairo_frontend").witness.composition_bundle;
const geometry_mod = @import("decommit_geometry.zig");

pub const Error = error{
    InvalidSchedule,
    DuplicateBinding,
    MissingBinding,
    InvalidCardinality,
    InvalidBindingSize,
    InvalidCompositionGeometry,
};

const trace_tree_count = 4;

const OrderedBinding = struct {
    ordinal: u32,
    binding: arena_plan.Binding,
};

/// Owns the slices exposed by `ProofDecommitGeometry`. The evaluator bundle
/// authenticates program-specific trace spans and maximum evaluation degree;
/// the admitted schedule authenticates exact retained-tree storage and FRI
/// ordinals. Neither side is allowed to supply missing values by convention.
pub const OwnedProofDecommitGeometry = struct {
    allocator: std.mem.Allocator,
    trace_trees: []geometry_mod.TraceTreeGeometry,
    fri_trees: []geometry_mod.FriTreeGeometry,

    pub fn init(
        allocator: std.mem.Allocator,
        schedule: []const std.json.Value,
        plan: arena_plan.Plan,
        composition: composition_bundle.Bundle,
    ) !OwnedProofDecommitGeometry {
        if (composition.plan_hash == 0 or composition.max_evaluation_log_size == 0)
            return Error.InvalidCompositionGeometry;
        const source_log = try quotientLog(try one(schedule, plan, "QuotientTile"));
        if (source_log != composition.max_evaluation_log_size)
            return Error.InvalidCompositionGeometry;

        const column_counts = try authenticatedColumnCounts(allocator, schedule, plan, composition);
        const trace_trees = try deriveTraceTrees(allocator, schedule, plan, source_log, column_counts);
        errdefer allocator.free(trace_trees);
        const fri_trees = try deriveFriTrees(allocator, schedule, plan, source_log);
        errdefer allocator.free(fri_trees);

        const result = OwnedProofDecommitGeometry{
            .allocator = allocator,
            .trace_trees = trace_trees,
            .fri_trees = fri_trees,
        };
        try result.geometry().validate();
        return result;
    }

    pub fn deinit(self: *OwnedProofDecommitGeometry) void {
        self.allocator.free(self.trace_trees);
        self.allocator.free(self.fri_trees);
        self.* = undefined;
    }

    pub fn geometry(self: *const OwnedProofDecommitGeometry) geometry_mod.ProofDecommitGeometry {
        return .{ .trace_trees = self.trace_trees, .fri_trees = self.fri_trees };
    }
};

fn authenticatedColumnCounts(
    allocator: std.mem.Allocator,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    composition: composition_bundle.Bundle,
) ![trace_tree_count]u32 {
    const preprocessed = try collect(allocator, schedule, plan, "PreprocessedCoefficients");
    defer allocator.free(preprocessed);
    const base = try collect(allocator, schedule, plan, "BaseCoefficients");
    defer allocator.free(base);
    const interaction = try collect(allocator, schedule, plan, "InteractionCoefficients");
    defer allocator.free(interaction);
    const quotient = try collect(allocator, schedule, plan, "CompositionCoefficients");
    defer allocator.free(quotient);

    try requireContiguousOrdinals(preprocessed);
    try requireContiguousOrdinals(quotient);
    const counts = [trace_tree_count]u32{
        std.math.cast(u32, preprocessed.len) orelse return Error.InvalidCardinality,
        std.math.cast(u32, base.len) orelse return Error.InvalidCardinality,
        std.math.cast(u32, interaction.len) orelse return Error.InvalidCardinality,
        std.math.cast(u32, quotient.len) orelse return Error.InvalidCardinality,
    };
    if (counts[3] == 0) return Error.InvalidCardinality;
    try validateCompositionSpans(composition, counts);
    return counts;
}

fn validateCompositionSpans(
    composition: composition_bundle.Bundle,
    column_counts: [trace_tree_count]u32,
) !void {
    var cursors = [3]u32{ 0, 0, 0 };
    for (composition.components) |component| {
        var seen = [3]bool{ false, false, false };
        for (component.trace_spans) |span| {
            if (span.tree >= seen.len or seen[span.tree]) return Error.InvalidCompositionGeometry;
            seen[span.tree] = true;
            if (span.start != cursors[span.tree] or span.end < span.start or
                span.end > column_counts[span.tree])
                return Error.InvalidCompositionGeometry;
            cursors[span.tree] = span.end;
        }
        if (!seen[0] or !seen[1] or !seen[2]) return Error.InvalidCompositionGeometry;
        for (component.preprocessed_indices) |index| if (index >= column_counts[0])
            return Error.InvalidCompositionGeometry;
    }
    if (cursors[0] != 0 or cursors[1] != column_counts[1] or cursors[2] != column_counts[2])
        return Error.InvalidCompositionGeometry;
}

fn deriveTraceTrees(
    allocator: std.mem.Allocator,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    source_log: u32,
    column_counts: [trace_tree_count]u32,
) ![]geometry_mod.TraceTreeGeometry {
    const retained = try collect(allocator, schedule, plan, "DecommitTraceRetainedPointers");
    defer allocator.free(retained);
    const sparse = try collect(allocator, schedule, plan, "DecommitTraceSparseOffsets");
    defer allocator.free(sparse);
    if (retained.len != trace_tree_count or sparse.len != trace_tree_count)
        return Error.InvalidCardinality;

    const trees = try allocator.alloc(geometry_mod.TraceTreeGeometry, trace_tree_count);
    errdefer allocator.free(trees);
    for (trees, retained, sparse, 0..) |*tree, retained_entry, sparse_entry, tree_index| {
        const expected_ordinal = @as(u32, @intCast(tree_index)) << 16;
        if (retained_entry.ordinal != expected_ordinal or sparse_entry.ordinal != expected_ordinal)
            return Error.InvalidSchedule;
        const leaf_log = try retainedLeafLog(retained_entry.binding);
        if (tree_index != 0 and leaf_log != source_log) return Error.InvalidCompositionGeometry;
        const unretained = try wordCount(sparse_entry.binding);
        tree.* = .{
            .role = @enumFromInt(tree_index),
            .tree_index = @intCast(tree_index),
            .source_log = source_log,
            .tree_log = leaf_log,
            .leaf_log = leaf_log,
            .unretained = unretained,
            .column_count = column_counts[tree_index],
        };
    }
    return trees;
}

fn deriveFriTrees(
    allocator: std.mem.Allocator,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    source_log: u32,
) ![]geometry_mod.FriTreeGeometry {
    const retained = try collect(allocator, schedule, plan, "DecommitFriRetainedPointers");
    defer allocator.free(retained);
    const challenges = try collect(allocator, schedule, plan, "FriFoldingChallenge");
    defer allocator.free(challenges);
    const intermediate = try collect(allocator, schedule, plan, "FriRetainedEvaluation");
    defer allocator.free(intermediate);
    if (retained.len < 2 or challenges.len != retained.len or intermediate.len + 1 != retained.len)
        return Error.InvalidCardinality;
    try requireContiguousOrdinals(challenges);
    for (intermediate, 1..) |entry, round| if (entry.ordinal != round)
        return Error.InvalidSchedule;

    const first_leaf_log = try retainedLeafLog(retained[0].binding);
    if (first_leaf_log >= source_log) return Error.InvalidBindingSize;
    const packed_log = source_log - first_leaf_log;
    const second_leaf_log = try retainedLeafLog(retained[1].binding);
    if (second_leaf_log >= first_leaf_log) return Error.InvalidBindingSize;
    const fold_step = first_leaf_log - second_leaf_log;
    const final_log = try finalCoefficientLog(try one(schedule, plan, "FriFinalCoefficients"));
    const fri = fri_geometry.FriGeometry.initRuntime(source_log, .{
        .round_count = retained.len,
        .fold_step = fold_step,
        .final_log = final_log,
        .packed_log = packed_log,
    }) catch return Error.InvalidBindingSize;

    const trees = try allocator.alloc(geometry_mod.FriTreeGeometry, retained.len);
    errdefer allocator.free(trees);
    for (trees, retained, 0..) |*tree, entry, round| {
        const tree_index = trace_tree_count + round;
        const expected_ordinal = @as(u32, @intCast(tree_index)) << 16;
        if (entry.ordinal != expected_ordinal or try retainedLeafLog(entry.binding) != try fri.leafLog(round))
            return Error.InvalidSchedule;
        tree.* = .{
            .role = @intCast(tree_index),
            .round = @intCast(round),
            .tree_index = @intCast(tree_index),
            .leaf_log = try fri.leafLog(round),
        };
    }
    return trees;
}

fn collect(
    allocator: std.mem.Allocator,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    wanted: []const u8,
) ![]OrderedBinding {
    var result = std.ArrayList(OrderedBinding).empty;
    errdefer result.deinit(allocator);
    for (schedule) |entry| {
        if (!std.mem.eql(u8, try purpose(entry), wanted)) continue;
        const binding = plan.binding(try logicalId(entry)) catch return Error.MissingBinding;
        if (binding.size_bytes == 0 or binding.size_bytes % 4 != 0) return Error.InvalidBindingSize;
        try result.append(allocator, .{ .ordinal = try ordinal(entry), .binding = binding });
    }
    if (result.items.len == 0) return Error.MissingBinding;
    std.mem.sortUnstable(OrderedBinding, result.items, {}, struct {
        fn lessThan(_: void, lhs: OrderedBinding, rhs: OrderedBinding) bool {
            if (lhs.ordinal != rhs.ordinal) return lhs.ordinal < rhs.ordinal;
            return lhs.binding.logical_id < rhs.binding.logical_id;
        }
    }.lessThan);
    for (result.items[1..], result.items[0 .. result.items.len - 1]) |current, previous| {
        if (current.ordinal == previous.ordinal and current.binding.logical_id == previous.binding.logical_id)
            return Error.DuplicateBinding;
    }
    return result.toOwnedSlice(allocator);
}

fn requireContiguousOrdinals(entries: []const OrderedBinding) !void {
    for (entries, 0..) |entry, expected| if (entry.ordinal != expected)
        return Error.InvalidSchedule;
}

fn one(
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    wanted: []const u8,
) !arena_plan.Binding {
    var found: ?arena_plan.Binding = null;
    for (schedule) |entry| {
        if (!std.mem.eql(u8, try purpose(entry), wanted)) continue;
        if (found != null) return Error.DuplicateBinding;
        found = plan.binding(try logicalId(entry)) catch return Error.MissingBinding;
    }
    return found orelse Error.MissingBinding;
}

fn purpose(entry: std.json.Value) ![]const u8 {
    const value = switch (entry) {
        .object => |object| object.get("purpose") orelse return Error.InvalidSchedule,
        else => return Error.InvalidSchedule,
    };
    return switch (value) {
        .string => |text| text,
        else => Error.InvalidSchedule,
    };
}

fn logicalId(entry: std.json.Value) !u32 {
    return integerField(entry, "id");
}

fn ordinal(entry: std.json.Value) !u32 {
    return integerField(entry, "ordinal");
}

fn integerField(entry: std.json.Value, name: []const u8) !u32 {
    const value = switch (entry) {
        .object => |object| object.get(name) orelse return Error.InvalidSchedule,
        else => return Error.InvalidSchedule,
    };
    return switch (value) {
        .integer => |number| if (number >= 0 and number <= std.math.maxInt(u32)) @intCast(number) else Error.InvalidSchedule,
        else => Error.InvalidSchedule,
    };
}

fn wordCount(binding: arena_plan.Binding) !u32 {
    if (binding.size_bytes == 0 or binding.size_bytes % 4 != 0) return Error.InvalidBindingSize;
    return std.math.cast(u32, binding.size_bytes / 4) orelse Error.InvalidBindingSize;
}

fn quotientLog(binding: arena_plan.Binding) !u32 {
    if (binding.size_bytes < 16 or binding.size_bytes % 16 != 0 or
        !std.math.isPowerOfTwo(binding.size_bytes / 16))
        return Error.InvalidBindingSize;
    return std.math.log2_int(u64, binding.size_bytes / 16);
}

fn retainedLeafLog(binding: arena_plan.Binding) !u32 {
    const words = try wordCount(binding);
    if (words < 4 or words % 2 != 0) return Error.InvalidBindingSize;
    return words / 2 - 1;
}

fn finalCoefficientLog(binding: arena_plan.Binding) !u32 {
    if (binding.size_bytes < 16 or binding.size_bytes % 16 != 0 or
        !std.math.isPowerOfTwo(binding.size_bytes / 16))
        return Error.InvalidBindingSize;
    return std.math.log2_int(u64, binding.size_bytes / 16);
}
