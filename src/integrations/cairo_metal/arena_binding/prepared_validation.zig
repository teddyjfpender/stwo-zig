const std = @import("std");
const arena_plan = @import("stwo_metal_backend").arena_plan;
const protocol_recipes = @import("stwo_metal_backend").protocol_recipes;
const schedule_bindings = @import("../schedule_bindings.zig");
const resident_errors = @import("../resident/errors.zig");

const Error = resident_errors.Error;
const Sn2Counts = schedule_bindings.Sn2Counts;
const ProofDecommitGeometry = schedule_bindings.ProofDecommitGeometry;
const friStartLog = schedule_bindings.friStartLog;

pub fn runtimeFriGeometry(bindings: anytype) !protocol_recipes.FriGeometry {
    const geometry = protocol_recipes.FriGeometry.initRuntime(
        try friStartLog(bindings.quotient_tile),
        .{
            .round_count = bindings.decommit_fri_trees.len,
            .fold_step = protocol_recipes.FriGeometry.fold_step,
            .final_log = protocol_recipes.FriGeometry.final_log,
            .packed_log = protocol_recipes.FriGeometry.packed_log,
        },
    ) catch return Error.InvalidBindingSize;
    for (bindings.decommit_fri_trees, 0..) |tree, round| {
        if (tree.leaf_log != try geometry.leafLog(round)) return Error.InvalidBindingSize;
    }
    return geometry;
}

pub fn validate(bindings: anytype, geometry: ProofDecommitGeometry) !void {
    try geometry.validate();
    _ = try runtimeFriGeometry(bindings);
    if (bindings.decommit_trace_trees.len != geometry.trace_trees.len or
        bindings.decommit_fri_trees.len != geometry.fri_trees.len or
        bindings.decommit_trace_groups.len != try geometry.traceGroupCount())
        return Error.InvalidCardinality;
    if (bindings.fri_challenges.len != geometry.fri_trees.len) return Error.InvalidFriChallengeCount;
    if (bindings.fri_retained_evaluations.len + 1 != geometry.fri_trees.len)
        return Error.InvalidFriRetainedCount;
    if (bindings.fri_merkle_layers.len != try geometry.friLayerCount()) return Error.InvalidFriLayerCount;

    var group_cursor: usize = 0;
    for (bindings.decommit_trace_trees, geometry.trace_trees) |tree, expected| {
        if (tree.role != expected.role or tree.tree_index != expected.tree_index or
            tree.source_log != expected.source_log or tree.tree_log != expected.tree_log or
            tree.leaf_log != expected.leaf_log or tree.unretained != expected.unretained or
            tree.column_count != expected.column_count or tree.groups.len != expected.groupCount())
            return Error.InvalidCardinality;
        const coefficients: []const arena_plan.Binding = switch (tree.role) {
            .preprocessed => bindings.preprocessed_coefficients,
            .base => bindings.base_coefficients,
            .interaction => bindings.interaction_coefficients,
            .composition => bindings.composition_coefficients,
        };
        if (coefficients.len != tree.column_count) return Error.InvalidCardinality;
        var column_count: usize = 0;
        for (tree.groups, 0..) |group, group_index| {
            if (group_cursor >= bindings.decommit_trace_groups.len or
                group.tree_index != tree.tree_index or group.group_index != group_index or
                group.column_count == 0 or group.column_count > 16)
                return Error.InvalidSchedule;
            column_count = std.math.add(usize, column_count, group.column_count) catch
                return Error.InvalidCardinality;
            group_cursor += 1;
        }
        if (column_count != tree.column_count) return Error.InvalidCardinality;
    }
    if (group_cursor != bindings.decommit_trace_groups.len) return Error.InvalidCardinality;
    for (bindings.decommit_fri_trees, geometry.fri_trees) |tree, expected| {
        if (tree.role != expected.role or tree.round != expected.round or
            tree.tree_index != expected.tree_index or tree.leaf_log != expected.leaf_log)
            return Error.InvalidCardinality;
    }
    if (bindings.canonical_base_coefficients.len != bindings.base_coefficients.len or
        bindings.canonical_interaction_coefficients.len != bindings.interaction_coefficients.len)
        return Error.InvalidCardinality;
    if (bindings.inverse_twiddles.size_bytes == 0 or
        !std.math.isPowerOfTwo(bindings.inverse_twiddles.size_bytes / @sizeOf(u32)))
        return Error.InvalidBindingSize;
    try validateDisjointActiveBindings(bindings.inverse_twiddles, bindings.composition_accumulators);
    if (bindings.decommit_values.size_bytes == 0 or bindings.decommit_assembly.size_bytes == 0 or
        bindings.decommit_trace_lde_tile.size_bytes == 0 or bindings.proof_bytes.size_bytes == 0 or
        bindings.assembly.len == 0 or
        bindings.proof_copies.len != geometry.fri_trees.len + 10 or
        bindings.transcript_inputs.len == 0 or bindings.transcript_outputs.len == 0)
        return Error.InvalidBindingSize;
    var cursor: u64 = 0;
    for (bindings.proof_copies) |copy| {
        if (copy.destination_word_offset != cursor or copy.source.size_bytes < @as(u64, copy.word_count) * 4)
            return Error.InvalidBindingSize;
        cursor = std.math.add(u64, cursor, copy.word_count) catch return Error.InvalidBindingSize;
    }
    if (cursor * 4 != bindings.proof_bytes.size_bytes) return Error.InvalidBindingSize;
}

pub fn validateSn2(bindings: anytype) !void {
    if (bindings.composition_coefficients.len != Sn2Counts.composition_coefficients) return Error.InvalidCompositionCount;
    if (bindings.quotient_partials.len == 0 or bindings.quotient_partials.len % 4 != 0)
        return Error.InvalidQuotientCount;
    const quotient_sample_count = bindings.quotient_partials.len / 4;
    if (bindings.quotient_sample_points.size_bytes != quotient_sample_count * 8 * 4 or
        bindings.quotient_first_linear_terms.size_bytes != quotient_sample_count * 4 * 4)
        return Error.InvalidQuotientCount;
    for (0..quotient_sample_count) |sample| {
        const first = bindings.quotient_partials[sample * 4];
        if (first.size_bytes == 0 or !std.math.isPowerOfTwo(first.size_bytes / 4))
            return Error.InvalidBindingSize;
        for (bindings.quotient_partials[sample * 4 ..][0..4]) |partial| {
            if (partial.size_bytes != first.size_bytes) return Error.InvalidBindingSize;
        }
    }
    if (bindings.fri_challenges.len != Sn2Counts.fri_challenges) return Error.InvalidFriChallengeCount;
    if (bindings.fri_retained_evaluations.len != Sn2Counts.fri_retained_evaluations) return Error.InvalidFriRetainedCount;
    const fri_geometry = protocol_recipes.FriGeometry.init(try friStartLog(bindings.quotient_tile)) catch
        return Error.InvalidBindingSize;
    if (bindings.fri_merkle_layers.len != fri_geometry.totalLayerCount()) return Error.InvalidFriLayerCount;
    if (bindings.decommit_trace_groups.len != Sn2Counts.decommit_trace_groups) return Error.InvalidCardinality;
    if (bindings.composition_ext_params.len != 58) return Error.InvalidExtParamCount;
    if (bindings.relation_claimed_sums.len != 58 or bindings.canonical_claimed_sums.len != bindings.relation_claimed_sums.len)
        return Error.InvalidClaimedSumCount;
    if (bindings.preprocessed_coefficients.len != 161) return Error.InvalidPreprocessedCount;
    if (bindings.canonical_base_coefficients.len != bindings.base_coefficients.len or
        bindings.canonical_interaction_coefficients.len != bindings.interaction_coefficients.len)
        return Error.InvalidCardinality;
    if (bindings.inverse_twiddles.size_bytes == 0 or
        !std.math.isPowerOfTwo(bindings.inverse_twiddles.size_bytes / @sizeOf(u32)))
        return Error.InvalidBindingSize;
    try validateDisjointBindings(bindings.inverse_twiddles, bindings.composition_accumulators);
    for (bindings.composition_coefficients) |binding| {
        if (binding.size_bytes != bindings.inverse_twiddles.size_bytes) return Error.InvalidBindingSize;
    }
    if (bindings.fri_final_coefficients.size_bytes != 8 * 4 or
        bindings.fri_final_degree_error.size_bytes != 4 or
        bindings.transcript_state.size_bytes < 10 * 4 or bindings.transcript_inputs.len != 26 or bindings.transcript_outputs.len != 13 or
        bindings.decommit_values.size_bytes == 0 or
        bindings.decommit_assembly.size_bytes == 0 or bindings.decommit_trace_lde_tile.size_bytes == 0 or
        bindings.proof_bytes.size_bytes == 0 or bindings.assembly.len == 0 or
        bindings.proof_copies.len != 18)
        return Error.InvalidBindingSize;
    if (bindings.decommit_trace_trees.len != Sn2Counts.decommit_trace_trees or
        bindings.decommit_fri_trees.len != Sn2Counts.decommit_fri_trees)
        return Error.InvalidCardinality;
    for (bindings.decommit_trace_trees, Sn2Counts.decommit_trace_groups_by_tree, Sn2Counts.decommit_trace_columns_by_tree, 0..) |tree, group_count, column_count, tree_index| {
        if (tree.tree_index != tree_index or @intFromEnum(tree.role) != tree_index or
            tree.groups.len != group_count or tree.column_count != column_count)
            return Error.InvalidCardinality;
    }
    for (bindings.decommit_fri_trees, 0..) |tree, round| {
        if (tree.round != round or tree.tree_index != round + Sn2Counts.decommit_trace_trees or
            tree.role != tree.tree_index)
            return Error.InvalidCardinality;
    }
    var cursor: u64 = 0;
    for (bindings.proof_copies) |copy| {
        if (copy.destination_word_offset != cursor or copy.source.size_bytes < @as(u64, copy.word_count) * 4)
            return Error.InvalidBindingSize;
        cursor += copy.word_count;
    }
    if (cursor * 4 != bindings.proof_bytes.size_bytes) return Error.InvalidBindingSize;
}
pub fn validateDisjointBindings(first: arena_plan.Binding, second: arena_plan.Binding) Error!void {
    const first_end = std.math.add(u64, first.offset_bytes, first.size_bytes) catch
        return Error.InvalidBindingSize;
    const second_end = std.math.add(u64, second.offset_bytes, second.size_bytes) catch
        return Error.InvalidBindingSize;
    if (first.offset_bytes < second_end and second.offset_bytes < first_end)
        return Error.InvalidBindingAlias;
}

pub fn validateDisjointActiveBindings(first: arena_plan.Binding, second: arena_plan.Binding) Error!void {
    if (!bindingHasActiveTick(first) or !bindingHasActiveTick(second)) return;
    return validateDisjointBindings(first, second);
}

fn bindingHasActiveTick(binding: arena_plan.Binding) bool {
    for (binding.occupied) |word| if (word != 0) return true;
    return false;
}
