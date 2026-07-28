//! Lifetime-sealed proof arena for exact mixed-height CUDA Blake.

const std = @import("std");
const field = @import("stwo_cuda_backend").abi.field;
const quotient_abi = @import("stwo_cuda_backend").abi.stages.quotient;
const arena = @import("stwo_cuda_backend").runtime.arena;
const relation_abi = @import("stwo_cuda_backend").abi.stages.relation;
const telemetry = @import("stwo_cuda_backend").runtime.telemetry;
const completion_plan = @import("completion_plan.zig");
const geometry_mod = @import("geometry.zig");
const interaction_plan = @import("interaction_plan.zig");
const slots = @import("slots.zig");
const views_mod = @import("views.zig");

pub const Prepared = struct {
    geometry: geometry_mod.Geometry,
    views: views_mod.TreeViews,
    requirements: []arena.Requirement,
    plan: arena.Plan,

    pub fn init(
        allocator: std.mem.Allocator,
        geometry: geometry_mod.Geometry,
    ) !Prepared {
        const views = try views_mod.TreeViews.init(geometry);
        try views.validate(geometry);
        const requirements = try buildRequirements(allocator, geometry);
        errdefer allocator.free(requirements);
        return .{
            .geometry = geometry,
            .views = views,
            .requirements = requirements,
            .plan = try arena.Plan.init(allocator, requirements),
        };
    }

    pub fn deinit(self: *Prepared, allocator: std.mem.Allocator) void {
        self.plan.deinit(allocator);
        allocator.free(self.requirements);
        self.* = undefined;
    }

    pub fn placement(
        self: Prepared,
        id: arena.SlotId,
    ) !arena.Placement {
        return self.plan.placement(id);
    }

    pub fn validate(self: Prepared) !void {
        try self.views.validate(self.geometry);
        for (self.plan.placements, 0..) |left, index| {
            for (self.plan.placements[index + 1 ..]) |right| {
                if (!lifetimesOverlap(
                    left.requirement,
                    right.requirement,
                )) continue;
                if (try left.endWords() > right.offset_words and
                    try right.endWords() > left.offset_words)
                {
                    return error.OverlappingResidentLifetime;
                }
            }
        }
        try requireWords(
            self,
            slots.main_evaluations,
            self.geometry.main_words,
        );
        try requireWords(
            self,
            slots.interaction_evaluations,
            self.geometry.interaction_words,
        );
        try requireWords(
            self,
            slots.statement1_claims,
            geometry_mod.statement1_words,
        );
        const relation_words = try geometry_mod.relationFractionWorkspaceWords(
            self.geometry.statement.log_n_rows,
        );
        try requireWords(
            self,
            slots.interaction_denominators,
            relation_words,
        );
        const interaction = try interaction_plan.Plan.init(
            self.geometry,
            self.views,
        );
        const completion = try completion_plan.Plan.init(interaction);
        try requireWords(
            self,
            slots.interaction_output_pointer_table,
            geometry_mod.interaction_columns * 2,
        );
        try requireWords(
            self,
            slots.interaction_geometry,
            geometry_mod.component_count * relation_abi.geometry_words,
        );
        try requireWords(
            self,
            slots.interaction_reduction_partials,
            try completion.scratchWords(),
        );
        try requireWords(
            self,
            slots.interaction_scan_block_sums,
            try completion.scratchWords(),
        );
        try requireWords(
            self,
            slots.commitment_states,
            try progressiveStateWords(self.geometry.query_log),
        );
        try requireWords(
            self,
            slots.sampled_values,
            try typedWords(
                field.SecureField,
                geometry_mod.sampled_value_count,
            ),
        );
        try requireWords(
            self,
            slots.oods_points,
            try typedWords(
                field.SecureCirclePoint,
                geometry_mod.sampled_value_count,
            ),
        );
        try requireWords(
            self,
            slots.quotient_descriptors,
            try typedWords(
                quotient_abi.PreparedTermDescriptor,
                geometry_mod.sampled_value_count,
            ),
        );
        try requireWords(
            self,
            slots.quotient_term_points,
            try typedWords(
                field.SecureCirclePoint,
                geometry_mod.sampled_value_count,
            ),
        );
    }
};

pub fn buildRequirements(
    allocator: std.mem.Allocator,
    geometry: geometry_mod.Geometry,
) ![]arena.Requirement {
    var result = std.ArrayList(arena.Requirement).empty;
    errdefer result.deinit(allocator);
    const query_rows = try rowsAtLog(geometry.query_log);

    try add(&result, allocator, slots.twiddles_forward, query_rows, .ingress, .decommit);
    try add(&result, allocator, slots.twiddles_inverse, query_rows, .ingress, .fri_commit);
    try add(&result, allocator, slots.transcript_state, 16, .ingress, .decommit);
    try add(&result, allocator, slots.relation_elements, geometry_mod.relation_element_words, .trace_commit, .constraint_evaluation);
    try add(&result, allocator, slots.statement1_claims, geometry_mod.statement1_words, .constraint_evaluation, .proof_assembly);
    try add(&result, allocator, slots.composition_challenge, 4, .constraint_evaluation, .constraint_evaluation);
    const relation_words = try geometry_mod.relationFractionWorkspaceWords(
        geometry.statement.log_n_rows,
    );
    const interaction = try interaction_plan.Plan.init(
        geometry,
        try views_mod.TreeViews.init(geometry),
    );
    const completion = try completion_plan.Plan.init(interaction);
    const pointer_words = @sizeOf(usize) / @sizeOf(u32);
    const top_table_words = geometry_mod.component_count * pointer_words;
    const scratch_words = try completion.scratchWords();
    try add(&result, allocator, slots.interaction_denominators, relation_words, .constraint_evaluation, .constraint_evaluation);
    try addAligned(
        &result,
        allocator,
        slots.commitment_states,
        try progressiveStateWords(geometry.query_log),
        8,
        .trace_commit,
        .constraint_evaluation,
    );
    try addAligned(&result, allocator, slots.interaction_output_pointer_table, geometry_mod.interaction_columns * pointer_words, pointer_words, .ingress, .constraint_evaluation);
    try addAligned(&result, allocator, slots.interaction_output_tables, top_table_words, pointer_words, .ingress, .constraint_evaluation);
    try addAligned(&result, allocator, slots.interaction_denominator_tables, top_table_words, pointer_words, .ingress, .constraint_evaluation);
    try addAligned(&result, allocator, slots.interaction_claim_tables, top_table_words, pointer_words, .ingress, .constraint_evaluation);
    try add(&result, allocator, slots.interaction_geometry, geometry_mod.component_count * relation_abi.geometry_words, .ingress, .constraint_evaluation);
    try add(&result, allocator, slots.interaction_reduction_partials, scratch_words, .constraint_evaluation, .constraint_evaluation);
    try add(&result, allocator, slots.interaction_scan_block_sums, scratch_words, .constraint_evaluation, .constraint_evaluation);

    try addTree(
        &result,
        allocator,
        .preprocessed,
        slots.preprocessed_evaluations,
        slots.preprocessed_coefficients,
        slots.preprocessed_lde,
        slots.preprocessed_hashes,
        slots.preprocessed_layers,
        geometry,
        .trace_generation,
        .trace_commit,
        .constraint_evaluation,
    );
    try addTree(
        &result,
        allocator,
        .main,
        slots.main_evaluations,
        slots.main_coefficients,
        slots.main_lde,
        slots.main_hashes,
        slots.main_layers,
        geometry,
        .trace_generation,
        .trace_commit,
        .constraint_evaluation,
    );
    try addTree(
        &result,
        allocator,
        .interaction,
        slots.interaction_evaluations,
        slots.interaction_coefficients,
        slots.interaction_lde,
        slots.interaction_hashes,
        slots.interaction_layers,
        geometry,
        .constraint_evaluation,
        .constraint_evaluation,
        .constraint_evaluation,
    );
    try addTree(
        &result,
        allocator,
        .composition,
        slots.composition_evaluations,
        slots.composition_coefficients,
        slots.composition_lde,
        slots.composition_hashes,
        slots.composition_layers,
        geometry,
        .constraint_evaluation,
        .constraint_evaluation,
        .constraint_evaluation,
    );

    try add(&result, allocator, slots.constraint_random_powers, try typedWords(field.SecureField, geometry_mod.constraint_count), .constraint_evaluation, .constraint_evaluation);
    try add(&result, allocator, slots.constraint_denominator_inverses, geometry_mod.component_count * 2, .constraint_evaluation, .constraint_evaluation);
    try add(&result, allocator, slots.constraint_component_partials, try typedWords(field.SecureField, try checkedMul(geometry_mod.component_count, query_rows)), .constraint_evaluation, .constraint_evaluation);

    const sample_words = try typedWords(
        field.SecureField,
        geometry_mod.sampled_value_count,
    );
    try add(&result, allocator, slots.oods_parameter, try typedWords(field.SecureField, 1), .oods, .quotient);
    try add(&result, allocator, slots.oods_points, try typedWords(field.SecureCirclePoint, geometry_mod.sampled_value_count), .oods, .quotient);
    try add(&result, allocator, slots.oods_fold_counts, geometry_mod.sampled_value_count, .ingress, .oods);
    try add(&result, allocator, slots.oods_output_indices, geometry_mod.sampled_value_count, .ingress, .oods);
    try add(&result, allocator, slots.oods_scratch_a, sample_words, .oods, .oods);
    try add(&result, allocator, slots.oods_scratch_b, sample_words, .oods, .oods);
    try add(&result, allocator, slots.sampled_values, sample_words, .oods, .proof_assembly);

    try add(&result, allocator, slots.quotient_challenge, try typedWords(field.SecureField, 1), .oods, .quotient);
    try add(&result, allocator, slots.quotient_descriptors, try typedWords(quotient_abi.PreparedTermDescriptor, geometry_mod.sampled_value_count), .ingress, .quotient);
    try add(&result, allocator, slots.quotient_term_points, try typedWords(field.SecureCirclePoint, geometry_mod.sampled_value_count), .quotient, .quotient);
    try add(&result, allocator, slots.quotient_line_coefficients, try typedWords(field.SecureField, try checkedMul(geometry_mod.sampled_value_count, 3)), .quotient, .quotient);
    try add(&result, allocator, slots.quotient_partials, try typedWords(field.SecureField, query_rows), .quotient, .quotient);
    try add(&result, allocator, slots.quotient_coordinates, try typedWords(field.SecureField, query_rows), .quotient, .decommit);

    var layer_log = geometry.query_log;
    for (0..geometry.fri_tree_count) |index| {
        const layer_rows = try rowsAtLog(layer_log);
        try add(
            &result,
            allocator,
            slots.friCoordinates(index),
            try typedWords(field.SecureField, layer_rows),
            if (index == 0) .quotient else .fri_commit,
            .decommit,
        );
        try addAligned(
            &result,
            allocator,
            slots.friHashes(index),
            try hashWords(layer_rows),
            8,
            .fri_commit,
            .decommit,
        );
        try addAligned(
            &result,
            allocator,
            slots.friLayers(index),
            try merkleLayerWords(layer_log),
            2,
            .fri_commit,
            .decommit,
        );
        layer_log -= 1;
    }

    try add(&result, allocator, slots.pow_nonce, 2, .pow, .proof_assembly);
    try add(&result, allocator, slots.raw_queries, geometry.protocol.fri_config.n_queries, .decommit, .proof_assembly);
    try add(&result, allocator, slots.decommit_scratch, try decommitScratchWords(geometry), .decommit, .decommit);
    try addAligned(&result, allocator, slots.proof_bundle, try terminalBundleCapacity(geometry), 8, .proof_assembly, .proof_assembly);
    return result.toOwnedSlice(allocator);
}

fn addTree(
    result: *std.ArrayList(arena.Requirement),
    allocator: std.mem.Allocator,
    tree: geometry_mod.Tree,
    evaluation_slot: arena.SlotId,
    coefficient_slot: arena.SlotId,
    lde_slot: arena.SlotId,
    hash_slot: arena.SlotId,
    layer_slot: arena.SlotId,
    geometry: geometry_mod.Geometry,
    generate_stage: telemetry.Stage,
    commit_stage: telemetry.Stage,
    evaluation_live_through: telemetry.Stage,
) !void {
    const source_words = geometry.treeWords(tree);
    const commitment_rows = try rowsAtLog(
        geometry.treeCommitmentLog(tree),
    );
    try add(result, allocator, evaluation_slot, source_words, generate_stage, evaluation_live_through);
    try add(result, allocator, coefficient_slot, source_words, commit_stage, .oods);
    try add(result, allocator, lde_slot, source_words * 2, commit_stage, .decommit);
    try addAligned(result, allocator, hash_slot, try hashWords(commitment_rows), 8, commit_stage, .decommit);
    try addAligned(
        result,
        allocator,
        layer_slot,
        try merkleLayerWords(geometry.treeCommitmentLog(tree)),
        2,
        commit_stage,
        .decommit,
    );
}

fn terminalBundleCapacity(geometry: geometry_mod.Geometry) !usize {
    const roots = (geometry_mod.trace_tree_count +
        geometry.fri_tree_count) * 8;
    const fixed = 128 +
        roots +
        geometry_mod.sampled_value_count * 4 +
        geometry_mod.statement1_words +
        8;
    return std.math.add(
        usize,
        fixed,
        try decommitScratchWords(geometry),
    ) catch error.GeometryOverflow;
}

fn decommitScratchWords(geometry: geometry_mod.Geometry) !usize {
    const queries = geometry.protocol.fri_config.n_queries;
    const trace_values = std.math.mul(
        usize,
        queries,
        geometry_mod.source_column_count,
    ) catch return error.GeometryOverflow;
    const trace_hashes = geometry_mod.trace_tree_count *
        queries *
        geometry.query_log *
        8;
    const fri = geometry.fri_tree_count *
        queries *
        (4 + geometry.query_log * 8);
    return std.math.add(
        usize,
        trace_values + trace_hashes,
        fri,
    ) catch error.GeometryOverflow;
}

fn hashWords(rows: usize) !usize {
    const hashes = std.math.sub(
        usize,
        std.math.mul(usize, rows, 2) catch
            return error.GeometryOverflow,
        1,
    ) catch return error.GeometryOverflow;
    return typedWords(field.Blake2sHash, hashes);
}

fn progressiveStateWords(log_rows: u32) !usize {
    return typedWords(
        field.ProgressiveBlake2sState,
        try rowsAtLog(log_rows),
    );
}

fn merkleLayerWords(log_rows: u32) !usize {
    const descriptors = std.math.add(
        usize,
        std.math.cast(usize, log_rows) orelse
            return error.GeometryOverflow,
        1,
    ) catch return error.GeometryOverflow;
    return typedWords(field.MerkleLayerDescriptor, descriptors);
}

fn typedWords(comptime F: type, count: usize) !usize {
    comptime std.debug.assert(@sizeOf(F) % @sizeOf(u32) == 0);
    return std.math.mul(
        usize,
        count,
        @sizeOf(F) / @sizeOf(u32),
    ) catch error.GeometryOverflow;
}

fn checkedMul(left: usize, right: usize) !usize {
    return std.math.mul(usize, left, right) catch error.GeometryOverflow;
}

fn rowsAtLog(log_rows: u32) !usize {
    if (log_rows >= @bitSizeOf(usize)) return error.GeometryOverflow;
    return @as(usize, 1) << @intCast(log_rows);
}

fn add(
    result: *std.ArrayList(arena.Requirement),
    allocator: std.mem.Allocator,
    id: arena.SlotId,
    words: usize,
    live_from: telemetry.Stage,
    live_through: telemetry.Stage,
) !void {
    try addAligned(
        result,
        allocator,
        id,
        words,
        1,
        live_from,
        live_through,
    );
}

fn addAligned(
    result: *std.ArrayList(arena.Requirement),
    allocator: std.mem.Allocator,
    id: arena.SlotId,
    words: usize,
    alignment_words: usize,
    live_from: telemetry.Stage,
    live_through: telemetry.Stage,
) !void {
    if (words == 0) return error.InvalidArenaRequirement;
    try result.append(allocator, .{
        .id = id,
        .words = words,
        .alignment_words = alignment_words,
        .live_from = live_from,
        .live_through = live_through,
    });
}

fn requireWords(
    prepared: Prepared,
    id: arena.SlotId,
    words: usize,
) !void {
    if ((try prepared.plan.placement(id)).requirement.words != words)
        return error.InvalidArenaRequirement;
}

fn lifetimesOverlap(
    left: arena.Requirement,
    right: arena.Requirement,
) bool {
    return left.live_from.index() <= right.live_through.index() and
        right.live_from.index() <= left.live_through.index();
}

test "exact Blake arena seals all mixed-height trees and terminal read" {
    const allocator = std.testing.allocator;
    const geometry = try geometry_mod.admit(.{
        .statement = .{ .log_n_rows = 4 },
        .protocol = @import("stwo_core").pcs.PcsConfig.default(),
    });
    var prepared = try Prepared.init(allocator, geometry);
    defer prepared.deinit(allocator);
    try prepared.validate();

    try std.testing.expectEqual(
        geometry.main_words,
        (try prepared.placement(slots.main_evaluations))
            .requirement.words,
    );
    try std.testing.expectEqual(
        geometry.interaction_words,
        (try prepared.placement(slots.interaction_evaluations))
            .requirement.words,
    );
    try std.testing.expectEqual(
        @as(usize, 4),
        (try prepared.placement(slots.quotient_coordinates))
            .requirement.words /
            (@as(usize, 1) << @intCast(geometry.query_log)),
    );
    try std.testing.expectEqual(
        telemetry.Stage.proof_assembly,
        (try prepared.placement(slots.proof_bundle))
            .requirement.live_from,
    );
    try std.testing.expectEqual(
        (@as(usize, geometry.treeCommitmentLog(.main)) + 1) * 4,
        (try prepared.placement(slots.main_layers)).requirement.words,
    );
    const commitment_states =
        (try prepared.placement(slots.commitment_states)).requirement;
    try std.testing.expectEqual(
        (@as(usize, 1) << @intCast(geometry.query_log)) * 24,
        commitment_states.words,
    );
    try std.testing.expectEqual(
        telemetry.Stage.trace_commit,
        commitment_states.live_from,
    );
    try std.testing.expectEqual(
        telemetry.Stage.constraint_evaluation,
        commitment_states.live_through,
    );
    try std.testing.expectEqual(
        geometry_mod.sampled_value_count * 8,
        (try prepared.placement(slots.oods_points)).requirement.words,
    );
    try std.testing.expectEqual(
        geometry_mod.sampled_value_count * 5,
        (try prepared.placement(slots.quotient_descriptors))
            .requirement.words,
    );
    try std.testing.expectEqual(
        geometry_mod.sampled_value_count * 8,
        (try prepared.placement(slots.quotient_term_points))
            .requirement.words,
    );
}

test "exact Blake arena aliases only disjoint protocol lifetimes" {
    const allocator = std.testing.allocator;
    const geometry = try geometry_mod.admit(.{
        .statement = .{ .log_n_rows = 5 },
        .protocol = @import("stwo_core").pcs.PcsConfig.default(),
    });
    var prepared = try Prepared.init(allocator, geometry);
    defer prepared.deinit(allocator);
    try prepared.validate();
    try std.testing.expect(prepared.plan.total_words > geometry.trace_words);
}

test "exact arena excludes both legacy full-size interaction mirrors" {
    const allocator = std.testing.allocator;
    const geometry = try geometry_mod.admit(.{
        .statement = .{ .log_n_rows = 4 },
        .protocol = @import("stwo_core").pcs.PcsConfig.default(),
    });
    const current_requirements = try buildRequirements(allocator, geometry);
    defer allocator.free(current_requirements);
    for (current_requirements) |requirement| {
        try std.testing.expect(requirement.id != 0x2121);
        try std.testing.expect(requirement.id != 0x2215);
    }
    var legacy_requirements = std.ArrayList(arena.Requirement).empty;
    defer legacy_requirements.deinit(allocator);
    try legacy_requirements.appendSlice(allocator, current_requirements);
    const relation_words = try geometry_mod.relationFractionWorkspaceWords(
        geometry.statement.log_n_rows,
    );
    const source_words = geometry.treeWords(.preprocessed) +
        geometry.main_words;
    try legacy_requirements.append(allocator, .{
        .id = 0x2121,
        .words = relation_words,
        .live_from = .constraint_evaluation,
        .live_through = .constraint_evaluation,
    });
    try legacy_requirements.append(allocator, .{
        .id = 0x2215,
        .words = source_words,
        .live_from = .trace_generation,
        .live_through = .constraint_evaluation,
    });
    var current = try arena.Plan.init(allocator, current_requirements);
    defer current.deinit(allocator);
    var legacy = try arena.Plan.init(allocator, legacy_requirements.items);
    defer legacy.deinit(allocator);
    try std.testing.expectEqual(
        relation_words + source_words,
        legacy.total_words - current.total_words,
    );
}
