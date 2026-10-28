//! Structural inventory of the native proof wire and its verifier-owned plan.
//! A new wire field must be assigned a custody route here before it can ship.
const std = @import("std");
const fixed_wire = @import("../fixed_wire.zig");
const profile = @import("../segment_profile.zig");
const schedule = @import("../air/verifier_schedule.zig");
const payload = @import("../segment_transcript_outer_source_v2_prepared_v2.zig");
const transcript = @import("../transcript_program_v2.zig");
const provider_shape = @import("../air/segment_publication_input_provider_shape_v2.zig");
const relation = @import("../../air/lang/relation.zig");
const merkle_root = @import("../air/merkle_root.zig");
const merkle_root_relation = @import("../air/merkle_root_relation.zig");
const merkle_path = @import("../air/merkle_path.zig");
const merkle_path_relation = @import("../air/merkle_path_relation.zig");
const trace_merkle = @import("../air/trace_merkle.zig");
const trace_merkle_relation = @import("../air/trace_merkle_relation.zig");
const fri_anchor = @import("../air/fri_merkle_anchor.zig");
const fri_anchor_relation = @import("../air/fri_merkle_anchor_relation.zig");
const fri_node = @import("../air/fri_merkle_node.zig");
const fri_node_relation = @import("../air/fri_merkle_node_relation.zig");
const fri_leaf = @import("../air/fri_merkle_leaf.zig");
const fri_leaf_relation = @import("../air/fri_merkle_leaf_relation.zig");
const fri_input = @import("../air/fri_verifier_input.zig");
const fri_input_relation = @import("../air/fri_verifier_input_relation.zig");

const Custody = enum {
    transcript_payload,
    query_mapping,
    trace_merkle_path,
    fri_layer,
    pow_check,
};

fn route(comptime name: []const u8) Custody {
    if (std.mem.eql(u8, name, "commitments") or
        std.mem.eql(u8, name, "claimed_sums") or
        std.mem.eql(u8, name, "physical_claimed_sums") or
        std.mem.eql(u8, name, "sampled_values") or
        std.mem.eql(u8, name, "last_layer_coefficients")) return .transcript_payload;
    if (std.mem.eql(u8, name, "queried_values")) return .query_mapping;
    if (std.mem.eql(u8, name, "trace_paths")) return .trace_merkle_path;
    if (std.mem.eql(u8, name, "fri_layers")) return .fri_layer;
    if (std.mem.eql(u8, name, "interaction_pow") or
        std.mem.eql(u8, name, "pcs_pow")) return .pow_check;
    @compileError("fixed wire field has no reviewed verifier custody route: " ++ name);
}

test "every fixed wire field has a plan-owned custody route" {
    const Wire = fixed_wire.FixedStarkProofWire(profile.DIMENSIONS);
    const fields = @typeInfo(Wire).@"struct".fields;
    try std.testing.expectEqual(@as(usize, 10), fields.len);
    var routes: [5]usize = @splat(0);
    inline for (fields) |field| {
        const custody = comptime route(field.name);
        routes[@intFromEnum(custody)] += 1;
    }
    try std.testing.expectEqualDeep([5]usize{ 5, 1, 1, 1, 2 }, routes);

    var plans = try profile.initPlans(std.testing.allocator, 2, 3);
    defer plans.vm.deinit();
    defer plans.recursion.deinit();
    var commitments: usize = 0;
    var trace_paths: usize = 0;
    var fri_paths: usize = 0;
    var fri_folds: usize = 0;
    var fri_commitments: usize = 0;
    var queried_values: usize = 0;
    var sampled_values: usize = 0;
    var physical_claims: usize = 0;
    var claimed_sums: usize = 0;
    var last_coefficients: usize = 0;
    var interaction_pow: usize = 0;
    var pcs_pow: usize = 0;
    var first_physical: ?usize = null;
    var first_composition_draw: ?usize = null;
    for (plans.vm.steps, 0..) |step, index| switch (step) {
        .absorb_trace_commitment => commitments += 1,
        .absorb_claimed_sums => |item| claimed_sums += @as(usize, item.count),
        .absorb_physical_claims => |item| {
            physical_claims += @as(usize, item.count);
            if (first_physical == null) first_physical = index;
        },
        .draw_composition_randomness => first_composition_draw = index,
        .absorb_sampled_values => |item| sampled_values += @as(usize, item.count),
        .absorb_last_layer_coefficients => |item| last_coefficients += @as(usize, item.count),
        .verify_trace_merkle_path => trace_paths += 1,
        .verify_fri_merkle_path => fri_paths += 1,
        .fold_fri => fri_folds += 1,
        .absorb_fri_commitment => fri_commitments += 1,
        .evaluate_deep_quotient => |item| queried_values += @as(usize, item.queried_values_per_query),
        .verify_and_absorb_interaction_pow => interaction_pow += 1,
        .verify_and_absorb_pcs_pow => pcs_pow += 1,
        else => {},
    };
    try std.testing.expectEqual(profile.DIMENSIONS.commitment_count, commitments);
    try std.testing.expectEqual(profile.DIMENSIONS.claimed_sum_count, claimed_sums);
    try std.testing.expectEqual(profile.DIMENSIONS.physical_claimed_sum_count, physical_claims);
    try std.testing.expectEqual(profile.DIMENSIONS.sampled_value_count, sampled_values);
    try std.testing.expectEqual(profile.DIMENSIONS.last_layer_coefficient_count, last_coefficients);
    try std.testing.expectEqual(profile.DIMENSIONS.trace_path_count, trace_paths);
    try std.testing.expectEqual(profile.DIMENSIONS.fri_layer_count * profile.DIMENSIONS.query_count, fri_paths);
    try std.testing.expectEqual(fri_paths, fri_folds);
    try std.testing.expectEqual(profile.DIMENSIONS.fri_layer_count, fri_commitments);
    try std.testing.expectEqual(profile.DIMENSIONS.queried_value_count, queried_values);
    try std.testing.expectEqual(@as(usize, 1), interaction_pow);
    try std.testing.expectEqual(@as(usize, 1), pcs_pow);
    try std.testing.expect(first_physical.? < first_composition_draw.?);
}

test "full-profile transcript coordinates cover every scalar wire slot exactly once" {
    const dimensions = profile.DIMENSIONS;
    // The row-5 source coordinates are protocol fields, not offsets supplied
    // by the proof. Exhaustive checks below detect gaps and aliases even when
    // a small synthetic execution cannot exercise production-sized arrays.
    for (0..dimensions.commitment_count) |tree| {
        for (0..8) |limb| {
            const item = metadata(.trace_commitment, .{ @intCast(tree), 0, 0, 0 }, @intCast(limb));
            try std.testing.expectEqual(payload.PayloadSourceKindV2.commitment, item.source_kind);
            try std.testing.expectEqual(@as(u32, @intCast(tree)), item.item_index);
            try std.testing.expectEqual(@as(u32, @intCast(limb)), item.limb_index);
            try std.testing.expectEqual(@as(u32, @intFromBool(tree == 0)), item.constant_mask);
            try std.testing.expectEqual(@as(u32, 1), item.input_use_count);
        }
    }
    for (0..dimensions.claimed_sum_count) |claim| {
        for (0..4) |limb| {
            const item = metadata(.claimed_sum, .{ @intCast(claim), 0, 0, 0 }, @intCast(limb));
            try std.testing.expectEqual(payload.PayloadSourceKindV2.claimed_sum, item.source_kind);
            try std.testing.expectEqual(@as(u32, @intCast(claim)), item.item_index);
            try std.testing.expectEqual(@as(u32, @intCast(limb)), item.limb_index);
            try std.testing.expectEqual(@as(u32, 0), item.constant_mask);
            try std.testing.expectEqual(@as(u32, 1), item.input_use_count);
        }
    }
    // Batch offsets cross the native component/infra boundary. The source
    // index must remain global even when the plan splits claims into batches.
    for (0..dimensions.physical_claimed_sum_count) |claim| {
        for (0..4) |limb| {
            const item = metadata(.physical_claim_batch, .{ @intCast(claim), 1, 0, 0 }, @intCast(limb));
            try std.testing.expectEqual(payload.PayloadSourceKindV2.vm_air_claimed_sum, item.source_kind);
            try std.testing.expectEqual(@as(u32, @intCast(claim)), item.item_index);
            try std.testing.expectEqual(@as(u32, @intCast(limb)), item.limb_index);
            try std.testing.expectEqual(@as(u32, 0), item.constant_mask);
            try std.testing.expectEqual(@as(u32, 1), item.input_use_count);
        }
    }
    for (0..dimensions.sampled_value_count) |value| {
        for (0..4) |limb| {
            const item = metadata(.sampled_values, .{ @intCast(dimensions.sampled_value_count), 0, 0, 0 }, @intCast(value * 4 + limb));
            try std.testing.expectEqual(payload.PayloadSourceKindV2.sampled_value, item.source_kind);
            try std.testing.expectEqual(@as(u32, @intCast(value)), item.item_index);
            try std.testing.expectEqual(@as(u32, @intCast(limb)), item.limb_index);
            try std.testing.expectEqual(@as(u32, 0), item.constant_mask);
            try std.testing.expectEqual(@as(u32, 2), item.input_use_count);
        }
    }
    for (0..dimensions.fri_layer_count) |layer| {
        for (0..8) |limb| {
            const item = metadata(.fri_commitment, .{ @intCast(layer), 0, 0, 0 }, @intCast(limb));
            try std.testing.expectEqual(payload.PayloadSourceKindV2.fri_commitment, item.source_kind);
            try std.testing.expectEqual(@as(u32, @intCast(layer)), item.item_index);
            try std.testing.expectEqual(@as(u32, @intCast(limb)), item.limb_index);
            try std.testing.expectEqual(@as(u32, 0), item.constant_mask);
            try std.testing.expectEqual(@as(u32, 1), item.input_use_count);
        }
    }
    for (0..dimensions.last_layer_coefficient_count) |coefficient| {
        for (0..4) |limb| {
            const item = metadata(.last_layer_coefficients, .{ @intCast(dimensions.last_layer_coefficient_count), 0, 0, 0 }, @intCast(coefficient * 4 + limb));
            try std.testing.expectEqual(payload.PayloadSourceKindV2.last_layer_coefficient, item.source_kind);
            try std.testing.expectEqual(@as(u32, @intCast(coefficient)), item.item_index);
            try std.testing.expectEqual(@as(u32, @intCast(limb)), item.limb_index);
            try std.testing.expectEqual(@as(u32, 0), item.constant_mask);
            try std.testing.expectEqual(@as(u32, 1), item.input_use_count);
        }
    }
}

test "transcript payload distinguishes key constants and physical wire claims" {
    const provider = try provider_shape.Shape.init(profile.DIMENSIONS.physical_claimed_sum_count);
    try std.testing.expectEqual(@as(u32, @intCast(provider_shape.LUP2_WORD_COUNT)), provider.logical_row_count);
    try std.testing.expectEqual(@as(usize, 0), provider_shape.DETAILED_LIMB_COUNT);
    const tree0 = metadata(.trace_commitment, .{ 0, 0, 0, 0 }, 0);
    try std.testing.expectEqual(@as(u32, 1), tree0.constant_mask);
    try std.testing.expectEqual(@as(u32, 1), tree0.input_use_count);
    for (1..profile.DIMENSIONS.commitment_count) |tree| {
        const item = metadata(.trace_commitment, .{ @intCast(tree), 0, 0, 0 }, 0);
        try std.testing.expectEqual(@as(u32, 0), item.constant_mask);
        try std.testing.expectEqual(@as(u32, 1), item.input_use_count);
    }
    for (0..profile.PHYSICAL_CLAIMED_SUM_COUNT) |claim| {
        const item = metadata(.physical_claim_batch, .{ @intCast(claim), 1, 0, 0 }, 0);
        try std.testing.expectEqual(payload.PayloadSourceKindV2.vm_air_claimed_sum, item.source_kind);
        try std.testing.expectEqual(@as(u32, @intCast(claim)), item.item_index);
        try std.testing.expectEqual(@as(u32, 0), item.constant_mask);
        try std.testing.expectEqual(@as(u32, 1), item.input_use_count);
    }
    // PoW values are checked by the dedicated PoW rows, so their payload
    // input-relation multiplicity is zero; they are not silently discarded.
    for ([_]transcript.Kind{ .interaction_pow, .pcs_pow }) |kind| {
        const item = metadata(kind, .{ 0, 0, 0, 0 }, 0);
        try std.testing.expectEqual(@as(u32, 0), item.constant_mask);
        try std.testing.expectEqual(@as(u32, 0), item.input_use_count);
    }
}

fn metadata(kind: transcript.Kind, args: [4]u32, payload_index: u32) payload.PayloadMetadata {
    return payload.payloadMetadata(.{
        .kind = kind,
        .verifier_sequence = 0,
        .sub_index = 0,
        .args = args,
    }, payload_index);
}

fn eventCount(plan: anytype, domain: relation.Domain, role: relation.Role) usize {
    var count: usize = 0;
    for (plan.events) |event| {
        count += @intFromBool(event.domain == domain and event.role == role);
    }
    return count;
}

test "Merkle and FRI AIR custody joins roots paths leaves and verifier values" {
    const allocator = std.testing.allocator;
    var root_def = try merkle_root.build(allocator);
    defer root_def.deinit();
    const root_plan = try merkle_root_relation.authenticate(&root_def);
    var path_def = try merkle_path.build(allocator);
    defer path_def.deinit();
    const path_plan = try merkle_path_relation.authenticate(&path_def);
    var trace_def = try trace_merkle.build(allocator);
    defer trace_def.deinit();
    const trace_plan = try trace_merkle_relation.authenticate(&trace_def);
    var anchor_def = try fri_anchor.build(allocator);
    defer anchor_def.deinit();
    const anchor_plan = try fri_anchor_relation.authenticate(&anchor_def);
    var node_def = try fri_node.build(allocator);
    defer node_def.deinit();
    const node_plan = try fri_node_relation.authenticate(&node_def);
    var leaf_def = try fri_leaf.build(allocator);
    defer leaf_def.deinit();
    const leaf_plan = try fri_leaf_relation.authenticate(&leaf_def);
    var input_def = try fri_input.build(allocator);
    defer input_def.deinit();
    const input_plan = try fri_input_relation.authenticate(&input_def);

    const node = relation.Domain.recursion_merkle_node;
    const local = relation.Domain.recursion_fri_merkle_local_root;
    const value = relation.Domain.recursion_fri_merkle_value_word;
    try std.testing.expectEqual(@as(usize, 1), eventCount(root_plan, node, .emit));
    try std.testing.expectEqual(@as(usize, 1), eventCount(path_plan, node, .consume));
    try std.testing.expectEqual(@as(usize, 1), eventCount(path_plan, node, .emit));
    try std.testing.expectEqual(@as(usize, 1), eventCount(trace_plan, node, .consume));
    try std.testing.expectEqual(@as(usize, 1), eventCount(anchor_plan, node, .consume));
    try std.testing.expectEqual(@as(usize, 1), eventCount(anchor_plan, local, .emit));
    try std.testing.expectEqual(@as(usize, 1), eventCount(node_plan, node, .consume));
    try std.testing.expectEqual(@as(usize, 1), eventCount(node_plan, local, .consume));
    try std.testing.expectEqual(@as(usize, 2), eventCount(node_plan, node, .emit));
    try std.testing.expectEqual(@as(usize, 1), eventCount(leaf_plan, node, .consume));
    try std.testing.expectEqual(@as(usize, 1), eventCount(leaf_plan, local, .consume));
    try std.testing.expectEqual(@as(usize, 8), eventCount(leaf_plan, value, .emit));
    try std.testing.expectEqual(@as(usize, 1), eventCount(input_plan, value, .consume));
}
