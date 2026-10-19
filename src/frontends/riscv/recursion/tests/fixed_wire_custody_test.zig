//! Structural inventory of the native proof wire and its verifier-owned plan.
//! A new wire field must be assigned a custody route here before it can ship.
const std = @import("std");
const fixed_wire = @import("../fixed_wire.zig");
const profile = @import("../segment_profile.zig");
const schedule = @import("../air/verifier_schedule.zig");
const payload = @import("../segment_transcript_outer_source_v2_prepared_v2.zig");
const transcript = @import("../transcript_program_v2.zig");
const provider_shape = @import("../air/segment_publication_input_provider_shape_v2.zig");

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
    try std.testing.expectEqual(profile.DIMENSIONS.queried_value_count, queried_values);
    try std.testing.expectEqual(@as(usize, 1), interaction_pow);
    try std.testing.expectEqual(@as(usize, 1), pcs_pow);
    try std.testing.expect(first_physical.? < first_composition_draw.?);
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
