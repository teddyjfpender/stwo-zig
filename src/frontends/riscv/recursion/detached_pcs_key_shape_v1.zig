//! Proof-free PCS/FRI shape for an independently admitted detached child key.
//! This module owns no captured proof, query draw, or evaluated verifier row.
const std = @import("std");
const layout_mod = @import("recursion_air_composition_capture_layout_v3.zig");
const schedule = @import("air/verifier_schedule.zig");
const fixed = @import("fixed_profile.zig");
const channel = @import("poseidon2_channel.zig");
const challenges = @import("air/universal_challenges.zig");
const transcript = @import("pcs_transcript_program_v1.zig");

pub fn scheduleShape(allocator: std.mem.Allocator, key: anytype) !schedule.ScheduleShape {
    const Layout = layout_mod.CaptureLayoutV3;
    var from_key = if (comptime @hasField(@TypeOf(key.*), "source_manifest"))
        try Layout.initSegmentFromKey(allocator, &key.manifest, key.pcs_config.fri_config.log_blowup_factor)
    else
        try Layout.initDetachedParentFromKey(allocator, &key.manifest, key.pcs_config.fri_config.log_blowup_factor);
    defer from_key.deinit();
    const heights = try from_key.treeHeightsFromManifest(&key.manifest);
    // A sparse roster changes active AIRs, not the fixed claimed-sum wire.
    const claimed_sum_count = if (comptime @hasField(@TypeOf(key.*), "source_manifest"))
        @import("air/segment_outer_adapter_manifest_v2.zig").COMPONENT_COUNT
    else
        @import("air/universal_adapter_manifest.zig").COMPONENT_COUNT;
    const identity = try key.identity();
    return .{
        .protocol_id = channel.hashBytes("detached-segment-pcs-checks/v1", 0x44504331),
        .shape_id = channel.hashBytes(&identity, 0x44504731),
        .interaction_pow_bits = key.profile.interactionPowBits(),
        .pcs_pow_bits = key.pcs_config.pow_bits,
        .query_count = @intCast(key.pcs_config.fri_config.n_queries),
        .table_count = key.manifest.roster_count,
        .claimed_sum_count = claimed_sum_count,
        .sampled_value_count = from_key.sampled_value_count,
        .tree_heights = heights,
        .fri = try fixed.FriSchedule.init(from_key.quotient_max_log_degree_bound, key.pcs_config.fri_config),
    };
}

pub fn planFromKey(allocator: std.mem.Allocator, key: anytype, schema: schedule.Schema) !schedule.Plan {
    const shape = try scheduleShape(allocator, key);
    return schedule.Plan.initShape(allocator, try schedule.ProgramSpec.init(schema, challenges.RELATION_COUNT, 1, key.manifest.total_constraints, challenges.RELATION_COUNT), shape);
}

pub fn transcriptShape(allocator: std.mem.Allocator, key: anytype) !transcript.PcsShape {
    const shape = try scheduleShape(allocator, key);
    return .{
        .sampled_value_count = shape.sampled_value_count,
        .fri_layer_count = shape.fri.count,
        .last_layer_coefficient_count = shape.fri.last_layer_coefficient_count,
        .query_count = shape.query_count,
        .pow_bits = shape.pcs_pow_bits,
    };
}
