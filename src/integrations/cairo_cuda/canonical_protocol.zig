//! Runtime proof geometry using the same security configuration as CPU/Metal.
const std = @import("std");
const cairo = @import("stwo_cairo_frontend");
const core = @import("stwo_core");
const sizing = @import("executor/resident_plan_sizing.zig");
const compact = cairo.compact_verifier_interchange;

pub fn derive(allocator: std.mem.Allocator, bundle: cairo.witness.composition_bundle.Bundle, preprocessed_logs: []const u32) !compact.CompactProtocolV1 {
    const config = cairo.proving.transaction.official_pcs_config;
    const degree = try bundle.verifierMaxLogDegreeBound();
    const columns = [4]u32{ @intCast(preprocessed_logs.len), finalSpan(bundle, 1), finalSpan(bundle, 2), 8 };
    const fold = config.fri_config.fold_step;
    const final_log = config.fri_config.log_last_layer_degree_bound;
    const rounds = 1 + (degree - final_log - 1) / fold;
    const geometry = compact.RuntimeProtocolGeometryV1{
        .query_pow_bits = config.pow_bits,
        .log_blowup_factor = config.fri_config.log_blowup_factor,
        .query_count = @intCast(config.fri_config.n_queries),
        .log_last_layer_degree_bound = final_log,
        .fri_fold_step = fold,
        .fri_lifting_log_size = null,
        .interaction_pow_bits = 24,
        .commitment_count = 4,
        .sampled_tree_count = 4,
        .fri_tree_count = rounds,
        .decommitment_record_count = 4 + rounds,
        .max_log_degree_bound = degree,
    };
    try geometry.validate();
    const shape = try cairo.witness.resident_geometry.sampleShape(allocator, bundle, .{ columns[0], columns[1], columns[2] });
    defer cairo.witness.resident_geometry.freeSampleShape(allocator, shape);
    var sampled: u64 = 0;
    for (shape) |tree| for (tree) |count| {
        sampled = try std.math.add(u64, sampled, count);
    };
    const capacity = try decommitmentCapacity(bundle, preprocessed_logs, geometry, columns);
    return (compact.CompactProofLayoutV1{
        .interaction_claim_words = try std.math.mul(u32, @intCast(bundle.components.len), 4),
        .sampled_value_words = std.math.cast(u32, try std.math.mul(u64, sampled, 4)) orelse return error.GeometryOverflow,
        .decommitment_capacity_words = capacity,
    }).protocolRuntime(0, geometry, columns);
}

fn finalSpan(bundle: cairo.witness.composition_bundle.Bundle, tree: u32) u32 {
    var end: u32 = 0;
    for (bundle.components) |component| for (component.trace_spans) |span| {
        if (span.tree == tree) end = @max(end, span.end);
    };
    return end;
}

/// Same conservative assembly bounds as the resident allocator. Includes the
/// tallest fixed commitment, which can exceed the FRI evaluation domain.
fn decommitmentCapacity(bundle: cairo.witness.composition_bundle.Bundle, logs: []const u32, geometry: compact.RuntimeProtocolGeometryV1, columns: [4]u32) !u32 {
    const queries: usize = geometry.query_count;
    var words: usize = try cairo.compact_protocol_geometry.minimumDecommitmentWords(geometry.decommitment_record_count, geometry.query_count);
    var heights = [_]u32{ 0, 0, 0, geometry.max_log_degree_bound };
    for (logs) |log| heights[0] = @max(heights[0], log);
    for (bundle.components) |component| {
        heights[1] = @max(heights[1], component.trace_log_size);
        heights[2] = @max(heights[2], component.trace_log_size);
    }
    for (columns, heights) |count, height| words = try sizing.addSize(words, try sizing.traceAssemblyWords(queries, count, height + geometry.log_blowup_factor));
    const fri = try core.fri.geometry.FriGeometry.initRuntime(geometry.max_log_degree_bound + geometry.log_blowup_factor, .{
        .round_count = geometry.fri_tree_count,
        .fold_step = geometry.fri_fold_step,
        .final_log = geometry.log_last_layer_degree_bound + geometry.log_blowup_factor,
        .packed_log = core.fri.geometry.FriGeometry.packed_log,
    });
    for (0..fri.roundCount()) |index| {
        const expanded = try sizing.mul(queries, try sizing.pow2usize(try fri.roundFold(index)));
        words = try sizing.addSize(words, try sizing.friAssemblyWords(queries, expanded, (try fri.evaluationLog(index)) - (try fri.leafLog(index))));
    }
    return std.math.cast(u32, words) orelse error.GeometryOverflow;
}
