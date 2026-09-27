//! Value-free original STARK/PCS transcript operation grammar.
//! This describes routing and draw consumption, never witness assignments.
const std = @import("std");
const core = @import("stwo_core");
const sequence = @import("blake3_transcript_witness.zig");
const Deep = @import("pcs_deep_circuit.zig");
const Fri = @import("fri_verifier_circuit.zig");
const native = @import("blake3_native_transcript.zig");
pub const Operation = union(enum) {
    commitment: struct { slot: usize, source: sequence.Caller },
    secure: struct { role: sequence.OutputRole, consumption: enum { one, two } },
    claim_frame: struct { tag: [3]u32, count: usize, source: sequence.Caller },
    sampled_values: struct { count: usize, source: sequence.Caller },
    fri_root: struct { layer: usize, source: sequence.Caller },
    terminal_coefficients: struct { count: usize, source: sequence.Caller },
    pow: struct { bits: u32, source: sequence.Caller },
    nonce: sequence.Caller,
    queries: struct { count: usize, log_domain_size: u32 },
};
/// Exact original suffix after trace/interaction commitments. Both closed
/// parents and native word families select this same operation order.
/// Profiles/config/count are independently reconstructed by the caller.
pub fn appendPcsSuffix(a: std.mem.Allocator, out: *std.ArrayList(Operation), config: core.pcs.PcsConfig, deep: Deep.Profile, fri: Fri.Profile, commitments: usize) !void {
    try deep.validate();
    try fri.validate();
    if (deep.trees.len != commitments or deep.lifting_log_size != fri.lifting_log_size or
        deep.query_count != fri.query_count or deep.query_count != config.fri_config.n_queries or
        deep.log_blowup_factor != config.fri_config.log_blowup_factor or
        fri.log_blowup_factor != config.fri_config.log_blowup_factor or
        fri.log_last_layer_degree_bound != config.fri_config.log_last_layer_degree_bound or
        config.pow_bits > 256 or config.fri_config.fold_step == 0 or config.fri_config.fold_step > Fri.MAX_FOLD_STEP)
        return error.UntrustedFixedPcsOperationGeometry;
    var remaining = fri.lifting_log_size;
    const terminal = try std.math.add(u32, fri.log_blowup_factor, fri.log_last_layer_degree_bound);
    for (fri.fold_widths) |width| {
        if (remaining <= terminal or width != @as(u32, 1) << @intCast(@min(config.fri_config.fold_step, remaining - terminal)))
            return error.UntrustedFixedPcsOperationGeometry;
        remaining -= std.math.log2_int(u32, width);
    }
    if (remaining != terminal) return error.UntrustedFixedPcsOperationGeometry;
    const slots = try native.suffixRootSlots(commitments);
    var pending: std.ArrayList(Operation) = .empty;
    defer pending.deinit(a);
    try pending.append(a, .{ .secure = .{ .role = .composition, .consumption = .one } });
    try pending.append(a, .{ .commitment = .{ .slot = commitments - 1, .source = slots.composition } });
    try pending.append(a, .{ .secure = .{ .role = .oods, .consumption = .one } });
    try pending.append(a, .{ .sampled_values = .{ .count = try deep.sampleCount(), .source = native.SAMPLE_SOURCE } });
    try pending.append(a, .{ .secure = .{ .role = .deep, .consumption = .one } });
    for (fri.fold_widths, 0..) |_, layer| {
        try pending.append(a, .{ .fri_root = .{ .layer = layer, .source = .{ .circuit = slots.fri.circuit, .first_wire = try std.math.add(u32, slots.fri.first_wire, try std.math.mul(u32, @intCast(layer), 8)) } } });
        try pending.append(a, .{ .secure = .{ .role = .{ .fri = layer }, .consumption = .one } });
    }
    try pending.append(a, .{ .terminal_coefficients = .{ .count = try fri.lastLayerCoefficientCount(), .source = native.TERMINAL_SOURCE } });
    const nonce_source = sequence.Caller{ .circuit = 4_100_001, .first_wire = 2 };
    try pending.append(a, .{ .pow = .{ .bits = config.pow_bits, .source = nonce_source } });
    try pending.append(a, .{ .nonce = nonce_source });
    try pending.append(a, .{ .queries = .{ .count = config.fri_config.n_queries, .log_domain_size = fri.lifting_log_size } });
    // All allocations and geometry checks precede mutation of caller inventory.
    try out.appendSlice(a, pending.items);
}
