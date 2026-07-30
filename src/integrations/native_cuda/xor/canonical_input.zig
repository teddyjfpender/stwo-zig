//! Canonical resident word encodings for the XOR public request.

const geometry_mod = @import("geometry.zig");
const pcs = @import("stwo_core").pcs;
const cpu_xor = @import("stwo_native_examples").xor;

pub const protocol_word_count: usize = 4;
pub const statement_word_count: usize = geometry_mod.statement_word_count;

pub fn protocolWords(value: pcs.PcsConfig) [protocol_word_count]u32 {
    return .{
        value.pow_bits,
        value.fri_config.log_blowup_factor,
        @intCast(value.fri_config.n_queries),
        value.fri_config.log_last_layer_degree_bound,
    };
}

pub fn statementWords(
    value: cpu_xor.Statement,
) [statement_word_count]u32 {
    const offset: u64 = @intCast(value.offset);
    return .{
        value.log_size,
        value.log_step,
        @truncate(offset),
        @truncate(offset >> 32),
    };
}

pub fn coefficientLogSizes(
    geometry: geometry_mod.Geometry,
) [geometry_mod.sampled_mask_points]u32 {
    return [_]u32{geometry.statement.log_size} **
        geometry_mod.sampled_mask_points;
}

test "XOR request words preserve the full public statement" {
    const std = @import("std");
    const words = statementWords(.{
        .log_size = 16,
        .log_step = 3,
        .offset = 0xfeed_face_1234_5678,
    });
    try std.testing.expectEqualSlices(
        u32,
        &.{ 16, 3, 0x1234_5678, 0xfeed_face },
        &words,
    );
    const protocol = protocolWords(pcs.PcsConfig.default());
    try std.testing.expectEqualSlices(u32, &.{ 10, 1, 3, 0 }, &protocol);
}
