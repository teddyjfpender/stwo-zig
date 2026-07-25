//! Canonical resident word encodings for the Plonk public request.

const geometry_mod = @import("geometry.zig");
const pcs = @import("stwo_core").pcs;
const cpu_input = @import("../../../examples/plonk_logup/input.zig");

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
    value: cpu_input.Request,
) [statement_word_count]u32 {
    return .{value.log_n_rows};
}

pub fn coefficientLogSizes(
    geometry: geometry_mod.Geometry,
) [geometry_mod.sampled_mask_points]u32 {
    return [_]u32{geometry.statement.log_n_rows} **
        geometry_mod.sampled_mask_points;
}

test "Plonk LogUp request words preserve the public row log" {
    const std = @import("std");
    const words = statementWords(.{ .log_n_rows = 16 });
    try std.testing.expectEqualSlices(
        u32,
        &.{16},
        &words,
    );
    const protocol = protocolWords(pcs.PcsConfig.default());
    try std.testing.expectEqualSlices(u32, &.{ 10, 1, 3, 0 }, &protocol);
}
