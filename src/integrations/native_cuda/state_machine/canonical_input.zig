//! Canonical resident encodings for the state-machine request.

const geometry_mod = @import("geometry.zig");
const pcs = @import("stwo_core").pcs;
const cpu_state_machine = @import("../../../examples/state_machine/input.zig");

pub const protocol_word_count: usize = 4;
pub const statement_word_count = geometry_mod.statement_word_count;

pub fn protocolWords(value: pcs.PcsConfig) [protocol_word_count]u32 {
    return .{
        value.pow_bits,
        value.fri_config.log_blowup_factor,
        @intCast(value.fri_config.n_queries),
        value.fri_config.log_last_layer_degree_bound,
    };
}

/// The device fills final state and claimed sums after drawing relation
/// elements. The four request words are immutable inputs to that derivation.
pub fn statementWords(
    value: cpu_state_machine.Request,
) [statement_word_count]u32 {
    return .{
        value.log_n_rows,
        value.log_n_rows - 1,
        value.initial_state[0].toU32(),
        value.initial_state[1].toU32(),
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    };
}

pub fn coefficientLogSizes(
    geometry: geometry_mod.Geometry,
) [geometry_mod.coefficient_log_count]u32 {
    return [_]u32{geometry.statement.log_n_rows} **
        geometry_mod.coefficient_log_count;
}

test "state-machine request words reserve challenge-derived statement output" {
    const std = @import("std");
    const M31 = @import("stwo_core").fields.m31.M31;
    const words = statementWords(.{
        .log_n_rows = 16,
        .initial_state = .{ M31.fromU64(9), M31.fromU64(3) },
    });
    try std.testing.expectEqualSlices(
        u32,
        &.{ 16, 15, 9, 3 },
        words[0..4],
    );
    try std.testing.expect(std.mem.allEqual(u32, words[4..], 0));
    const protocol = protocolWords(pcs.PcsConfig.default());
    try std.testing.expectEqualSlices(u32, &.{ 10, 1, 3, 0 }, &protocol);
}
