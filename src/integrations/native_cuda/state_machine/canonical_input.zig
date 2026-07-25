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

/// Exact Statement0 words mixed between the empty preprocessed and main
/// commitments. Public initial state remains request metadata, as it does in
/// the pinned CPU/Rust transcript.
pub fn statementWords(
    value: cpu_state_machine.Request,
) [statement_word_count]u32 {
    return .{
        value.log_n_rows,
        value.log_n_rows - 1,
    };
}

pub fn coefficientLogSizes(
    geometry: geometry_mod.Geometry,
) [geometry_mod.coefficient_log_count]u32 {
    const n = geometry.statement.log_n_rows;
    const m = n - 1;
    return .{
        // Main: x state then y state.
        n, n, m, m,
        // Interaction: x cumulative QM31 then y cumulative QM31.
        n, n, n, n,
        m, m, m, m,
        // Composition split coordinates all live at the maximum log.
        n, n, n, n,
        n, n, n, n,
    };
}

test "State Machine v2 ingress preserves mixed-height column logs" {
    const std = @import("std");
    const M31 = @import("stwo_core").fields.m31.M31;
    const words = statementWords(.{
        .log_n_rows = 16,
        .initial_state = .{ M31.fromU64(9), M31.fromU64(3) },
    });
    try std.testing.expectEqualSlices(
        u32,
        &.{ 16, 15 },
        &words,
    );
    const logs = coefficientLogSizes(try geometry_mod.admit(
        .{
            .log_n_rows = 16,
            .initial_state = .{ M31.fromU64(9), M31.fromU64(3) },
        },
        pcs.PcsConfig.default(),
    ));
    try std.testing.expectEqualSlices(
        u32,
        &.{ 16, 16, 15, 15 },
        logs[0..4],
    );
    try std.testing.expectEqualSlices(
        u32,
        &.{ 16, 16, 16, 16, 15, 15, 15, 15 },
        logs[4..12],
    );
    const protocol = protocolWords(pcs.PcsConfig.default());
    try std.testing.expectEqualSlices(u32, &.{ 10, 1, 3, 0 }, &protocol);
}
