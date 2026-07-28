//! Canonical resident encodings for the state-machine request.

const geometry_mod = @import("geometry.zig");
const pcs = @import("stwo_core").pcs;
const cpu_state_machine = @import("stwo_native_examples").backend_support.state_machine.input;

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

pub fn transcriptStatementWords(
    value: cpu_state_machine.Request,
) [geometry_mod.transcript_statement_word_count]u32 {
    return .{
        value.log_n_rows,
        0,
        value.log_n_rows - 1,
        0,
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
    try std.testing.expectEqualSlices(
        u32,
        &.{ 16, 0, 15, 0 },
        &transcriptStatementWords(.{
            .log_n_rows = 16,
            .initial_state = .{ M31.fromU64(9), M31.fromU64(3) },
        }),
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

test "resident Statement0 words exactly match two CPU mixU64 calls" {
    const statement = @import("stwo_native_examples").backend_support.state_machine.statement;
    const request = cpu_state_machine.Request{
        .log_n_rows = 16,
        .initial_state = .{
            @import("stwo_core").fields.m31.M31.fromU64(9),
            @import("stwo_core").fields.m31.M31.fromU64(3),
        },
    };
    var expected = statement.Channel{};
    statement.mixStatement0(
        &expected,
        .{ .n = 16, .m = 15 },
    );

    const words = transcriptStatementWords(request);
    var actual = statement.Channel{};
    actual.mixU32s(words[0..2]);
    actual.mixU32s(words[2..4]);
    try @import("std").testing.expectEqualSlices(
        u8,
        &expected.digestBytes(),
        &actual.digestBytes(),
    );
}
