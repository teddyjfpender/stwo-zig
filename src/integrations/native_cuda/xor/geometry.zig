//! Fail-closed structural geometry for Native XOR proof-program emission.

const std = @import("std");
const cpu_xor = @import("../../../examples/xor.zig");
const pcs = @import("stwo_core").pcs;

pub const preprocessed_columns: u32 = 2;
pub const main_columns: u32 = 1;
pub const interaction_columns: u32 = 0;
pub const composition_columns: u32 = 8;
pub const sampled_mask_points: u32 = 1 + composition_columns;

pub const Error = error{
    GeometryOverflow,
    InvalidLogSize,
    InvalidStep,
    UnsupportedProtocol,
};

pub const Geometry = struct {
    statement: cpu_xor.Statement,
    protocol: pcs.PcsConfig,
    trace_rows: u64,
    trace_elements: u64,
    commitment_log_rows: u32,
    composition_log_rows: u32,
    fri_tree_count: u32,

    pub fn traceColumnCount(_: Geometry) u32 {
        return preprocessed_columns + main_columns + interaction_columns;
    }
};

pub fn admit(
    statement: cpu_xor.Statement,
    protocol: pcs.PcsConfig,
) Error!Geometry {
    if (statement.log_size == 0 or statement.log_size >= 63)
        return error.InvalidLogSize;
    if (statement.log_step > statement.log_size) return error.InvalidStep;
    if (!supportedProtocol(protocol)) return error.UnsupportedProtocol;

    const trace_rows = @as(u64, 1) << @intCast(statement.log_size);
    const trace_elements = std.math.mul(
        u64,
        trace_rows,
        preprocessed_columns + main_columns + interaction_columns,
    ) catch return error.GeometryOverflow;
    const commitment_log_rows = std.math.add(
        u32,
        statement.log_size,
        protocol.fri_config.log_blowup_factor,
    ) catch return error.GeometryOverflow;
    const composition_log_rows = std.math.add(
        u32,
        statement.log_size,
        1,
    ) catch return error.GeometryOverflow;

    return .{
        .statement = statement,
        .protocol = protocol,
        .trace_rows = trace_rows,
        .trace_elements = trace_elements,
        .commitment_log_rows = commitment_log_rows,
        .composition_log_rows = composition_log_rows,
        .fri_tree_count = statement.log_size,
    };
}

fn supportedProtocol(value: pcs.PcsConfig) bool {
    const fri = value.fri_config;
    return value.pow_bits == 10 and
        fri.log_blowup_factor == 1 and
        fri.log_last_layer_degree_bound == 0 and
        fri.n_queries == 3 and
        fri.fold_step == 1 and
        value.lifting_log_size == null;
}

test "XOR geometry preserves exact CPU tree shape" {
    const shape = try admit(
        .{ .log_size = 16, .log_step = 3, .offset = 5 },
        pcs.PcsConfig.default(),
    );
    try std.testing.expectEqual(@as(u64, 1 << 16), shape.trace_rows);
    try std.testing.expectEqual(@as(u64, 3 * (1 << 16)), shape.trace_elements);
    try std.testing.expectEqual(@as(u32, 3), shape.traceColumnCount());
    try std.testing.expectEqual(@as(u32, 17), shape.commitment_log_rows);
    try std.testing.expectEqual(@as(u32, 16), shape.fri_tree_count);
}

test "XOR geometry rejects statements and protocols outside parity" {
    const protocol = pcs.PcsConfig.default();
    try std.testing.expectError(
        error.InvalidLogSize,
        admit(.{ .log_size = 0, .log_step = 0, .offset = 0 }, protocol),
    );
    try std.testing.expectError(
        error.InvalidStep,
        admit(.{ .log_size = 5, .log_step = 6, .offset = 0 }, protocol),
    );
    var changed = protocol;
    changed.pow_bits += 1;
    try std.testing.expectError(
        error.UnsupportedProtocol,
        admit(.{ .log_size = 5, .log_step = 2, .offset = 3 }, changed),
    );
}
