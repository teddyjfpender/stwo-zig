//! Fail-closed geometry for the exact Plonk/LogUp proof protocol.

const std = @import("std");
const cpu_input = @import("../../../examples/plonk_logup/input.zig");
const pcs = @import("stwo_core").pcs;

pub const preprocessed_columns: u32 = 4;
pub const main_columns: u32 = 4;
pub const interaction_columns: u32 = 8;
pub const composition_columns: u32 = 8;
pub const source_columns: u32 = preprocessed_columns +
    main_columns + interaction_columns + composition_columns;
pub const sampled_mask_points: u32 = 28;
pub const max_log_size: u32 = 29;

pub const Error = cpu_input.Error || error{
    GeometryOverflow,
    UnsupportedProtocol,
};

pub const Geometry = struct {
    statement: cpu_input.Request,
    protocol: pcs.PcsConfig,
    trace_rows: u64,
    trace_elements: u64,
    commitment_log_rows: u32,
    fri_tree_count: u32,
    commitment_rows: usize,
    committed_tree_count: usize,
    decommitted_trace_tree_count: usize,
    decommit_tree_count: usize,
    last_layer_domain_rows: usize,

    pub fn traceColumnCount(_: Geometry) u32 {
        return preprocessed_columns + main_columns + interaction_columns;
    }

    pub fn traceLogSize(self: Geometry) u32 {
        return self.statement.log_n_rows;
    }

    pub fn queryLogSize(self: Geometry) u32 {
        return self.commitment_log_rows;
    }

    pub fn powBits(self: Geometry) u32 {
        return self.protocol.pow_bits;
    }

    pub fn lastLayerDegreeBound(self: Geometry) u32 {
        return self.protocol.fri_config.log_last_layer_degree_bound;
    }

    pub fn traceRowCount(self: Geometry) Error!usize {
        return std.math.cast(usize, self.trace_rows) orelse
            error.GeometryOverflow;
    }
};

pub fn admit(
    statement: cpu_input.Request,
    protocol: pcs.PcsConfig,
) Error!Geometry {
    try cpu_input.validate(statement);
    if (statement.log_n_rows > max_log_size)
        return error.InvalidLogSize;
    if (!supportedProtocol(protocol)) return error.UnsupportedProtocol;

    const trace_rows = @as(u64, 1) << @intCast(statement.log_n_rows);
    const trace_elements = std.math.mul(
        u64,
        trace_rows,
        preprocessed_columns + main_columns + interaction_columns,
    ) catch return error.GeometryOverflow;
    const commitment_log_rows = std.math.add(
        u32,
        statement.log_n_rows,
        protocol.fri_config.log_blowup_factor,
    ) catch return error.GeometryOverflow;
    const commitment_rows = std.math.cast(
        usize,
        @as(u64, 1) << @intCast(commitment_log_rows),
    ) orelse return error.GeometryOverflow;
    const fri_tree_count = statement.log_n_rows;
    const decommitted_trace_tree_count: usize = 4;
    const decommit_tree_count = std.math.add(
        usize,
        decommitted_trace_tree_count,
        fri_tree_count,
    ) catch return error.GeometryOverflow;
    return .{
        .statement = statement,
        .protocol = protocol,
        .trace_rows = trace_rows,
        .trace_elements = trace_elements,
        .commitment_log_rows = commitment_log_rows,
        .fri_tree_count = fri_tree_count,
        .commitment_rows = commitment_rows,
        .committed_tree_count = 4,
        .decommitted_trace_tree_count = decommitted_trace_tree_count,
        .decommit_tree_count = decommit_tree_count,
        .last_layer_domain_rows = 2,
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

test "exact Plonk geometry retains interaction and composition trees" {
    const value = try admit(
        .{ .log_n_rows = 14 },
        pcs.PcsConfig.default(),
    );
    try std.testing.expectEqual(@as(u32, 16), value.traceColumnCount());
    try std.testing.expectEqual(@as(usize, 4), value.committed_tree_count);
    try std.testing.expectEqual(@as(u32, 28), sampled_mask_points);
    try std.testing.expectEqual(@as(u32, 24), source_columns);
}
