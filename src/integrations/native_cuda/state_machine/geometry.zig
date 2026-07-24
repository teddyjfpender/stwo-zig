//! Fail-closed geometry for the Native state-machine proof program.

const std = @import("std");
const cpu_state_machine = @import("../../../examples/state_machine/input.zig");
const pcs = @import("stwo_core").pcs;

pub const preprocessed_columns: u32 = 1;
pub const main_columns: u32 = 2;
pub const interaction_columns: u32 = 0;
pub const composition_columns: u32 = 8;
pub const sampled_mask_points: u32 = main_columns + composition_columns;
pub const resident_evaluation_columns: u32 =
    preprocessed_columns + main_columns + composition_columns;
pub const sampled_source_column_offset: u32 = preprocessed_columns;
pub const coefficient_log_count: u32 = resident_evaluation_columns;
pub const statement_word_count: usize = 14;
pub const max_log_size: u32 = 29;

pub const Error = cpu_state_machine.Error || error{
    GeometryOverflow,
    UnsupportedProtocol,
};

pub const Request = struct {
    statement: cpu_state_machine.Request,
    protocol: pcs.PcsConfig,
};

pub const Geometry = struct {
    statement: cpu_state_machine.Request,
    protocol: pcs.PcsConfig,
    trace_rows: u64,
    trace_elements: u64,
    commitment_log_rows: u32,
    composition_log_rows: u32,
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
    statement: cpu_state_machine.Request,
    protocol: pcs.PcsConfig,
) Error!Geometry {
    try cpu_state_machine.validate(statement);
    if (statement.log_n_rows > max_log_size)
        return error.InvalidLogSize;
    if (!supportedProtocol(protocol)) return error.UnsupportedProtocol;

    const trace_rows = @as(u64, 1) << @intCast(statement.log_n_rows);
    const trace_elements = std.math.mul(
        u64,
        trace_rows,
        preprocessed_columns + main_columns,
    ) catch return error.GeometryOverflow;
    const commitment_log_rows = std.math.add(
        u32,
        statement.log_n_rows,
        protocol.fri_config.log_blowup_factor,
    ) catch return error.GeometryOverflow;
    const commitment_rows_u64 =
        @as(u64, 1) << @intCast(commitment_log_rows);
    const commitment_rows = std.math.cast(
        usize,
        commitment_rows_u64,
    ) orelse return error.GeometryOverflow;
    const fri_tree_count = statement.log_n_rows;
    const decommitted_trace_tree_count: usize = 3;
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
        .composition_log_rows = std.math.add(
            u32,
            statement.log_n_rows,
            1,
        ) catch return error.GeometryOverflow,
        .fri_tree_count = fri_tree_count,
        .commitment_rows = commitment_rows,
        .committed_tree_count = 3,
        .decommitted_trace_tree_count = decommitted_trace_tree_count,
        .decommit_tree_count = decommit_tree_count,
        .last_layer_domain_rows = 2,
    };
}

pub fn admitRequest(request: Request) Error!Geometry {
    return admit(request.statement, request.protocol);
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

test "state-machine geometry distinguishes committed and sampled columns" {
    const M31 = @import("stwo_core").fields.m31.M31;
    const shape = try admit(
        .{
            .log_n_rows = 16,
            .initial_state = .{ M31.fromU64(9), M31.fromU64(3) },
        },
        pcs.PcsConfig.default(),
    );
    try std.testing.expectEqual(@as(u64, 1 << 16), shape.trace_rows);
    try std.testing.expectEqual(@as(u64, 3 * (1 << 16)), shape.trace_elements);
    try std.testing.expectEqual(@as(u32, 3), shape.traceColumnCount());
    try std.testing.expectEqual(@as(u32, 10), sampled_mask_points);
    try std.testing.expectEqual(@as(u32, 11), resident_evaluation_columns);
    try std.testing.expectEqual(@as(u32, 17), shape.commitment_log_rows);
    try std.testing.expectEqual(@as(usize, 19), shape.decommit_tree_count);
}

test "state-machine geometry rejects unsupported protocol and row bounds" {
    const M31 = @import("stwo_core").fields.m31.M31;
    const statement = cpu_state_machine.Request{
        .log_n_rows = 16,
        .initial_state = .{ M31.fromU64(9), M31.fromU64(3) },
    };
    var changed = pcs.PcsConfig.default();
    changed.pow_bits += 1;
    try std.testing.expectError(
        error.UnsupportedProtocol,
        admit(statement, changed),
    );
    var oversized = statement;
    oversized.log_n_rows = max_log_size + 1;
    try std.testing.expectError(
        error.InvalidLogSize,
        admit(oversized, pcs.PcsConfig.default()),
    );
}
