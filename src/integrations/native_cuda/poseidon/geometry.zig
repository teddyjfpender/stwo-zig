//! Fail-closed Native Poseidon proof geometry from the public statement.

const std = @import("std");
const cpu_poseidon = @import("../../../examples/poseidon.zig");
const poseidon_input = @import("../../../examples/poseidon/input.zig");
const pcs = @import("stwo_core").pcs;

pub const preprocessed_columns: u32 = 0;
pub const composition_columns: u32 = 8;
pub const composition_coordinates: u32 = 4;
pub const max_log_n_rows: u32 = 30;

pub const Error = poseidon_input.Error || error{
    GeometryOverflow,
    UnsupportedProtocol,
};

pub const Request = struct {
    statement: cpu_poseidon.Statement,
    protocol: pcs.PcsConfig,
};

pub const Geometry = struct {
    statement: cpu_poseidon.Statement,
    protocol: pcs.PcsConfig,
    log_n_rows: u32,
    trace_rows: u64,
    row_count: u32,
    main_columns: u32,
    main_cells: u64,
    trace_cells: usize,
    composition_rows: usize,
    sampled_value_count: usize,
    commitment_log_rows: u32,
    composition_log_rows: u32,
    commitment_rows: usize,
    fri_tree_count: u32,
    committed_tree_count: usize,
    decommitted_trace_tree_count: usize,
    decommit_tree_count: usize,
    last_layer_domain_rows: usize,

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
    statement: cpu_poseidon.Statement,
    protocol: pcs.PcsConfig,
) Error!Geometry {
    const log_n_rows = try poseidon_input.logNRows(statement);
    if (log_n_rows > max_log_n_rows) return error.InvalidLogNInstances;
    if (!supportedProtocol(protocol)) return error.UnsupportedProtocol;

    const main_columns = std.math.cast(
        u32,
        poseidon_input.N_COLUMNS,
    ) orelse return error.GeometryOverflow;
    const row_count = @as(u32, 1) << @intCast(log_n_rows);
    const trace_rows: u64 = row_count;
    const main_cells = std.math.mul(
        u64,
        trace_rows,
        main_columns,
    ) catch return error.GeometryOverflow;
    const trace_cells = std.math.cast(usize, main_cells) orelse
        return error.GeometryOverflow;
    const sampled_value_count = std.math.add(
        usize,
        poseidon_input.N_COLUMNS,
        composition_columns,
    ) catch return error.GeometryOverflow;
    const commitment_log_rows = std.math.add(
        u32,
        log_n_rows,
        protocol.fri_config.log_blowup_factor,
    ) catch return error.GeometryOverflow;
    const composition_log_rows = std.math.add(
        u32,
        log_n_rows,
        1,
    ) catch return error.GeometryOverflow;
    const commitment_rows_u64 =
        @as(u64, 1) << @intCast(commitment_log_rows);
    const commitment_rows = std.math.cast(
        usize,
        commitment_rows_u64,
    ) orelse return error.GeometryOverflow;
    const fri_tree_count = log_n_rows;
    const decommitted_trace_tree_count: usize = 2;
    const decommit_tree_count = std.math.add(
        usize,
        decommitted_trace_tree_count,
        fri_tree_count,
    ) catch return error.GeometryOverflow;

    return .{
        .statement = statement,
        .protocol = protocol,
        .log_n_rows = log_n_rows,
        .trace_rows = trace_rows,
        .row_count = row_count,
        .main_columns = main_columns,
        .main_cells = main_cells,
        .trace_cells = trace_cells,
        .composition_rows = std.math.mul(
            usize,
            std.math.cast(usize, trace_rows) orelse
                return error.GeometryOverflow,
            2,
        ) catch return error.GeometryOverflow,
        .sampled_value_count = sampled_value_count,
        .commitment_log_rows = commitment_log_rows,
        .composition_log_rows = composition_log_rows,
        .commitment_rows = commitment_rows,
        .fri_tree_count = fri_tree_count,
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

test "Poseidon geometry seals complete proof cardinalities" {
    const geometry = try admit(
        .{ .log_n_instances = 13 },
        pcs.PcsConfig.default(),
    );
    try std.testing.expectEqual(@as(u32, 10), geometry.log_n_rows);
    try std.testing.expectEqual(@as(u32, 1024), geometry.row_count);
    try std.testing.expectEqual(@as(u32, 1264), geometry.main_columns);
    try std.testing.expectEqual(@as(u64, 1_294_336), geometry.main_cells);
    try std.testing.expectEqual(@as(usize, 1272), geometry.sampled_value_count);
    try std.testing.expectEqual(@as(u32, 11), geometry.commitment_log_rows);
    try std.testing.expectEqual(@as(usize, 3), geometry.committed_tree_count);
    try std.testing.expectEqual(@as(usize, 12), geometry.decommit_tree_count);
}

test "Poseidon geometry rejects statement and protocol drift" {
    const protocol = pcs.PcsConfig.default();
    try std.testing.expectError(
        error.InvalidLogNInstances,
        admit(.{ .log_n_instances = 2 }, protocol),
    );
    var changed = protocol;
    changed.pow_bits += 1;
    try std.testing.expectError(
        error.UnsupportedProtocol,
        admit(.{ .log_n_instances = 13 }, changed),
    );
}
