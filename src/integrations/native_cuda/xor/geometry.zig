//! Fail-closed geometry for the exact Native XOR truth-table LogUp protocol.

const std = @import("std");
const cpu_xor = @import("stwo_native_examples").xor;
const pcs = @import("stwo_core").pcs;

pub const preprocessed_columns: u32 = 7;
pub const main_columns: u32 = 4;
pub const interaction_columns: u32 = 4;
pub const composition_columns: u32 = 8;
pub const statement_word_count: usize = 4;
pub const terminal_statement_words: usize = 4;
pub const public_statement_word_count: usize =
    statement_word_count + terminal_statement_words;
pub const source_columns: u32 = preprocessed_columns +
    main_columns + interaction_columns + composition_columns;
pub const resident_evaluation_columns: u32 = source_columns;
pub const sampled_source_column_offset: u32 = 0;
pub const sampled_source_column_count: u32 = source_columns;
// Current-only preprocessed/main and composition samples, plus current/previous
// samples for each of the four interaction coordinates.
pub const sampled_mask_points: u32 = preprocessed_columns +
    main_columns + 2 * interaction_columns + composition_columns;
// The quotient/commitment domain is one bit larger and the current resident
// CUDA proof kernels represent row counts as u32.
pub const min_log_size: u32 = 3;
pub const max_log_size: u32 = 29;

pub const Error = cpu_xor.Error || error{
    GeometryOverflow,
    UnsupportedProtocol,
};

pub const Request = struct {
    statement: cpu_xor.Statement,
    protocol: pcs.PcsConfig,
};

pub const Geometry = struct {
    statement: cpu_xor.Statement,
    protocol: pcs.PcsConfig,
    trace_rows: u64,
    trace_elements: u64,
    preprocessed_cells: u64,
    main_cells: u64,
    interaction_cells: u64,
    committed_cells: u64,
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
        return self.statement.log_size;
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

/// Interaction coefficients share one uniform compact N-word stride.
pub fn interactionCoefficientStride(geometry: Geometry) usize {
    return @intCast(geometry.trace_rows);
}

pub fn admit(
    statement: cpu_xor.Statement,
    protocol: pcs.PcsConfig,
) Error!Geometry {
    try cpu_xor.validateStatement(statement);
    if (statement.log_size < min_log_size or
        statement.log_size > max_log_size)
    {
        return error.InvalidLogSize;
    }
    if (!supportedProtocol(protocol)) return error.UnsupportedProtocol;

    const trace_rows = @as(u64, 1) << @intCast(statement.log_size);
    const preprocessed_cells = try cells(trace_rows, preprocessed_columns);
    const main_cells = try cells(trace_rows, main_columns);
    const interaction_cells = try cells(trace_rows, interaction_columns);
    const trace_elements = std.math.add(
        u64,
        std.math.add(u64, preprocessed_cells, main_cells) catch
            return error.GeometryOverflow,
        interaction_cells,
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
    const commitment_rows_u64 =
        @as(u64, 1) << @intCast(commitment_log_rows);
    const commitment_rows = std.math.cast(
        usize,
        commitment_rows_u64,
    ) orelse return error.GeometryOverflow;
    const committed_tree_count: usize = 4;
    const decommitted_trace_tree_count: usize = 4;
    const fri_tree_count: u32 = statement.log_size;
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
        .preprocessed_cells = preprocessed_cells,
        .main_cells = main_cells,
        .interaction_cells = interaction_cells,
        .committed_cells = trace_elements,
        .commitment_log_rows = commitment_log_rows,
        .composition_log_rows = composition_log_rows,
        .fri_tree_count = fri_tree_count,
        .commitment_rows = commitment_rows,
        .committed_tree_count = committed_tree_count,
        .decommitted_trace_tree_count = decommitted_trace_tree_count,
        .decommit_tree_count = decommit_tree_count,
        .last_layer_domain_rows = 2,
    };
}

fn cells(rows: u64, columns: u32) Error!u64 {
    return std.math.mul(u64, rows, columns) catch
        error.GeometryOverflow;
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

test "XOR geometry preserves exact four-tree CPU shape" {
    const shape = try admit(
        .{ .log_size = 16, .log_step = 3, .offset = 5 },
        pcs.PcsConfig.default(),
    );
    try std.testing.expectEqual(@as(u64, 1 << 16), shape.trace_rows);
    try std.testing.expectEqual(@as(u64, 15 * (1 << 16)), shape.trace_elements);
    try std.testing.expectEqual(@as(u32, 15), shape.traceColumnCount());
    try std.testing.expectEqual(@as(u32, 17), shape.commitment_log_rows);
    try std.testing.expectEqual(@as(u32, 16), shape.fri_tree_count);
    try std.testing.expectEqual(@as(usize, 1 << 17), shape.commitment_rows);
    try std.testing.expectEqual(@as(usize, 4), shape.committed_tree_count);
    try std.testing.expectEqual(
        @as(usize, 4),
        shape.decommitted_trace_tree_count,
    );
    try std.testing.expectEqual(@as(usize, 20), shape.decommit_tree_count);
    try std.testing.expectEqual(@as(usize, 2), shape.last_layer_domain_rows);
    try std.testing.expectEqual(@as(u32, 27), sampled_mask_points);
    try std.testing.expectEqual(@as(u32, 23), source_columns);
    try std.testing.expectEqual(
        try shape.traceRowCount(),
        interactionCoefficientStride(shape),
    );
}

test "XOR geometry rejects statements and protocols outside parity" {
    const protocol = pcs.PcsConfig.default();
    try std.testing.expectError(
        error.InvalidLogSize,
        admit(.{ .log_size = 1, .log_step = 0, .offset = 0 }, protocol),
    );
    try std.testing.expectError(
        error.InvalidLogSize,
        admit(
            .{ .log_size = min_log_size - 1, .log_step = 0, .offset = 0 },
            protocol,
        ),
    );
    try std.testing.expectError(
        error.InvalidLogSize,
        admit(
            .{ .log_size = max_log_size + 1, .log_step = 0, .offset = 0 },
            protocol,
        ),
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
