//! Fail-closed Native CUDA admission for the wide-Fibonacci statement.

const std = @import("std");

pub const min_log_n_rows: u32 = 3;
pub const max_log_n_rows: u32 = 22;
pub const max_sequence_len: u32 = 128;
pub const max_queries: usize = 256;
pub const composition_coordinate_count: usize = 4;
pub const composition_column_count: usize = 2 * composition_coordinate_count;

pub const Error = error{
    GeometryOverflow,
    UnsupportedLogSize,
    UnsupportedProtocol,
    UnsupportedQueryCount,
    UnsupportedSequenceLength,
};

pub const Statement = struct {
    log_n_rows: u32,
    sequence_len: u32,
};

/// Deliberately mirrors only the protocol fields consumed by this integration.
/// The product adapter must construct it from `stwo_core.pcs.PcsConfig`; this
/// type is not another source of protocol defaults.
pub const Protocol = struct {
    pow_bits: u32,
    log_blowup_factor: u32,
    log_last_layer_degree_bound: u32,
    n_queries: usize,
    fold_step: u32,
    lifting_log_size: ?u32,
};

pub const Request = struct {
    statement: Statement,
    protocol: Protocol,
};

/// All sizes are logical element counts, not byte guesses. Backing-plan code
/// must apply the exact ABI element width when constructing arena slots.
pub const Geometry = struct {
    statement: Statement,
    protocol: Protocol,
    trace_rows: usize,
    trace_cells: usize,
    composition_rows: usize,
    commitment_rows: usize,
    main_columns: usize,
    sampled_value_count: usize,
    committed_tree_count: usize,
    decommitted_trace_tree_count: usize,
    fri_tree_count: usize,
    decommit_tree_count: usize,
    last_layer_domain_rows: usize,

    pub fn queryLogSize(self: Geometry) u32 {
        return self.statement.log_n_rows + self.protocol.log_blowup_factor;
    }
};

/// Native CUDA v1 intentionally admits the exact pinned-Rust protocol used by
/// the current wide-Fibonacci parity lane. Broader FRI/lifting configurations
/// remain admission errors until their byte-identical proof vectors land.
pub fn admit(request: Request) Error!Geometry {
    const statement = request.statement;
    const protocol = request.protocol;
    if (statement.log_n_rows < min_log_n_rows or
        statement.log_n_rows > max_log_n_rows)
    {
        return error.UnsupportedLogSize;
    }
    if (statement.sequence_len < 2 or
        statement.sequence_len > max_sequence_len)
    {
        return error.UnsupportedSequenceLength;
    }
    if (protocol.n_queries == 0 or protocol.n_queries > max_queries)
        return error.UnsupportedQueryCount;
    if (protocol.log_blowup_factor != 1 or
        protocol.log_last_layer_degree_bound != 0 or
        protocol.fold_step != 1 or
        protocol.lifting_log_size != null or
        protocol.pow_bits > 32)
    {
        return error.UnsupportedProtocol;
    }

    const trace_rows = try pow2(statement.log_n_rows);
    const trace_cells = try mul(trace_rows, statement.sequence_len);
    const composition_rows = try mul(trace_rows, 2);
    // Both the main and eight split-composition columns commit at log N + 1:
    // main gains one blowup bit; composition is split once before commitment.
    const commitment_rows = composition_rows;
    const sampled_value_count = try add(
        statement.sequence_len,
        composition_column_count,
    );
    // The empty preprocessed commitment remains transcript-visible, but has no
    // queried values and therefore does not enter the decommitment bundle.
    const committed_tree_count: usize = 3;
    const decommitted_trace_tree_count: usize = 2;

    // Quotient degree log N folds once from circle to line and then one level
    // per committed FRI tree until the degree-zero last layer.
    const fri_tree_count: usize = statement.log_n_rows;
    return .{
        .statement = statement,
        .protocol = protocol,
        .trace_rows = trace_rows,
        .trace_cells = trace_cells,
        .composition_rows = composition_rows,
        .commitment_rows = commitment_rows,
        .main_columns = statement.sequence_len,
        .sampled_value_count = sampled_value_count,
        .committed_tree_count = committed_tree_count,
        .decommitted_trace_tree_count = decommitted_trace_tree_count,
        .fri_tree_count = fri_tree_count,
        .decommit_tree_count = try add(
            decommitted_trace_tree_count,
            fri_tree_count,
        ),
        .last_layer_domain_rows = try pow2(
            protocol.log_blowup_factor +
                protocol.log_last_layer_degree_bound,
        ),
    };
}

fn pow2(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return error.GeometryOverflow;
    return @as(usize, 1) << @intCast(log_size);
}

fn add(left: anytype, right: anytype) Error!usize {
    const lhs = std.math.cast(usize, left) orelse
        return error.GeometryOverflow;
    const rhs = std.math.cast(usize, right) orelse
        return error.GeometryOverflow;
    return std.math.add(usize, lhs, rhs) catch error.GeometryOverflow;
}

fn mul(left: anytype, right: anytype) Error!usize {
    const lhs = std.math.cast(usize, left) orelse
        return error.GeometryOverflow;
    const rhs = std.math.cast(usize, right) orelse
        return error.GeometryOverflow;
    return std.math.mul(usize, lhs, rhs) catch error.GeometryOverflow;
}

test "default wide-Fibonacci geometry matches the pinned proof shape" {
    const geometry = try admit(.{
        .statement = .{ .log_n_rows = 14, .sequence_len = 100 },
        .protocol = .{
            .pow_bits = 10,
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 3,
            .fold_step = 1,
            .lifting_log_size = null,
        },
    });
    try std.testing.expectEqual(@as(usize, 1 << 14), geometry.trace_rows);
    try std.testing.expectEqual(@as(usize, 100 * (1 << 14)), geometry.trace_cells);
    try std.testing.expectEqual(@as(usize, 1 << 15), geometry.composition_rows);
    try std.testing.expectEqual(@as(usize, 108), geometry.sampled_value_count);
    try std.testing.expectEqual(@as(usize, 14), geometry.fri_tree_count);
    try std.testing.expectEqual(@as(usize, 16), geometry.decommit_tree_count);
    try std.testing.expectEqual(@as(usize, 2), geometry.last_layer_domain_rows);
}

test "admission rejects shapes without a pinned parity contract" {
    const baseline = Request{
        .statement = .{ .log_n_rows = 14, .sequence_len = 100 },
        .protocol = .{
            .pow_bits = 10,
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 3,
            .fold_step = 1,
            .lifting_log_size = null,
        },
    };
    var request = baseline;
    request.protocol.fold_step = 3;
    try std.testing.expectError(error.UnsupportedProtocol, admit(request));
    request = baseline;
    request.protocol.n_queries = max_queries + 1;
    try std.testing.expectError(error.UnsupportedQueryCount, admit(request));
    request = baseline;
    request.statement.sequence_len = max_sequence_len + 1;
    try std.testing.expectError(error.UnsupportedSequenceLength, admit(request));
}
