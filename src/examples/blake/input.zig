//! Owned Blake trace preparation for backend-neutral proving.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const prover_pcs = @import("stwo_prover_engine").pcs;
const prover_transaction = @import("../common/prover_transaction.zig");

const M31 = m31.M31;

pub const CELLS_PER_ROUND: usize = 96;

pub const Statement = struct {
    log_n_rows: u32,
    n_rounds: u32,
};

pub const PreparedInput = prover_transaction.PreparedInput(Statement);

pub const Error = prover_transaction.Error || error{
    InvalidLogNRows,
    InvalidNRounds,
    ColumnCountOverflow,
};

pub fn validate(statement: Statement) Error!void {
    if (statement.log_n_rows == 0 or statement.log_n_rows >= 31)
        return error.InvalidLogNRows;
    if (statement.n_rounds == 0) return error.InvalidNRounds;
    _ = try nColumns(statement);
}

pub fn genTrace(
    allocator: std.mem.Allocator,
    statement: Statement,
) (std.mem.Allocator.Error || Error)![][]M31 {
    try validate(statement);
    const n = try checkedPow2(statement.log_n_rows);
    const n_columns = try nColumns(statement);

    const trace = try allocator.alloc([]M31, n_columns);
    errdefer allocator.free(trace);

    var initialized: usize = 0;
    errdefer for (trace[0..initialized]) |column| allocator.free(column);

    for (trace) |*column| {
        column.* = try allocator.alloc(M31, n);
        @memset(column.*, M31.zero());
        initialized += 1;
    }

    for (0..n) |row| {
        var column_index: usize = 0;
        var seed: u64 = @as(u64, @intCast(row)) + 1;
        for (0..statement.n_rounds) |round| {
            for (0..CELLS_PER_ROUND) |cell| {
                seed = nextSeed(seed);
                const mixed = seed ^
                    (@as(u64, @intCast(round)) *% 0x9e37_79b9_7f4a_7c15) ^
                    (@as(u64, @intCast(cell + 1)) *% 0x517c_c1b7_2722_0a95);
                trace[column_index][row] = M31.fromU64(mixed);
                column_index += 1;
            }
        }
        std.debug.assert(column_index == n_columns);
    }

    return trace;
}

pub fn deinitTrace(allocator: std.mem.Allocator, trace: [][]M31) void {
    for (trace) |column| allocator.free(column);
    allocator.free(trace);
}

pub fn prepare(
    allocator: std.mem.Allocator,
    statement: Statement,
) (std.mem.Allocator.Error || Error)!PreparedInput {
    const trace = try genTrace(allocator, statement);
    var trace_moved = false;
    defer if (!trace_moved) deinitTrace(allocator, trace);

    const preprocessed = try allocator.alloc(prover_pcs.ColumnEvaluation, 0);
    var preprocessed_owner = prover_transaction.OwnedColumns.init(preprocessed);
    errdefer preprocessed_owner.deinit(allocator);

    const main = try allocator.alloc(prover_pcs.ColumnEvaluation, trace.len);
    var main_owner = prover_transaction.OwnedColumns.init(main);
    errdefer main_owner.deinit(allocator);
    for (trace, 0..) |values, index| {
        main[index] = .{ .log_size = statement.log_n_rows, .values = values };
    }
    allocator.free(trace);
    trace_moved = true;

    return .{
        .request = statement,
        .trace = try prover_transaction.PreparedTrace.initOwned(
            allocator,
            preprocessed_owner.take(),
            main_owner.take(),
        ),
    };
}

pub fn nColumns(statement: Statement) Error!usize {
    return std.math.mul(
        usize,
        @as(usize, @intCast(statement.n_rounds)),
        CELLS_PER_ROUND,
    ) catch return error.ColumnCountOverflow;
}

fn checkedPow2(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidLogNRows;
    return @as(usize, 1) << @intCast(log_size);
}

fn nextSeed(seed: u64) u64 {
    var value = seed;
    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    return value;
}
