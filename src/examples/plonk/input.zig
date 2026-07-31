//! Plonk statement validation and owned trace preparation.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const prover_pcs = @import("stwo_prover_engine").pcs;
const prover_transaction = @import("stwo_prover_engine").transaction;

const M31 = m31.M31;

pub const Statement = struct {
    log_n_rows: u32,
};

pub const Trace = struct {
    preprocessed: [4][]M31,
    main: [4][]M31,
};

pub const PreparedInput = prover_transaction.PreparedInput(Statement);

pub const Error = prover_transaction.Error || error{
    InvalidLogSize,
};

pub fn validate(statement: Statement) Error!void {
    if (statement.log_n_rows == 0 or statement.log_n_rows >= 31)
        return error.InvalidLogSize;
}

pub fn genTrace(
    allocator: std.mem.Allocator,
    statement: Statement,
) (std.mem.Allocator.Error || Error)!Trace {
    try validate(statement);
    const n = try checkedPow2(statement.log_n_rows);

    var preprocessed = try allocColumnSet(allocator, n);
    errdefer freeColumnSet(allocator, preprocessed);
    var main = try allocColumnSet(allocator, n);
    errdefer freeColumnSet(allocator, main);

    const fib = try allocator.alloc(M31, n + 2);
    defer allocator.free(fib);
    fib[0] = M31.one();
    fib[1] = M31.one();
    for (2..fib.len) |i| fib[i] = fib[i - 1].add(fib[i - 2]);

    for (0..n) |i| {
        preprocessed[0][i] = M31.fromU64(i);
        preprocessed[1][i] = M31.fromU64(i + 1);
        preprocessed[2][i] = M31.fromU64(i + 2);
        preprocessed[3][i] = M31.one();

        main[0][i] = M31.one();
        main[1][i] = fib[i];
        main[2][i] = fib[i + 1];
        main[3][i] = fib[i + 2];
    }

    if (n >= 2) {
        main[0][n - 1] = M31.zero();
        main[0][n - 2] = M31.one();
    }

    return .{ .preprocessed = preprocessed, .main = main };
}

pub fn deinitTrace(allocator: std.mem.Allocator, trace: *Trace) void {
    freeColumnSet(allocator, trace.preprocessed);
    freeColumnSet(allocator, trace.main);
    trace.* = undefined;
}

pub fn prepare(
    allocator: std.mem.Allocator,
    statement: Statement,
) (std.mem.Allocator.Error || Error)!PreparedInput {
    const trace = try genTrace(allocator, statement);
    var preprocessed_moved = false;
    var main_moved = false;
    defer {
        if (!preprocessed_moved) freeColumnSet(allocator, trace.preprocessed);
        if (!main_moved) freeColumnSet(allocator, trace.main);
    }

    const preprocessed = try columnsFromSet(
        allocator,
        statement.log_n_rows,
        trace.preprocessed,
    );
    var preprocessed_owner = prover_transaction.OwnedColumns.init(preprocessed);
    errdefer preprocessed_owner.deinit(allocator);
    preprocessed_moved = true;

    const main = try columnsFromSet(allocator, statement.log_n_rows, trace.main);
    var main_owner = prover_transaction.OwnedColumns.init(main);
    errdefer main_owner.deinit(allocator);
    main_moved = true;

    return .{
        .request = statement,
        .trace = try prover_transaction.PreparedTrace.initOwned(
            allocator,
            preprocessed_owner.take(),
            main_owner.take(),
        ),
    };
}

fn columnsFromSet(
    allocator: std.mem.Allocator,
    log_size: u32,
    values: [4][]M31,
) std.mem.Allocator.Error![]prover_pcs.ColumnEvaluation {
    const columns = try allocator.alloc(prover_pcs.ColumnEvaluation, values.len);
    for (values, 0..) |column, index| {
        columns[index] = .{ .log_size = log_size, .values = column };
    }
    return columns;
}

fn checkedPow2(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

fn allocColumnSet(allocator: std.mem.Allocator, n: usize) ![4][]M31 {
    var columns: [4][]M31 = undefined;
    var initialized: usize = 0;
    errdefer for (columns[0..initialized]) |column| allocator.free(column);
    for (&columns) |*column| {
        column.* = try allocator.alloc(M31, n);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    return columns;
}

fn freeColumnSet(allocator: std.mem.Allocator, columns: [4][]M31) void {
    for (columns) |column| allocator.free(column);
}
