//! XOR statement validation and owned trace preparation.

const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const m31 = @import("stwo_core").fields.m31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const utils = @import("stwo_core").utils;
const prover_pcs = @import("stwo_prover_impl").pcs;
const prover_transaction = @import("../common/prover_transaction.zig");

const M31 = m31.M31;

pub const PREPROCESSED_COLUMNS: usize = 7;
pub const MAIN_COLUMNS: usize = 4;

pub const Preprocessed = enum(usize) {
    is_first,
    is_step,
    row_bit,
    table_selector,
    table_a,
    table_b,
    table_c,
};

pub const Main = enum(usize) {
    a,
    b,
    c,
    multiplicity,
};

pub const Statement = struct {
    log_size: u32,
    log_step: u32,
    offset: usize,
    claimed_sum: QM31 = QM31.zero(),
};

pub const PreparedInput = prover_transaction.PreparedInput(Statement);

pub const Error = prover_transaction.Error || error{
    InvalidClaimedSum,
    InvalidLogSize,
    InvalidStep,
};

pub fn validate(statement: Statement) Error!void {
    if (statement.log_size < 2) return error.InvalidLogSize;
    if (statement.log_step > statement.log_size) return error.InvalidStep;
    if (!statement.claimed_sum.eql(QM31.zero())) return error.InvalidClaimedSum;
}

/// Generates `IsFirst` preprocessed values in bit-reversed order.
pub fn genIsFirstColumn(
    allocator: std.mem.Allocator,
    log_size: u32,
) (std.mem.Allocator.Error || Error)![]M31 {
    return core_air_utils.genIsFirstColumn(allocator, log_size);
}

/// Generates `IsStepWithOffset` preprocessed values in bit-reversed order.
pub fn genIsStepWithOffsetColumn(
    allocator: std.mem.Allocator,
    log_size: u32,
    log_step: u32,
    offset: usize,
) (std.mem.Allocator.Error || Error)![]M31 {
    return core_air_utils.genPeriodicIndicatorColumn(allocator, log_size, log_step, offset);
}

pub fn prepare(
    allocator: std.mem.Allocator,
    statement: Statement,
) (std.mem.Allocator.Error || Error)!PreparedInput {
    try validate(statement);

    const is_first = try genIsFirstColumn(allocator, statement.log_size);
    var is_first_moved = false;
    errdefer if (!is_first_moved) allocator.free(is_first);
    const is_step = try genIsStepWithOffsetColumn(
        allocator,
        statement.log_size,
        statement.log_step,
        statement.offset,
    );
    var is_step_moved = false;
    errdefer if (!is_step_moved) allocator.free(is_step);

    const lookup_preprocessed = try genLookupPreprocessed(allocator, statement.log_size);
    var lookup_preprocessed_moved = false;
    errdefer if (!lookup_preprocessed_moved) {
        for (lookup_preprocessed) |column| allocator.free(column);
        allocator.free(lookup_preprocessed);
    };

    const preprocessed_columns = try allocator.alloc(
        prover_pcs.ColumnEvaluation,
        PREPROCESSED_COLUMNS,
    );
    preprocessed_columns[@intFromEnum(Preprocessed.is_first)] = .{
        .log_size = statement.log_size,
        .values = is_first,
    };
    preprocessed_columns[@intFromEnum(Preprocessed.is_step)] = .{
        .log_size = statement.log_size,
        .values = is_step,
    };
    for (lookup_preprocessed, 0..) |values, index| {
        preprocessed_columns[2 + index] = .{
            .log_size = statement.log_size,
            .values = values,
        };
    }
    is_first_moved = true;
    is_step_moved = true;
    lookup_preprocessed_moved = true;
    allocator.free(lookup_preprocessed);
    var preprocessed = prover_transaction.OwnedColumns.init(preprocessed_columns);
    errdefer preprocessed.deinit(allocator);

    const main_values = try genMainColumns(
        allocator,
        statement.log_size,
        preprocessed_columns,
    );
    var main_values_moved = false;
    errdefer if (!main_values_moved) {
        for (main_values) |column| allocator.free(column);
        allocator.free(main_values);
    };
    const main_columns = try allocator.alloc(prover_pcs.ColumnEvaluation, MAIN_COLUMNS);
    for (main_values, main_columns) |values, *column| {
        column.* = .{ .log_size = statement.log_size, .values = values };
    }
    main_values_moved = true;
    allocator.free(main_values);
    var main = prover_transaction.OwnedColumns.init(main_columns);
    errdefer main.deinit(allocator);

    return .{
        .request = statement,
        .trace = try prover_transaction.PreparedTrace.initOwned(
            allocator,
            preprocessed.take(),
            main.take(),
        ),
    };
}

fn genLookupPreprocessed(
    allocator: std.mem.Allocator,
    log_size: u32,
) (std.mem.Allocator.Error || Error)![][]M31 {
    const n = try checkedPow2(log_size);
    const columns = try allocator.alloc([]M31, 5);
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |column| allocator.free(column);
        allocator.free(columns);
    }
    for (columns) |*column| {
        column.* = try allocator.alloc(M31, n);
        @memset(column.*, M31.zero());
        initialized += 1;
    }

    for (0..n) |i| {
        const storage = storageIndex(i, log_size);
        columns[0][storage] = M31.fromCanonical(@intCast((i >> 1) & 1));
    }
    for (0..4) |table_row| {
        const storage = storageIndex(table_row, log_size);
        const a: u32 = @intCast((table_row >> 1) & 1);
        const b: u32 = @intCast(table_row & 1);
        columns[1][storage] = M31.one();
        columns[2][storage] = M31.fromCanonical(a);
        columns[3][storage] = M31.fromCanonical(b);
        columns[4][storage] = M31.fromCanonical(a ^ b);
    }
    return columns;
}

fn genMainColumns(
    allocator: std.mem.Allocator,
    log_size: u32,
    preprocessed: []const prover_pcs.ColumnEvaluation,
) (std.mem.Allocator.Error || Error)![][]M31 {
    if (preprocessed.len != PREPROCESSED_COLUMNS) return error.InvalidPreparedGeometry;
    const n = try checkedPow2(log_size);
    const columns = try allocator.alloc([]M31, MAIN_COLUMNS);
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |column| allocator.free(column);
        allocator.free(columns);
    }
    for (columns) |*column| {
        column.* = try allocator.alloc(M31, n);
        @memset(column.*, M31.zero());
        initialized += 1;
    }

    const row_bit = preprocessed[@intFromEnum(Preprocessed.row_bit)].values;
    const is_step = preprocessed[@intFromEnum(Preprocessed.is_step)].values;
    if (row_bit.len != n or is_step.len != n) return error.InvalidPreparedGeometry;

    var counts = [_]u64{0} ** 4;
    for (0..n) |storage| {
        const a = row_bit[storage];
        const b = is_step[storage];
        if (a.v > 1 or b.v > 1) return error.InvalidPreparedGeometry;
        const c = M31.fromCanonical(a.v ^ b.v);
        columns[@intFromEnum(Main.a)][storage] = a;
        columns[@intFromEnum(Main.b)][storage] = b;
        columns[@intFromEnum(Main.c)][storage] = c;
        counts[(@as(usize, a.v) << 1) | @as(usize, b.v)] += 1;
    }
    for (counts, 0..) |count, table_row| {
        columns[@intFromEnum(Main.multiplicity)][storageIndex(table_row, log_size)] =
            M31.fromU64(count);
    }
    return columns;
}

pub fn storageIndex(coset_index: usize, log_size: u32) usize {
    const circle_domain_index = utils.cosetIndexToCircleDomainIndex(coset_index, log_size);
    return utils.bitReverseIndex(circle_domain_index, log_size);
}

fn checkedPow2(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}
