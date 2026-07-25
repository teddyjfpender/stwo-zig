//! Exact mixed-height Blake witness preparation.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const prover_pcs = @import("stwo_prover_impl").pcs;
const prover_transaction = @import("../common/prover_transaction.zig");
const constants = @import("constants.zig");
const geometry = @import("geometry.zig");
const round_trace = @import("round_trace.zig");
const scheduler_trace = @import("scheduler_trace.zig");
const xor_tables = @import("xor_tables.zig");

pub const Statement = struct {
    log_n_rows: u32,
    n_rounds: u32 = constants.N_ROUNDS,
};

/// Reviewed upper bound for the exact mixed-height witness. The fixed XOR
/// tables make even the minimum request large, so reject oversized requests
/// before allocating any trace column.
pub const MAX_COMMITTED_CELLS: u64 = 134_217_728;

pub const PreparedInput = prover_transaction.PreparedInput(Statement);

pub const Error = prover_transaction.Error || error{
    InvalidLogNRows,
    InvalidNRounds,
    ColumnCountOverflow,
    ResourceLimitExceeded,
};

pub fn validate(statement: Statement) Error!void {
    if (statement.log_n_rows < 4 or statement.log_n_rows >= 28)
        return error.InvalidLogNRows;
    if (statement.n_rounds != constants.N_ROUNDS)
        return error.InvalidNRounds;
    _ = try checkedPow2(statement.log_n_rows);
    for (constants.ROUND_LOG_SPLIT) |split| {
        _ = std.math.add(u32, statement.log_n_rows, split) catch
            return error.InvalidLogNRows;
    }
    const committed_cells = geometry.committedCells(statement.log_n_rows) catch
        return error.ColumnCountOverflow;
    if (committed_cells > MAX_COMMITTED_CELLS)
        return error.ResourceLimitExceeded;
}

test "exact Blake rejects oversized requests before witness allocation" {
    try std.testing.expectError(
        error.ResourceLimitExceeded,
        validate(.{ .log_n_rows = 20 }),
    );
}

pub fn prepare(
    allocator: std.mem.Allocator,
    statement: Statement,
) (std.mem.Allocator.Error || Error)!PreparedInput {
    try validate(statement);

    const preprocessed = try xor_tables.generatePreprocessed(allocator);
    var preprocessed_owner = prover_transaction.OwnedColumns.init(preprocessed);
    errdefer preprocessed_owner.deinit(allocator);

    const main = try generateMain(allocator, statement);
    var main_owner = prover_transaction.OwnedColumns.init(main);
    errdefer main_owner.deinit(allocator);

    return .{
        .request = statement,
        .trace = try prover_transaction.PreparedTrace.initOwned(
            allocator,
            preprocessed_owner.take(),
            main_owner.take(),
        ),
    };
}

pub fn generateMain(
    allocator: std.mem.Allocator,
    statement: Statement,
) (std.mem.Allocator.Error || Error)![]prover_pcs.ColumnEvaluation {
    try validate(statement);
    const columns = try allocator.alloc(
        prover_pcs.ColumnEvaluation,
        geometry.MAIN_COLUMNS,
    );
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |column| allocator.free(column.values);
        allocator.free(columns);
    }

    try allocateGroup(
        allocator,
        columns,
        &initialized,
        geometry.SCHEDULER_MAIN_COLUMNS,
        statement.log_n_rows,
    );
    for (constants.ROUND_LOG_SPLIT) |split| {
        try allocateGroup(
            allocator,
            columns,
            &initialized,
            geometry.ROUND_MAIN_COLUMNS,
            statement.log_n_rows + split,
        );
    }

    var xor_accumulator = try xor_tables.Accumulator.init(allocator);
    var xor_accumulator_moved = false;
    defer if (!xor_accumulator_moved) xor_accumulator.deinit(allocator);
    try fillScheduler(columns, statement.log_n_rows);
    try fillRoundComponents(columns, statement.log_n_rows, &xor_accumulator);

    const xor_columns = try xor_accumulator.intoColumns(allocator);
    xor_accumulator_moved = true;
    var xor_columns_moved = false;
    defer if (!xor_columns_moved) {
        for (xor_columns) |column| allocator.free(column.values);
        allocator.free(xor_columns);
    };
    std.debug.assert(xor_columns.len == geometry.XOR_MAIN_COLUMNS);
    @memcpy(
        columns[geometry.XOR_MAIN_OFFSET .. geometry.XOR_MAIN_OFFSET + xor_columns.len],
        xor_columns,
    );
    initialized += xor_columns.len;
    allocator.free(xor_columns);
    xor_columns_moved = true;

    std.debug.assert(initialized == columns.len);
    return columns;
}

fn allocateGroup(
    allocator: std.mem.Allocator,
    columns: []prover_pcs.ColumnEvaluation,
    initialized: *usize,
    count: usize,
    log_size: u32,
) !void {
    const row_count = try checkedPow2(log_size);
    for (0..count) |_| {
        columns[initialized.*] = .{
            .log_size = log_size,
            .values = try allocator.alloc(M31, row_count),
        };
        @memset(@constCast(columns[initialized.*].values), M31.zero());
        initialized.* += 1;
    }
}

fn fillScheduler(
    columns: []prover_pcs.ColumnEvaluation,
    log_size: u32,
) !void {
    const row_count = try checkedPow2(log_size);
    for (0..row_count) |storage| {
        const input = scheduler_trace.inputForPackedLane(storage / 16, storage % 16);
        const output = scheduler_trace.generate(input);
        for (output.row, 0..) |value, column| {
            @constCast(columns[geometry.SCHEDULER_MAIN_OFFSET + column]
                .values)[storage] = M31.fromCanonical(value);
        }
    }
}

fn fillRoundComponents(
    columns: []prover_pcs.ColumnEvaluation,
    log_size: u32,
    xor_accumulator: *xor_tables.Accumulator,
) !void {
    const scheduler_pack_count = try checkedPow2(log_size - 4);
    var packed_input_offset: usize = 0;
    for (
        constants.ROUND_LOG_SPLIT,
        geometry.ROUND_MAIN_OFFSETS,
        0..,
    ) |split, column_offset, component_index| {
        const component_log = log_size + split;
        const row_count = try checkedPow2(component_log);
        for (0..row_count) |storage| {
            const round_input = try roundInputForStorage(
                log_size,
                component_index,
                storage,
            );
            const output = round_trace.generate(
                round_input.state,
                round_input.message,
                xor_accumulator,
            );
            for (output.row, 0..) |value, column| {
                @constCast(columns[column_offset + column]
                    .values)[storage] = M31.fromCanonical(value);
            }
        }
        packed_input_offset += scheduler_pack_count *
            (@as(usize, 1) << @intCast(split));
    }
    std.debug.assert(
        packed_input_offset == scheduler_pack_count * constants.N_ROUNDS,
    );
}

pub fn roundInputForStorage(
    log_size: u32,
    component_index: usize,
    storage: usize,
) Error!scheduler_trace.RoundInput {
    if (component_index >= constants.ROUND_LOG_SPLIT.len)
        return error.InvalidPreparedGeometry;
    const scheduler_pack_count = try checkedPow2(log_size - 4);
    var packed_input_offset: usize = 0;
    for (constants.ROUND_LOG_SPLIT[0..component_index]) |split| {
        packed_input_offset += scheduler_pack_count *
            (@as(usize, 1) << @intCast(split));
    }
    const packed_input_index = packed_input_offset + storage / 16;
    const scheduler_pack = packed_input_index / constants.N_ROUNDS;
    const round_index = packed_input_index % constants.N_ROUNDS;
    const scheduler_input =
        scheduler_trace.inputForPackedLane(scheduler_pack, storage % 16);
    return scheduler_trace.generate(scheduler_input).round_inputs[round_index];
}

pub fn populateXorAccumulator(
    log_size: u32,
    accumulator: *xor_tables.Accumulator,
) Error!void {
    for (constants.ROUND_LOG_SPLIT, 0..) |split, component_index| {
        const row_count = try checkedPow2(log_size + split);
        for (0..row_count) |storage| {
            const input = try roundInputForStorage(
                log_size,
                component_index,
                storage,
            );
            _ = round_trace.generate(input.state, input.message, accumulator);
        }
    }
}

pub fn checkedPow2(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidLogNRows;
    return @as(usize, 1) << @intCast(log_size);
}

test "exact Blake witness binds fixed rounds and SIMD-compatible minimum" {
    try validate(.{ .log_n_rows = 4 });
    try std.testing.expectError(
        error.InvalidLogNRows,
        validate(.{ .log_n_rows = 3 }),
    );
    try std.testing.expectError(
        error.InvalidNRounds,
        validate(.{ .log_n_rows = 4, .n_rounds = 9 }),
    );
}

test "exact Blake round-component row mapping preserves the 8:2 split" {
    const log_size: u32 = 5;
    const scheduler_pack_count = try checkedPow2(log_size - 4);
    try std.testing.expectEqual(@as(usize, 2), scheduler_pack_count);

    const first_component_packs =
        scheduler_pack_count << @intCast(constants.ROUND_LOG_SPLIT[0]);
    try std.testing.expectEqual(@as(usize, 16), first_component_packs);
    try std.testing.expectEqual(@as(usize, 4), 20 - first_component_packs);

    const last_first_component = first_component_packs - 1;
    try std.testing.expectEqual(@as(usize, 1), last_first_component / 10);
    try std.testing.expectEqual(@as(usize, 5), last_first_component % 10);
    try std.testing.expectEqual(@as(usize, 1), first_component_packs / 10);
    try std.testing.expectEqual(@as(usize, 6), first_component_packs % 10);
}

test "exact Blake main witness has mixed heights and complete XOR multiplicities" {
    const allocator = std.testing.allocator;
    const columns = try generateMain(allocator, .{ .log_n_rows = 4 });
    defer {
        for (columns) |column| allocator.free(column.values);
        allocator.free(columns);
    }

    try std.testing.expectEqual(geometry.MAIN_COLUMNS, columns.len);
    try std.testing.expectEqual(@as(u32, 4), columns[0].log_size);
    try std.testing.expectEqual(
        @as(u32, 7),
        columns[geometry.ROUND_MAIN_OFFSETS[0]].log_size,
    );
    try std.testing.expectEqual(
        @as(u32, 5),
        columns[geometry.ROUND_MAIN_OFFSETS[1]].log_size,
    );
    try std.testing.expectEqual(
        geometry.XOR_TABLES[0].logSize(),
        columns[geometry.XOR_MAIN_OFFSET].log_size,
    );

    var multiplicity_sum: u64 = 0;
    for (columns[geometry.XOR_MAIN_OFFSET..]) |column| {
        for (column.values) |value| multiplicity_sum += value.toU32();
    }
    const round_rows =
        (@as(u64, 1) << @intCast(4 + constants.ROUND_LOG_SPLIT[0])) +
        (@as(u64, 1) << @intCast(4 + constants.ROUND_LOG_SPLIT[1]));
    try std.testing.expectEqual(round_rows * 128, multiplicity_sum);
}
