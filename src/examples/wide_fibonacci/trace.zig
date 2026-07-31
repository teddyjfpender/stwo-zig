//! Wide Fibonacci statement validation and trace preparation.

const std = @import("std");
const core_utils = @import("stwo_core").utils;
const m31 = @import("stwo_core").fields.m31;
const prover_pcs = @import("stwo_prover_engine").pcs;
const work_pool = @import("stwo_prover_engine").work_pool;
const prover_transaction = @import("stwo_prover_engine").transaction;

const M31 = m31.M31;
const GenericBackend = struct {};

/// Affine row seeds followed by `next = a^2 + b^2` in canonical M31.
/// The seven-word form is the backend-neutral quadratic-recurrence ABI:
/// a offset/step, b offset/step, previous/current square weights, constant.
pub const quadratic_recurrence_recipe: [7]u32 = .{ 1, 0, 0, 1, 1, 1, 0 };

pub const Statement = struct {
    log_n_rows: u32,
    sequence_len: u32,
};

pub const PreparedInput = prover_transaction.PreparedInput(Statement);

pub const Error = prover_transaction.Error || error{
    InvalidLogSize,
    InvalidSequenceLength,
};

/// Generates a wide-fibonacci trace in bit-reversed circle-domain order.
///
/// For each row `i`, the sequence starts at `(a, b) = (1, i)` and evolves via
/// `c = a^2 + b^2`.
pub fn generate(
    allocator: std.mem.Allocator,
    statement: Statement,
) (std.mem.Allocator.Error || Error)![][]M31 {
    return generateForBackend(GenericBackend, allocator, statement);
}

pub fn generateForBackend(
    comptime Backend: type,
    allocator: std.mem.Allocator,
    statement: Statement,
) ![][]M31 {
    if (statement.log_n_rows == 0 or statement.log_n_rows >= 31) return error.InvalidLogSize;
    if (statement.sequence_len < 2) return error.InvalidSequenceLength;

    const n = checkedPow2(statement.log_n_rows) catch return error.InvalidLogSize;
    const n_cols: usize = @intCast(statement.sequence_len);

    const columns = try allocator.alloc([]M31, n_cols);
    errdefer allocator.free(columns);

    var initialized: usize = 0;
    errdefer for (columns[0..initialized]) |column| allocator.free(column);

    for (columns) |*column| {
        column.* = try allocator.alloc(M31, n);
        initialized += 1;
    }

    if (comptime @hasDecl(Backend, "fillQuadraticRecurrenceTrace")) {
        if (!@hasDecl(Backend, "admitsQuadraticRecurrenceTrace"))
            @compileError("quadratic recurrence backend requires structural admission");
        if (Backend.admitsQuadraticRecurrenceTrace(n, n_cols)) {
            try Backend.fillQuadraticRecurrenceTrace(
                columns,
                statement.log_n_rows,
                quadratic_recurrence_recipe,
            );
            return columns;
        }
    }

    // Storage positions are independent recurrence instances. Deriving the
    // logical row from each contiguous bit-reversed-circle position avoids a
    // full permutation table and lets workers write coalesced column ranges.
    const FillWork = struct {
        columns: [][]M31,
        log_n_rows: u32,
        start: usize,
        end: usize,

        fn run(work: *@This()) void {
            var storage_index = work.start;
            while (storage_index + m31.PACK_WIDTH <= work.end) : (storage_index += m31.PACK_WIDTH) {
                var seed_values: [m31.PACK_WIDTH]u32 = undefined;
                for (&seed_values, 0..) |*seed, lane| {
                    seed.* = @intCast(logicalRow(
                        work.log_n_rows,
                        storage_index + lane,
                    ));
                }

                var previous: m31.PackedM31 = @splat(1);
                var current: m31.PackedM31 = seed_values;
                m31.storePacked(work.columns[0].ptr + storage_index, previous);
                m31.storePacked(work.columns[1].ptr + storage_index, current);
                for (work.columns[2..]) |column| {
                    const next = m31.addPacked(
                        m31.mulPacked(previous, previous),
                        m31.mulPacked(current, current),
                    );
                    m31.storePacked(column.ptr + storage_index, next);
                    previous = current;
                    current = next;
                }
            }

            while (storage_index < work.end) : (storage_index += 1) {
                var previous = M31.one();
                var current = M31.fromCanonical(@intCast(logicalRow(
                    work.log_n_rows,
                    storage_index,
                )));
                work.columns[0][storage_index] = previous;
                work.columns[1][storage_index] = current;
                for (work.columns[2..]) |column| {
                    const next = previous.square().add(current.square());
                    column[storage_index] = next;
                    previous = current;
                    current = next;
                }
            }
        }
    };

    const active_pool = work_pool.getGlobalPool();
    const worker_count = if (active_pool) |pool|
        @max(@as(usize, 1), @min(pool.workerCount(), n / 4096))
    else
        1;
    const chunk_len = std.math.divCeil(usize, n, worker_count) catch unreachable;
    var works: [work_pool.MAX_WORKERS]FillWork = undefined;
    for (0..worker_count) |worker| {
        const start = worker * chunk_len;
        works[worker] = .{
            .columns = columns,
            .log_n_rows = statement.log_n_rows,
            .start = start,
            .end = @min(n, start + chunk_len),
        };
    }
    if (worker_count > 1) {
        var wait_group: std.Thread.WaitGroup = .{};
        for (works[1..worker_count]) |*work| {
            active_pool.?.spawnWg(&wait_group, FillWork.run, .{work});
        }
        FillWork.run(&works[0]);
        wait_group.wait();
    } else {
        FillWork.run(&works[0]);
    }

    return columns;
}

inline fn logicalRow(log_n_rows: u32, storage_index: usize) usize {
    const circle_index = core_utils.bitReverseIndex(storage_index, log_n_rows);
    return core_utils.circleDomainIndexToCosetIndex(circle_index, log_n_rows);
}

pub fn deinit(allocator: std.mem.Allocator, columns: [][]M31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}

pub fn prepare(
    allocator: std.mem.Allocator,
    statement: Statement,
) (std.mem.Allocator.Error || Error)!PreparedInput {
    return prepareForBackend(GenericBackend, allocator, statement);
}

pub fn prepareForBackend(
    comptime Backend: type,
    allocator: std.mem.Allocator,
    statement: Statement,
) !PreparedInput {
    var main = if (try generateContiguousOwnedForBackend(Backend, allocator, statement)) |owned|
        owned
    else blk: {
        const columns = try generateForBackend(Backend, allocator, statement);
        break :blk prover_transaction.OwnedColumns.init(
            try intoOwnedColumns(allocator, statement.log_n_rows, columns),
        );
    };
    errdefer main.deinit(allocator);

    var preprocessed = prover_transaction.OwnedColumns.init(
        try allocator.alloc(prover_pcs.ColumnEvaluation, 0),
    );
    errdefer preprocessed.deinit(allocator);

    const preprocessed_taken = preprocessed.takeWithBacking();
    const main_taken = main.takeWithBacking();
    return .{
        .request = statement,
        .trace = try prover_transaction.PreparedTrace.initOwnedWithBacking(
            allocator,
            prover_transaction.OwnedColumns{
                .columns = preprocessed_taken.columns,
                .backing_buffers = preprocessed_taken.backing_buffers,
                .source = preprocessed_taken.source,
            },
            prover_transaction.OwnedColumns{
                .columns = main_taken.columns,
                .backing_buffers = main_taken.backing_buffers,
                .source = main_taken.source,
            },
        ),
    };
}

fn generateContiguousOwnedForBackend(
    comptime Backend: type,
    allocator: std.mem.Allocator,
    statement: Statement,
) !?prover_transaction.OwnedColumns {
    if (comptime !@hasDecl(Backend, "preferContiguousQuadraticRecurrenceTrace") or
        !@hasDecl(Backend, "admitsQuadraticRecurrenceTrace") or
        !@hasDecl(Backend, "fillQuadraticRecurrenceTrace")) return null;
    if (!Backend.preferContiguousQuadraticRecurrenceTrace) return null;
    if (statement.log_n_rows == 0 or statement.log_n_rows >= 31)
        return error.InvalidLogSize;
    if (statement.sequence_len < 2) return error.InvalidSequenceLength;

    const row_count = try checkedPow2(statement.log_n_rows);
    const column_count: usize = @intCast(statement.sequence_len);
    if (!Backend.admitsQuadraticRecurrenceTrace(row_count, column_count)) return null;
    const cell_count = std.math.mul(usize, row_count, column_count) catch
        return error.InvalidLogSize;

    const arena = try allocator.alloc(M31, cell_count);
    errdefer allocator.free(arena);
    const backing_buffers = try allocator.alloc([]M31, 1);
    errdefer allocator.free(backing_buffers);
    backing_buffers[0] = arena;
    const columns = try allocator.alloc(prover_pcs.ColumnEvaluation, column_count);
    errdefer allocator.free(columns);
    const views = try allocator.alloc([]M31, column_count);
    defer allocator.free(views);
    for (columns, views, 0..) |*column, *view, index| {
        const values = arena[index * row_count ..][0..row_count];
        column.* = .{ .log_size = statement.log_n_rows, .values = values };
        view.* = values;
    }
    const defer_generation = if (comptime @hasDecl(Backend, "preferDeferredQuadraticRecurrenceTrace") and
        @hasDecl(Backend, "admitsDeferredQuadraticRecurrenceTrace"))
        Backend.preferDeferredQuadraticRecurrenceTrace and
            Backend.admitsDeferredQuadraticRecurrenceTrace(row_count, column_count)
    else
        false;
    if (!defer_generation) {
        try Backend.fillQuadraticRecurrenceTrace(
            views,
            statement.log_n_rows,
            quadratic_recurrence_recipe,
        );
    }
    const source: prover_pcs.ColumnSource = if (defer_generation)
        .{ .quadratic_recurrence = .{
            .log_n_rows = statement.log_n_rows,
            .recipe = quadratic_recurrence_recipe,
        } }
    else
        .materialized;
    return prover_transaction.OwnedColumns.initWithBackingAndSource(
        columns,
        backing_buffers,
        source,
    );
}

fn checkedPow2(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

fn intoOwnedColumns(
    allocator: std.mem.Allocator,
    log_n_rows: u32,
    trace: [][]M31,
) ![]prover_pcs.ColumnEvaluation {
    const columns = allocator.alloc(prover_pcs.ColumnEvaluation, trace.len) catch |err| {
        deinit(allocator, trace);
        return err;
    };

    for (trace, 0..) |column, index| {
        columns[index] = .{ .log_size = log_n_rows, .values = column };
    }
    allocator.free(trace);
    return columns;
}
