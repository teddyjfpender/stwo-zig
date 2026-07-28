//! Row-parallel `range_check_9_9` accumulation over the packed small-value
//! memory table.
//!
//! The serial form walked the table once per 9-bit limb column, materialized
//! two full columns per limb pair, then scattered one increment per row. On
//! memory-7m that is 2^20 rows x 4 pairs — 8.4M limb extractions and 4.2M
//! scattered increments, and it was the whole of the 43 ms that the fixed
//! multiplicity stage costs.
//!
//! Multiplicity counting is an additive histogram, so the pass splits by row
//! and merges exactly. Each worker owns a private copy of only the relation
//! columns the small pass touches — for the small table the relation index *is*
//! the limb-pair index, so that is `small_limb_count / 2` columns, not the
//! whole table — and the merged column values are independent of the row
//! decomposition and of worker completion order.

const std = @import("std");
const adapter = @import("../adapter/mod.zig");
const memory_tables = @import("../witness/memory_tables.zig");
const multiplicity_tables = @import("multiplicity_tables.zig");
const prover = @import("stwo_prover_impl");

const work_pool = prover.work_pool;
const Tables = multiplicity_tables.Tables;

const table_label = "range_check_9_9";

/// Smallest row span worth a private histogram of its own.
const min_rows_per_worker: usize = 1 << 14;

/// Ceiling on the private histogram copies held live during the pass. The
/// merge re-reads every copy, so past this point the merge traffic costs more
/// than the extra scatter parallelism saves.
const max_private_bytes: usize = 192 << 20;

pub fn addSmallValueRangeChecks(
    input: *const adapter.ProverInput,
    tables: *Tables,
) !void {
    const pair_count = memory_tables.small_limb_count / 2;
    if (pair_count == 0) return;
    const small_rows = try memory_tables.smallRowCount(input);
    if (small_rows == 0) return;

    const table = tables.find(table_label) orelse return error.MissingFixedTable;
    const row_count: usize = table.entry.row_count;
    if (pair_count > table.entry.multiplicity_columns)
        return error.InvalidMultiplicityKey;
    const column_words = std.math.mul(usize, pair_count, row_count) catch
        return error.AllocationSizeOverflow;
    if (column_words == 0) return;

    // Charge the dense allocation here, in the position the first serial
    // increment would have charged it.
    const dense = try tables.reserve(table_label);

    const worker_count = workerCount(small_rows, column_words);
    const private = try tables.allocator.alloc(
        u32,
        std.math.mul(usize, column_words, worker_count) catch
            return error.AllocationSizeOverflow,
    );
    defer tables.allocator.free(private);

    var scatter: [work_pool.MAX_WORKERS]Scatter = undefined;
    for (scatter[0..worker_count], 0..) |*slot, index| slot.* = .{
        .input = input,
        .counts = private[index * column_words ..][0..column_words],
        .row_count = row_count,
        .pair_count = pair_count,
        .small_rows = small_rows,
        .index = index,
        .worker_count = worker_count,
        .failure = null,
    };
    try dispatch(Scatter, scatter[0..worker_count]);

    var merge: [work_pool.MAX_WORKERS]Merge = undefined;
    for (merge[0..worker_count], 0..) |*slot, index| slot.* = .{
        .dense = dense[0..column_words],
        .private = private,
        .column_words = column_words,
        .source_count = worker_count,
        .index = index,
        .worker_count = worker_count,
        .failure = null,
    };
    try dispatch(Merge, merge[0..worker_count]);
}

fn workerCount(small_rows: usize, column_words: usize) usize {
    const pool = work_pool.getGlobalPool() orelse return 1;
    const by_rows = std.math.divCeil(usize, small_rows, min_rows_per_worker) catch 1;
    const private_bytes = std.math.mul(usize, column_words, @sizeOf(u32)) catch
        return 1;
    const by_bytes = if (private_bytes == 0)
        work_pool.MAX_WORKERS
    else
        @max(@as(usize, 1), max_private_bytes / private_bytes);
    const capped = @min(@min(by_rows, by_bytes), work_pool.MAX_WORKERS);
    return @max(@as(usize, 1), @min(pool.workerCount(), capped));
}

fn dispatch(comptime Work: type, works: []Work) !void {
    if (works.len > 1) {
        const pool = work_pool.getGlobalPool().?;
        var wait_group: std.Thread.WaitGroup = .{};
        for (works[1..]) |*work| pool.spawnWg(&wait_group, Work.run, .{work});
        Work.run(&works[0]);
        wait_group.wait();
    } else {
        Work.run(&works[0]);
    }
    for (works) |work| {
        if (work.failure) |err| return err;
    }
}

/// Counts one disjoint row span into a private copy of the small relation
/// columns.
const Scatter = struct {
    input: *const adapter.ProverInput,
    counts: []u32,
    row_count: usize,
    pair_count: usize,
    small_rows: usize,
    index: usize,
    worker_count: usize,
    failure: ?anyerror,

    fn run(self: *Scatter) void {
        self.accumulate() catch |err| {
            self.failure = err;
        };
    }

    fn accumulate(self: *Scatter) !void {
        @memset(self.counts, 0);
        const span = std.math.divCeil(usize, self.small_rows, self.worker_count) catch
            unreachable;
        const start = self.index * span;
        if (start >= self.small_rows) return;
        const end = @min(self.small_rows, start + span);
        for (start..end) |row| {
            for (0..self.pair_count) |pair| {
                const low = try memory_tables.smallValueLimb(self.input, row, pair * 2);
                const high = try memory_tables.smallValueLimb(self.input, row, pair * 2 + 1);
                const key = (low << 9) | high;
                if (key >= self.row_count) return error.InvalidMultiplicityKey;
                const slot = &self.counts[pair * self.row_count + key];
                slot.* = std.math.add(u32, slot.*, 1) catch
                    return error.MultiplicityOverflow;
            }
        }
    }
};

/// Folds every private copy into the live dense columns over a disjoint slice
/// of the output.
const Merge = struct {
    dense: []u32,
    private: []const u32,
    column_words: usize,
    source_count: usize,
    index: usize,
    worker_count: usize,
    failure: ?anyerror,

    fn run(self: *Merge) void {
        self.fold() catch |err| {
            self.failure = err;
        };
    }

    fn fold(self: *Merge) !void {
        const span = std.math.divCeil(usize, self.column_words, self.worker_count) catch
            unreachable;
        const start = self.index * span;
        if (start >= self.column_words) return;
        const end = @min(self.column_words, start + span);
        for (start..end) |word| {
            var total = self.dense[word];
            for (0..self.source_count) |source| {
                total = std.math.add(
                    u32,
                    total,
                    self.private[source * self.column_words + word],
                ) catch return error.MultiplicityOverflow;
            }
            self.dense[word] = total;
        }
    }
};
