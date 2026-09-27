//! Allocation-free, destination-writing LogUp generation for prepared Tree 2.
//!
//! Preparation owns the placement maps, chunk summaries, error slots, and
//! three batch-inversion buffers used by every admitted worker lane. `runInto`
//! performs two joined waves without allocation:
//!
//!   1. derive row fractions, batch-invert, and write chunk-local prefixes;
//!   2. apply the canonical chunk offsets to disjoint output rows.
//!
//! Field addition is exact, so the ordered scan of chunk totals produces the
//! same cumulative column and final claim as the predecessor's row-by-row
//! scan. A failed or cancelled run may leave private destination bytes dirty,
//! but never reports completion to the enclosing transactional owner.

const std = @import("std");
const fields = @import("stwo_core").fields;
const M31 = fields.m31.M31;
const QM31 = fields.qm31.QM31;
const task_graph = @import("stwo_prover_engine").task_graph;
const work_pool = @import("stwo_prover_engine").work_pool;
const logup = @import("../air/logup.zig");
const infra = @import("../infra_trace.zig");

pub const CHUNK_ROWS: usize = 4096;

/// Borrowed slices assigned by the production owner before execution. Slices
/// may overlap only between `pool_exclusive` descriptors, whose graph contract
/// guarantees that they never execute concurrently.
pub const Storage = struct {
    trace_size: usize,
    n_sums: usize,
    lane_count: usize,
    chunk_totals: []QM31,
    chunk_offsets: []QM31,
    chunk_errors: []?anyerror,
    scratch: []QM31,
    abort: std.atomic.Value(bool) = .init(false),

    pub fn chunkCount(self: *const Storage) usize {
        return std.math.divCeil(usize, self.trace_size, CHUNK_ROWS) catch
            unreachable;
    }

    pub fn chunkCapacity(self: *const Storage) usize {
        return @min(self.trace_size, CHUNK_ROWS);
    }

    pub fn summaryCells(self: *const Storage) usize {
        return self.chunkCount() * self.n_sums;
    }

    pub fn scratchCells(self: *const Storage) usize {
        return self.lane_count * 3 * self.n_sums * self.chunkCapacity();
    }

    pub fn validate(self: *const Storage) !void {
        if (self.trace_size == 0 or self.n_sums == 0 or
            self.lane_count == 0 or self.lane_count > work_pool.MAX_WORKERS or
            self.chunk_totals.len != self.summaryCells() or
            self.chunk_offsets.len != self.summaryCells() or
            self.chunk_errors.len != self.chunkCount() or
            self.scratch.len != self.scratchCells())
        {
            return error.InvalidPreparedLogupStorage;
        }
    }
};

/// Generates `active_sums` cumulative secure columns directly into their four
/// M31 coordinate destinations. `RowContext.rowPairsAt(logical, committed)`
/// returns an error union containing `[max_sums]logup.RowPair`; only its active
/// prefix is read. Dispatch is monomorphised outside the row loop.
pub fn runInto(
    comptime max_sums: usize,
    storage: *Storage,
    placement: infra.BitReversalTable,
    row_context: anytype,
    active_sums: usize,
    columns: []const []M31,
    claims: []QM31,
    task_context: *task_graph.TaskContext,
) !bool {
    const RowContext = @TypeOf(row_context);
    const Worker = WorkerType(max_sums, RowContext);

    try storage.validate();
    if (active_sums == 0 or active_sums > max_sums or
        active_sums != storage.n_sums or claims.len != active_sums or
        columns.len != 4 * active_sums or
        placement.mapping.len != storage.trace_size)
    {
        return error.InvalidPreparedLogupDestination;
    }
    for (columns) |column| {
        if (column.len != storage.trace_size) {
            return error.InvalidPreparedLogupDestination;
        }
    }
    if (storage.lane_count > task_context.worker_budget.count or
        (task_context.task_class != .pool_exclusive and storage.lane_count != 1))
    {
        return error.InvalidPreparedLogupWorkerShape;
    }

    storage.abort.store(false, .release);
    @memset(storage.chunk_errors, null);
    @memset(storage.chunk_totals, QM31.zero());
    @memset(storage.chunk_offsets, QM31.zero());

    var workers: [work_pool.MAX_WORKERS]Worker = undefined;
    for (workers[0..storage.lane_count], 0..) |*worker, lane_index| {
        worker.* = .{
            .storage = storage,
            .placement = placement,
            .row_context = &row_context,
            .columns = columns,
            .lane_index = lane_index,
        };
    }

    if (!try runWave(Worker, workers[0..storage.lane_count], .local_prefix, task_context)) {
        return false;
    }
    for (storage.chunk_errors) |failure| {
        if (failure) |err| return err;
    }
    if (task_context.isCancelled()) return false;

    for (0..active_sums) |sum_index| {
        var accumulator = QM31.zero();
        for (0..storage.chunkCount()) |chunk_index| {
            const index = chunk_index * active_sums + sum_index;
            storage.chunk_offsets[index] = accumulator;
            accumulator = accumulator.add(storage.chunk_totals[index]);
        }
        claims[sum_index] = accumulator;
    }

    if (!try runWave(Worker, workers[0..storage.lane_count], .offset, task_context)) {
        return false;
    }
    if (task_context.isCancelled()) return false;
    try task_context.setCompletedWork(storage.trace_size);
    return true;
}

const Phase = enum { local_prefix, offset };

fn runWave(
    comptime Worker: type,
    workers: []Worker,
    phase: Phase,
    context: *task_graph.TaskContext,
) !bool {
    if (context.isCancelled()) return false;
    var spawn_failure: ?anyerror = null;
    for (workers) |*worker| {
        worker.phase = phase;
        worker.cancellation = context.cancellation;
    }
    if (workers.len > 1) {
        for (workers[1..]) |*worker| {
            context.spawnChild(Worker.run, .{worker}) catch |err| {
                worker.storage.abort.store(true, .release);
                spawn_failure = err;
                break;
            };
        }
    }
    Worker.run(&workers[0]);
    if (workers.len > 1) try context.waitForChildren();
    if (spawn_failure) |err| return err;
    return !context.isCancelled();
}

fn WorkerType(comptime max_sums: usize, comptime RowContext: type) type {
    return struct {
        const Self = @This();

        storage: *Storage,
        placement: infra.BitReversalTable,
        row_context: *const RowContext,
        columns: []const []M31,
        lane_index: usize,
        phase: Phase = .local_prefix,
        cancellation: *const task_graph.CancellationToken = undefined,

        fn run(self: *Self) void {
            switch (self.phase) {
                .local_prefix => self.localPrefixes(self.cancellation),
                .offset => self.applyOffsets(self.cancellation),
            }
        }

        fn localPrefixes(
            self: *Self,
            cancellation: *const task_graph.CancellationToken,
        ) void {
            const storage = self.storage;
            const chunk_capacity = storage.chunkCapacity();
            const term_capacity = storage.n_sums * chunk_capacity;
            const lane_stride = 3 * term_capacity;
            const lane_start = self.lane_index * lane_stride;
            const lane = storage.scratch[lane_start .. lane_start + lane_stride];
            const numerators = lane[0..term_capacity];
            const denominators = lane[term_capacity .. 2 * term_capacity];
            const inverses = lane[2 * term_capacity .. 3 * term_capacity];

            var chunk_index = self.lane_index;
            while (chunk_index < storage.chunkCount()) : (chunk_index += storage.lane_count) {
                if (cancellation.isCancelled() or storage.abort.load(.acquire)) return;
                self.generateChunk(
                    chunk_index,
                    numerators,
                    denominators,
                    inverses,
                ) catch |err| {
                    storage.chunk_errors[chunk_index] = err;
                    storage.abort.store(true, .release);
                    return;
                };
            }
        }

        fn generateChunk(
            self: *Self,
            chunk_index: usize,
            numerators: []QM31,
            denominators: []QM31,
            inverses: []QM31,
        ) !void {
            const storage = self.storage;
            const row_start = chunk_index * CHUNK_ROWS;
            const row_end = @min(storage.trace_size, row_start + CHUNK_ROWS);
            const chunk_len = row_end - row_start;
            const term_len = storage.n_sums * chunk_len;

            for (row_start..row_end, 0..) |logical_row, local_row| {
                const committed_row = self.placement.map(logical_row);
                const pairs: [max_sums]logup.RowPair = try self.row_context.rowPairsAt(
                    logical_row,
                    committed_row,
                );
                for (pairs[0..storage.n_sums], 0..) |pair, sum_index| {
                    const term_index = sum_index * chunk_len + local_row;
                    denominators[term_index] = pair.d1.mul(pair.d2);
                    numerators[term_index] = pair.n1.mul(pair.d2)
                        .add(pair.n2.mul(pair.d1));
                }
            }
            try fields.batchInverseInPlace(
                QM31,
                denominators[0..term_len],
                inverses[0..term_len],
            );

            for (0..storage.n_sums) |sum_index| {
                var accumulator = QM31.zero();
                for (row_start..row_end, 0..) |logical_row, local_row| {
                    const term_index = sum_index * chunk_len + local_row;
                    accumulator = accumulator.add(
                        numerators[term_index].mul(inverses[term_index]),
                    );
                    const coordinates = accumulator.toM31Array();
                    const committed_row = self.placement.map(logical_row);
                    for (coordinates, 0..) |coordinate, coordinate_index| {
                        self.columns[4 * sum_index + coordinate_index][committed_row] =
                            coordinate;
                    }
                }
                storage.chunk_totals[chunk_index * storage.n_sums + sum_index] =
                    accumulator;
            }
        }

        fn applyOffsets(
            self: *Self,
            cancellation: *const task_graph.CancellationToken,
        ) void {
            const storage = self.storage;
            var chunk_index = self.lane_index;
            while (chunk_index < storage.chunkCount()) : (chunk_index += storage.lane_count) {
                if (cancellation.isCancelled()) return;
                const row_start = chunk_index * CHUNK_ROWS;
                const row_end = @min(storage.trace_size, row_start + CHUNK_ROWS);
                for (0..storage.n_sums) |sum_index| {
                    const offset = storage.chunk_offsets[
                        chunk_index * storage.n_sums + sum_index
                    ];
                    if (offset.isZero()) continue;
                    for (row_start..row_end) |logical_row| {
                        const committed_row = self.placement.map(logical_row);
                        const column_start = 4 * sum_index;
                        const local = QM31.fromM31(
                            self.columns[column_start][committed_row],
                            self.columns[column_start + 1][committed_row],
                            self.columns[column_start + 2][committed_row],
                            self.columns[column_start + 3][committed_row],
                        ).add(offset).toM31Array();
                        for (local, 0..) |coordinate, coordinate_index| {
                            self.columns[column_start + coordinate_index][committed_row] =
                                coordinate;
                        }
                    }
                }
            }
        }
    };
}

comptime {
    if (CHUNK_ROWS > @import("interaction_trace_plan.zig").MAX_CANCELLATION_TILE_ROWS) {
        @compileError("prepared LogUp chunks exceed the Tree-2 cancellation bound");
    }
}
