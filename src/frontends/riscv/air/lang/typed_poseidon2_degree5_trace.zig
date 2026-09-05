//! Parallel main-trace writer for the degree-five Poseidon2 candidate.
//!
//! The candidate semantics are compiled once into a flat row program and
//! evaluated eight rows at a time in committed (bit-reversed) order, so every
//! worker streams contiguous column ranges instead of scattering one row
//! across 239 columns.  Workers own disjoint committed ranges and their own
//! vector scratch; the compiler authority and column storage are shared and
//! immutable.  Padding rows are written as zero by the same pass.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const infra = @import("../../infra_trace.zig");
const work_pool = @import("stwo_prover_engine").work_pool;
const candidate_mod = @import("typed_poseidon2_degree_bounded_candidate.zig");
const production = @import("../memory_commitment/poseidon2_air.zig");
const row_program = @import("typed_poseidon2_degree5_row_program.zig");

pub const Columns = struct {
    values: [][]M31,

    pub fn deinit(self: *Columns, allocator: std.mem.Allocator) void {
        for (self.values) |column| allocator.free(column);
        allocator.free(self.values);
        self.* = undefined;
    }
};

pub fn generateMain(
    allocator: std.mem.Allocator,
    candidate: *const candidate_mod.Candidate,
    calls: []const production.Call,
    log_size: u32,
) !Columns {
    try candidate.validateRetained();
    if (candidate.profile != .degree5 or log_size >= @bitSizeOf(usize))
        return error.InvalidCandidateTrace;
    const size = @as(usize, 1) << @intCast(log_size);
    if (calls.len > size) return error.InvalidTraceShape;
    // Every committed row (padding included) is written exactly once below,
    // so the columns need no zero prefill.
    const columns = try allocateColumns(
        allocator,
        candidate.mainColumnCount(),
        size,
    );
    errdefer freeColumns(allocator, columns);
    var program = try row_program.RowProgram.compile(allocator, candidate);
    defer program.deinit();
    const table = try infra.BitReversalTable.init(allocator, log_size);
    defer table.deinit(allocator);
    // Blocks are addressed by committed row; invert the logical->committed
    // permutation once so each block gathers its eight logical calls.
    const logical_of = try allocator.alloc(usize, size);
    defer allocator.free(logical_of);
    for (table.mapping, 0..) |committed, logical| logical_of[committed] = logical;

    const block_count = if (size >= row_program.LANES) size / row_program.LANES else 1;
    const worker_count: usize = if (work_pool.getGlobalPool()) |pool|
        @min(pool.workerCount(), @max(@as(usize, 1), block_count / min_blocks_per_worker))
    else
        1;
    if (worker_count > 1) {
        const pool = work_pool.getGlobalPool().?;
        const workers = try allocator.alloc(Worker, worker_count);
        defer allocator.free(workers);
        for (workers, 0..) |*worker, index| {
            worker.* = .{
                .allocator = allocator,
                .program = &program,
                .calls = calls,
                .logical_of = logical_of,
                .columns = columns,
                .committed_start = row_program.LANES * (block_count * index / worker_count),
                .committed_end = row_program.LANES * (block_count * (index + 1) / worker_count),
            };
        }
        workers[worker_count - 1].committed_end = size;
        var wait_group = std.Thread.WaitGroup{};
        for (workers[1..]) |*worker| {
            pool.spawnWg(&wait_group, Worker.run, .{worker});
        }
        Worker.run(&workers[0]);
        wait_group.wait();
        for (workers) |worker| if (worker.failure) |failure| return failure;
        return .{ .values = columns };
    }

    var worker = Worker{
        .allocator = allocator,
        .program = &program,
        .calls = calls,
        .logical_of = logical_of,
        .columns = columns,
        .committed_start = 0,
        .committed_end = size,
    };
    try worker.runFallible();
    return .{ .values = columns };
}

/// Below this many eight-row blocks per worker the spawn cost outweighs the
/// streaming write bandwidth a second core adds.
const min_blocks_per_worker: usize = 512;

const Worker = struct {
    allocator: std.mem.Allocator,
    program: *const row_program.RowProgram,
    calls: []const production.Call,
    logical_of: []const usize,
    columns: [][]M31,
    committed_start: usize,
    committed_end: usize,
    failure: ?anyerror = null,

    fn run(self: *Worker) void {
        self.runFallible() catch |failure| {
            self.failure = failure;
        };
    }

    fn runFallible(self: *Worker) !void {
        const slots = try self.allocator.alloc(row_program.Block, self.program.slot_count);
        defer self.allocator.free(slots);
        const size = self.logical_of.len;
        var committed = self.committed_start;
        while (committed < self.committed_end) : (committed += row_program.LANES) {
            if (committed + row_program.LANES <= size) {
                self.program.writeBlock(
                    self.columns,
                    committed,
                    self.logical_of[committed..][0..row_program.LANES],
                    self.calls,
                    slots,
                );
                continue;
            }
            // Traces below eight rows: evaluate a full block into staging and
            // copy only the committed rows that exist.
            var logical_rows: [row_program.LANES]usize = undefined;
            for (&logical_rows, 0..) |*logical, lane| {
                logical.* = if (committed + lane < size)
                    self.logical_of[committed + lane]
                else
                    std.math.maxInt(usize);
            }
            const staging = try self.allocator.alloc(M31, self.columns.len * row_program.LANES);
            defer self.allocator.free(staging);
            const staging_columns = try self.allocator.alloc([]M31, self.columns.len);
            defer self.allocator.free(staging_columns);
            for (staging_columns, 0..) |*column, index|
                column.* = staging[index * row_program.LANES ..][0..row_program.LANES];
            self.program.writeBlock(staging_columns, 0, &logical_rows, self.calls, slots);
            for (self.columns, staging_columns) |column, staged| {
                const remaining = size - committed;
                @memcpy(column[committed..][0..remaining], staged[0..remaining]);
            }
            return;
        }
    }
};

fn allocateColumns(
    allocator: std.mem.Allocator,
    count: usize,
    size: usize,
) ![][]M31 {
    const columns = try allocator.alloc([]M31, count);
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |column| allocator.free(column);
        allocator.free(columns);
    }
    for (columns) |*column| {
        column.* = try allocator.alloc(M31, size);
        initialized += 1;
    }
    return columns;
}

fn freeColumns(allocator: std.mem.Allocator, columns: [][]M31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}

comptime {
    if (candidate_mod.Profile.degree5.expected().main_columns != 239) {
        @compileError("degree-five trace geometry drifted");
    }
}
