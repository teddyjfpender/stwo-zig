//! Parallel main-trace writer for the degree-five Poseidon2 candidate.
//!
//! Every worker owns its semantic scratch while the compiler authority and
//! committed column storage are immutable/shared.  Logical rows write to
//! distinct bit-reversed destinations, so no lock or per-row allocation is
//! required.  Padding is zero-filled before workers launch.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const infra = @import("../../infra_trace.zig");
const work_pool = @import("stwo_prover_engine").work_pool;
const candidate_mod = @import("typed_poseidon2_degree_bounded_candidate.zig");
const poseidon = @import("typed_poseidon2.zig");
const production = @import("../memory_commitment/poseidon2_air.zig");
const types = @import("types.zig");

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
    try candidate.validate();
    if (candidate.profile != .degree5 or log_size >= @bitSizeOf(usize))
        return error.InvalidCandidateTrace;
    const size = @as(usize, 1) << @intCast(log_size);
    if (calls.len > size) return error.InvalidTraceShape;
    const columns = try allocateColumns(
        allocator,
        candidate.mainColumnCount(),
        size,
    );
    errdefer freeColumns(allocator, columns);
    const table = try infra.BitReversalTable.init(allocator, log_size);
    defer table.deinit(allocator);

    if (work_pool.getGlobalPool()) |pool| {
        const worker_count = @min(
            pool.workerCount(),
            @max(@as(usize, 1), calls.len / 4096),
        );
        if (worker_count > 1) {
            const workers = try allocator.alloc(Worker, worker_count);
            defer allocator.free(workers);
            for (workers, 0..) |*worker, index| {
                worker.* = .{
                    .allocator = allocator,
                    .candidate = candidate,
                    .calls = calls,
                    .mapping = table.mapping,
                    .columns = columns,
                    .logical_start = calls.len * index / worker_count,
                    .logical_end = calls.len * (index + 1) / worker_count,
                };
            }
            var wait_group = std.Thread.WaitGroup{};
            for (workers[1..]) |*worker| {
                pool.spawnWg(&wait_group, Worker.run, .{worker});
            }
            Worker.run(&workers[0]);
            wait_group.wait();
            for (workers) |worker| if (worker.failure) |failure| return failure;
            return .{ .values = columns };
        }
    }

    const scratch = try allocator.alloc(M31, candidate.arena.nodeCount());
    defer allocator.free(scratch);
    for (calls, 0..) |call, logical_row| {
        try fillRow(
            candidate,
            columns,
            table.map(logical_row),
            call,
            scratch,
        );
    }
    return .{ .values = columns };
}

const Worker = struct {
    allocator: std.mem.Allocator,
    candidate: *const candidate_mod.Candidate,
    calls: []const production.Call,
    mapping: []const usize,
    columns: [][]M31,
    logical_start: usize,
    logical_end: usize,
    failure: ?anyerror = null,

    fn run(self: *Worker) void {
        self.runFallible() catch |failure| {
            self.failure = failure;
        };
    }

    fn runFallible(self: *Worker) !void {
        const scratch = try self.allocator.alloc(
            M31,
            self.candidate.arena.nodeCount(),
        );
        defer self.allocator.free(scratch);
        for (self.calls[self.logical_start..self.logical_end], self.logical_start..) |
            call,
            logical_row,
        | {
            try fillRow(
                self.candidate,
                self.columns,
                self.mapping[logical_row],
                call,
                scratch,
            );
        }
    }
};

fn fillRow(
    candidate: *const candidate_mod.Candidate,
    columns: [][]M31,
    committed_row: usize,
    call: production.Call,
    scratch: []M31,
) !void {
    if (columns.len != candidate.mainColumnCount() or
        scratch.len != candidate.arena.nodeCount())
    {
        return error.InvalidCandidateTrace;
    }
    try evaluateSemantic(candidate, call.input, scratch);
    columns[0][committed_row] = M31.one();
    for (call.input, 0..) |word, lane| {
        columns[1 + lane][committed_row] = M31.fromU64(word);
    }
    for (candidate.selected_values, 0..) |value, ordinal| {
        columns[candidate_mod.MATERIALIZATION_COLUMN_START + ordinal][committed_row] =
            scratch[types.idIndex(value)];
    }
    columns[columns.len - 2][committed_row] =
        M31.fromU64(@intFromBool(call.wide));
    columns[columns.len - 1][committed_row] =
        M31.fromU64(@intFromBool(call.io));
}

fn evaluateSemantic(
    candidate: *const candidate_mod.Candidate,
    input: [candidate_mod.WIDTH]u32,
    scratch: []M31,
) !void {
    const inputs = poseidon.values(candidate.definition.inputs);
    for (candidate.arena.nodesView(), 0..) |node, index| {
        scratch[index] = switch (node.key.op) {
            .constant => |constant| switch (constant) {
                .field => |value| M31.fromCanonical(value),
                .unsigned => |value| M31.fromU64(value),
            },
            .input => blk: {
                const value: types.ValueId = @enumFromInt(index);
                if (value == candidate.gate) break :blk M31.one();
                for (inputs, 0..) |input_value, lane| {
                    if (value == input_value) break :blk M31.fromU64(input[lane]);
                }
                return error.UnsupportedCandidateExpression;
            },
            .add => |operation| scratch[types.idIndex(operation.lhs)].add(
                scratch[types.idIndex(operation.rhs)],
            ),
            .sub => |operation| scratch[types.idIndex(operation.lhs)].sub(
                scratch[types.idIndex(operation.rhs)],
            ),
            .mul => |operation| scratch[types.idIndex(operation.lhs)].mul(
                scratch[types.idIndex(operation.rhs)],
            ),
            .neg => |operand| scratch[types.idIndex(operand)].neg(),
            .select => |selection| if (!scratch[
                types.idIndex(selection.selector)
            ].isZero())
                scratch[types.idIndex(selection.when_true)]
            else
                scratch[types.idIndex(selection.when_false)],
            .hint_output, .call_output, .machine_derived => return error.UnsupportedCandidateExpression,
        };
    }
}

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
        @memset(column.*, M31.zero());
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
