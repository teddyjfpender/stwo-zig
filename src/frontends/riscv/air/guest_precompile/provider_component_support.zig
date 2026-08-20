//! Allocation and sampling helpers for the guest Poseidon2 provider adapter.

const std = @import("std");
const circle = @import("stwo_core").circle;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const prover_engine = @import("stwo_prover_engine");
const prover_task_graph = prover_engine.task_graph;
const prover_work_pool = prover_engine.work_pool;
const components = @import("component_registry.zig");
const direct = @import("direct_constraints.zig");

const CirclePointQM31 = circle.CirclePointQM31;
const main_column_count = direct.provider_main_column_count;
const batch_count = components.provider_batch_count;

pub fn serialTaskContext(
    context: *anyopaque,
    cancellation: *const prover_task_graph.CancellationToken,
) prover_task_graph.TaskContext {
    return .{
        .user_context = context,
        .cancellation = cancellation,
        .key = .{
            .epoch = 0,
            .stage_rank = 0,
            .component_registry_index = 0,
            .shard_or_chunk_index = 0,
        },
        .worker_budget = prover_work_pool.WorkerBudget.serial(),
        .task_class = .leaf,
        .exclusive_lease = null,
        .child_wait_group = null,
    };
}

pub fn pointColumns(
    allocator: std.mem.Allocator,
    count: usize,
    points: []const CirclePointQM31,
) ![][]CirclePointQM31 {
    const result = try allocator.alloc([]CirclePointQM31, count);
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |column| allocator.free(column);
        allocator.free(result);
    }
    for (result) |*column| {
        column.* = try allocator.dupe(CirclePointQM31, points);
        initialized += 1;
    }
    return result;
}

pub fn freePointColumns(
    allocator: std.mem.Allocator,
    columns: [][]CirclePointQM31,
) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}

pub fn sampleMain(columns: [][]QM31) ![main_column_count]QM31 {
    if (columns.len != main_column_count) return error.InvalidProofShape;
    var result: [main_column_count]QM31 = undefined;
    for (&result, columns) |*value, column| {
        if (column.len != 1) return error.InvalidProofShape;
        value.* = column[0];
    }
    return result;
}

pub fn sampleInteraction(
    columns: [][]QM31,
    offset: usize,
    current: *[batch_count]QM31,
    previous: *[batch_count]QM31,
) !void {
    for (0..batch_count) |batch| {
        current[batch] = try sampledSecure(columns, offset + 4 * batch, 0);
        previous[batch] = try sampledSecure(columns, offset + 4 * batch, 1);
    }
}

pub fn sampledSecure(columns: [][]QM31, offset: usize, point: usize) !QM31 {
    if (columns.len < offset + 4) return error.InvalidProofShape;
    var coordinates: [4]QM31 = undefined;
    for (&coordinates, 0..) |*value, index| {
        if (columns[offset + index].len != 2) return error.InvalidProofShape;
        value.* = columns[offset + index][point];
    }
    return QM31.fromPartialEvals(coordinates);
}

pub fn readMain(
    columns: []const []const M31,
    row: usize,
) [main_column_count]QM31 {
    var result: [main_column_count]QM31 = undefined;
    for (&result, columns) |*value, column| {
        value.* = QM31.fromBase(column[row]);
    }
    return result;
}

pub fn readInteraction(
    evaluations: []const []const M31,
    start: usize,
    row: usize,
    previous_row: usize,
    current: *[batch_count]QM31,
    previous: *[batch_count]QM31,
) void {
    for (0..batch_count) |batch| {
        const columns = evaluations[start + 4 * batch ..][0..4];
        current[batch] = secureAt(columns, row);
        previous[batch] = secureAt(columns, previous_row);
    }
}

pub fn secureAt(columns: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(
        columns[0][row],
        columns[1][row],
        columns[2][row],
        columns[3][row],
    );
}
