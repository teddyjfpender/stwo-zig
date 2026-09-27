//! Process-local parallel projection for freshly evaluated VM composition rows.
//! This is not an authority boundary: the caller supplies an authenticated
//! schedule and the exact evaluation retained by `Prepared`.

const dependency = @import("vm_air_composition_circuit_error.zig");

const std = dependency.std;
const M31 = dependency.M31;
const QM31 = dependency.QM31;
const graph_mod = dependency.graph_mod;
const row18_witness = dependency.row18_witness;
const Error = dependency.Error;

pub const MAX_WORKER_COUNT: usize = 256;
pub const ProjectionRow = row18_witness.Row;
const CHUNK_ROW_COUNT: usize = 4096;

pub fn fillScheduleValues(
    allocator: std.mem.Allocator,
    rows: []const row18_witness.Row,
    evaluation_values: []const QM31,
    destination: []M31,
    circuit_id: u32,
    requested_worker_count: usize,
) Error!void {
    if (rows.len != destination.len)
        return error.CircuitIdentityMismatch;
    std.debug.assert(requested_worker_count > 0);
    std.debug.assert(requested_worker_count <= MAX_WORKER_COUNT);
    if (rows.len == 0) return;

    const chunk_count = std.math.divCeil(
        usize,
        rows.len,
        CHUNK_ROW_COUNT,
    ) catch unreachable;
    const worker_count = @min(requested_worker_count, chunk_count);
    var work = Work{
        .rows = rows,
        .evaluation_values = evaluation_values,
        .destination = destination,
        .circuit_id = circuit_id,
    };
    if (worker_count == 1) {
        work.run();
    } else {
        var pool: std.Thread.Pool = undefined;
        pool.init(.{
            .allocator = allocator,
            .n_jobs = worker_count - 1,
        }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.GraphConstructionFailed,
        };
        defer pool.deinit();
        var wait_group: std.Thread.WaitGroup = .{};
        for (1..worker_count) |_|
            pool.spawnWg(&wait_group, Work.run, .{&work});
        work.run();
        pool.waitAndWork(&wait_group);
    }

    const failures = work.failures.load(.acquire);
    if (failures & FAILURE_CIRCUIT != 0)
        return error.CircuitIdentityMismatch;
    if (failures & FAILURE_BASE_FIELD != 0)
        return error.InputIsNotBaseField;
}

const FAILURE_CIRCUIT: u8 = 1 << 0;
const FAILURE_BASE_FIELD: u8 = 1 << 1;

const Work = struct {
    rows: []const row18_witness.Row,
    evaluation_values: []const QM31,
    destination: []M31,
    circuit_id: u32,
    next_chunk: std.atomic.Value(usize) = .init(0),
    failures: std.atomic.Value(u8) = .init(0),

    fn run(self: *Work) void {
        while (true) {
            const chunk = self.next_chunk.fetchAdd(1, .monotonic);
            const start = std.math.mul(
                usize,
                chunk,
                CHUNK_ROW_COUNT,
            ) catch return;
            if (start >= self.rows.len) return;
            const end = start + @min(
                CHUNK_ROW_COUNT,
                self.rows.len - start,
            );
            for (self.rows[start..end], self.destination[start..end]) |
                row,
                *value,
            | {
                value.* = rowValue(
                    row,
                    self.evaluation_values,
                    self.circuit_id,
                ) catch |err| blk: {
                    const failure: u8 = switch (err) {
                        error.InputIsNotBaseField => FAILURE_BASE_FIELD,
                        else => FAILURE_CIRCUIT,
                    };
                    _ = self.failures.fetchOr(failure, .release);
                    break :blk M31.zero();
                };
            }
        }
    }
};

fn rowValue(
    row: row18_witness.Row,
    evaluation_values: []const QM31,
    circuit_id: u32,
) Error!M31 {
    if (row.circuit_id != circuit_id)
        return error.CircuitIdentityMismatch;
    return switch (row.classification) {
        .vm_input => blk: {
            if (row.node_id >= evaluation_values.len)
                return error.CircuitIdentityMismatch;
            break :blk evaluation_values[row.node_id].tryIntoM31() catch
                return error.InputIsNotBaseField;
        },
        .constant_anchor, .output_anchor => |modes| blk: {
            if (!std.meta.eql(modes, graph_mod.ModeSet.SEGMENT))
                return error.CircuitIdentityMismatch;
            break :blk M31.zero();
        },
        .recursion_input => return error.CircuitIdentityMismatch,
    };
}

test "fresh composition schedule projection is deterministic across workers" {
    const allocator = std.testing.allocator;
    const rows = try allocator.alloc(row18_witness.Row, CHUNK_ROW_COUNT + 1);
    defer allocator.free(rows);
    for (rows) |*row| row.* = .{
        .classification = .{ .vm_input = .segment_selector },
        .circuit_id = 1,
        .node_id = 0,
        .use_count = 1,
    };
    const evaluation = [_]QM31{QM31.fromBase(M31.fromCanonical(19))};
    const serial = try allocator.alloc(M31, rows.len);
    defer allocator.free(serial);
    const parallel = try allocator.alloc(M31, rows.len);
    defer allocator.free(parallel);

    try fillScheduleValues(
        allocator,
        rows,
        &evaluation,
        serial,
        1,
        1,
    );
    try fillScheduleValues(
        allocator,
        rows,
        &evaluation,
        parallel,
        1,
        4,
    );
    try std.testing.expectEqualSlices(M31, serial, parallel);
}
