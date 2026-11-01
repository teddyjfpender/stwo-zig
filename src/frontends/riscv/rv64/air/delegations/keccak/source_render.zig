//! Native witness placement only: one metadata gather feeds sixteen contiguous
//! physical rows in every column. No permutation or polynomial is evaluated.
const std = @import("std");
const builtin = @import("builtin");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const L = @import("layout.zig");
const PackedRow = @import("packed_row.zig").PackedRow;
const M = core.fields.m31.M31;
const work = engine.work_pool;
pub const ROWS: usize = 16;
pub const MIN_STACK: usize = if (builtin.mode == .Debug) 1024 * 1024 else 256 * 1024;
pub fn render(metadata: []const PackedRow, main: []M, log: u32, pool: ?*work.WorkPool) !void {
    return renderProfiled(metadata, main, log, pool, null);
}
pub fn renderProfiled(metadata: []const PackedRow, main: []M, log: u32, pool: ?*work.WorkPool, used_workers: ?*usize) !void {
    if (used_workers) |out| out.* = 1;
    if (log < 5 or log > 26) return error.InvalidKeccakMainPhase;
    const n = @as(usize, 1) << @intCast(log);
    if (main.len != L.MAIN * n or metadata.len > n) return error.InvalidKeccakMainPhase;
    try @import("../main_storage.zig").exclude(&.{.{ .values = main, .cells = L.MAIN * n }}, std.mem.sliceAsBytes(metadata));
    for (metadata) |row| if (row.id >= core.fields.m31.Modulus or row.flags > 3) return error.InvalidKeccakMetadata;
    // Small witnesses run on the caller. Each production helper gets at least
    // 4096 rows (~30MiB MAIN); tests lower only this dispatch threshold so tiny
    // fixtures exercise identical placement and partial-submission cleanup.
    const min_rows: usize = if (builtin.is_test) ROWS else 4096;
    const workers = if (pool) |p| @min(p.workerCount(), @max(1, n / min_rows)) else 1;
    if (workers == 1) {
        var job = Job{ .metadata = metadata, .main = main, .log = log, .begin = 0, .end = n };
        job.run();
        return;
    }
    if (pool.?.stackSize() < MIN_STACK) return error.InvalidKeccakSourceWorkerStack;
    // A concurrent proof may already own the scoped pool. Placement can always
    // run on the caller without introducing a nested wait or changing bytes.
    var lease = pool.?.acquire(try work.WorkerBudget.init(workers)) catch |err| switch (err) {
        error.WorkerBudgetUnavailable => {
            var job = Job{ .metadata = metadata, .main = main, .log = log, .begin = 0, .end = n };
            job.run();
            return;
        },
        else => return err,
    };
    defer lease.deinit();
    if (used_workers) |out| out.* = workers;
    var jobs: [work.MAX_WORKERS]Job = undefined;
    const tiles = n / ROWS;
    for (jobs[0..workers], 0..) |*job, i| job.* = .{ .metadata = metadata, .main = main, .log = log, .begin = tiles * i / workers * ROWS, .end = tiles * (i + 1) / workers * ROWS };
    var group = std.Thread.WaitGroup{};
    defer {
        group.wait();
        lease.completeWave();
    }
    for (jobs[1..workers], 0..) |*job, i| {
        if (comptime builtin.is_test) if (testing.fail_after_submissions == i) return error.InjectedKeccakSourceSubmissionFailure;
        try lease.spawnWg(&group, Job.run, .{job});
    }
    jobs[0].run();
}
const Job = struct {
    metadata: []const PackedRow,
    main: []M,
    log: u32,
    begin: usize,
    end: usize,
    fn run(self: *const Job) void {
        const n = @as(usize, 1) << @intCast(self.log);
        var start = self.begin;
        while (start < self.end) : (start += ROWS) {
            var rows: [ROWS]PackedRow = undefined;
            for (&rows, 0..) |*row, i| {
                const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(start + i, self.log), self.log);
                row.* = if (logical < self.metadata.len) self.metadata[logical] else .{};
            }
            for (0..L.STATE) |c| {
                for (&rows, self.main[c * n + start ..][0..ROWS]) |*row, *out|
                    out.* = row.stateCell(c);
            }
            for (0..L.PARITY) |c| {
                for (&rows, self.main[(L.STATE + c) * n + start ..][0..ROWS]) |*row, *out|
                    out.* = row.parityCell(c);
            }
            for (&rows, 0..) |*row, i| {
                self.main[L.ACTIVE_A * n + start + i] = M.fromCanonical(row.flags & 1);
                self.main[L.ACTIVE_B * n + start + i] = M.fromCanonical((row.flags >> 1) & 1);
                self.main[L.BASE_ID * n + start + i] = M.fromCanonical(row.id);
            }
        }
    }
};
pub const testing = if (builtin.is_test) struct {
    pub var fail_after_submissions: ?usize = null;
    /// Retained logical-row scatter oracle. Expand uses the same canonical
    /// packed-row interpretation; independent native witnesses are tested too.
    pub fn scatter(metadata: []const PackedRow, main: []M, log: u32) !void {
        const n = @as(usize, 1) << @intCast(log);
        @memset(main, M.zero());
        for (metadata, 0..) |row, logical| {
            const values = try row.expand();
            const p = @import("../../witness.zig").physical(logical, log);
            for (values, 0..) |value, c| main[c * n + p] = value;
        }
    }
} else struct {};
