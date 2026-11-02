//! Shared two-wave native prefix scheduling and exact ordered summary scan.
//! The typed job supplies only component chunk arithmetic and physical prefix
//! correction. Output stays private to the caller until both joined waves pass.
const std = @import("std");
const Q = @import("stwo_core").fields.qm31.QM31;
const work = @import("stwo_prover_engine").work_pool;

/// Job contract: start/end/stride/correct/failure fields, pub run() void,
/// pub validateTotals(*const Job,[K]Q)!void. Initial chunk assignment is retained
/// verbatim. Correction assigns disjoint contiguous physical output ranges.
pub fn run(comptime K: usize, comptime Job: type, jobs: []Job, summaries: [][K]Q, rows: usize, pool: ?*work.WorkPool) ![K]Q {
    return runImpl(K, Job, jobs, summaries, rows, pool, null, null);
}
fn runImpl(comptime K: usize, comptime Job: type, jobs: []Job, summaries: [][K]Q, rows: usize, pool: ?*work.WorkPool, fail_wave: ?usize, fail_after: ?usize) ![K]Q {
    if (K == 0 or jobs.len == 0 or jobs.len > work.MAX_WORKERS or summaries.len == 0 or rows == 0) return error.InvalidNativePrefixGeometry;
    if (rows > std.math.maxInt(usize) / work.MAX_WORKERS) return error.InvalidNativePrefixGeometry;
    if (jobs.len > 1) {
        const active = pool orelse return error.InvalidNativePrefixGeometry;
        if (jobs.len > active.workerCount()) return error.InvalidNativePrefixGeometry;
        var lease = try active.acquire(try work.WorkerBudget.init(jobs.len));
        defer lease.deinit();
        try wave(Job, &lease, jobs, if (fail_wave == 0) fail_after else null);
        const totals = try scan(K, Job, jobs, summaries, rows);
        try wave(Job, &lease, jobs, if (fail_wave == 1) fail_after else null);
        return totals;
    }
    jobs[0].run();
    if (jobs[0].failure) |err| return err;
    const totals = try scan(K, Job, jobs, summaries, rows);
    jobs[0].run();
    if (jobs[0].failure) |err| return err;
    return totals;
}
/// One joined wave of independent jobs (no prefix scan). Job contract:
/// pub run() void and failure: ?anyerror. Jobs are joined before any failure is
/// reported; the first failing job in index order supplies the error.
pub fn single(comptime Job: type, jobs: []Job, pool: ?*work.WorkPool) !void {
    if (jobs.len == 0 or jobs.len > work.MAX_WORKERS) return error.InvalidNativePrefixGeometry;
    if (jobs.len == 1) {
        jobs[0].run();
        if (jobs[0].failure) |err| return err;
        return;
    }
    const active = pool orelse return error.InvalidNativePrefixGeometry;
    if (jobs.len > active.workerCount()) return error.InvalidNativePrefixGeometry;
    var lease = try active.acquire(try work.WorkerBudget.init(jobs.len));
    defer lease.deinit();
    try wave(Job, &lease, jobs, null);
}
/// Conservative relative-block policy: 32 M31 values = 128 bytes. This
/// establishes ownership of relative blocks, not hardware cache lines: the
/// allocator does not promise a 128-byte-aligned column base.
pub const GROUP_LOG_ROWS: u32 = 5;
pub const GROUP_ROWS: usize = 1 << GROUP_LOG_ROWS;
/// Choose bounded prefix segments with approximately four groups per worker.
pub fn lineSegmentLog(log: u32, max_log: u32, min_log: u32, workers_: usize) ?u32 {
    if (log < min_log + GROUP_LOG_ROWS + 1) return null;
    const spread: u32 = std.math.log2_int_ceil(usize, 4 * @max(1, workers_));
    const fit = if (log >= GROUP_LOG_ROWS + spread) log - GROUP_LOG_ROWS - spread else 0;
    const segment = @min(max_log, @min(fit, log - GROUP_LOG_ROWS - 1));
    return if (segment >= min_log) segment else null;
}
pub fn lineGroupCount(log: u32, segment_log: u32) usize {
    std.debug.assert(log >= segment_log + GROUP_LOG_ROWS + 1);
    return @as(usize, 1) << @intCast(log - segment_log - GROUP_LOG_ROWS);
}
/// Every group owns GROUP_ROWS segments and complete relative 128-byte blocks.
/// For logical row `(segment << segment_log) | r`, bit-reversed circle order
/// reverses the segment bits on even r and complements them on odd r. Vary the
/// highest GROUP_LOG_ROWS-1 segment bits and pair the remaining low bits with
/// their complement. Matching r and (2^segment_log-1-r) from those halves fill
/// one complete physical block. Distinct groups cannot share a relative block.
/// Rows need not be emitted in that paired order; each segment keeps its own
/// logical prefix, which is corrected by the ordered summary scan.
pub fn lineGroupSegments(log: u32, segment_log: u32, group: usize) [GROUP_ROWS]usize {
    std.debug.assert(group < lineGroupCount(log, segment_log));
    const q: std.math.Log2Int(usize) = @intCast(log - segment_log - (GROUP_LOG_ROWS - 1));
    const mask = (@as(usize, 1) << q) - 1;
    var segments: [GROUP_ROWS]usize = undefined;
    for (&segments, 0..) |*segment, t| {
        const high = t % (GROUP_ROWS / 2);
        const low = if (t < GROUP_ROWS / 2) group else group ^ mask;
        segment.* = (high << q) | low;
    }
    return segments;
}
/// Worker count for `rows` split into `grain`-row units under `pool`.
pub fn workers(pool: ?*work.WorkPool, rows: usize, grain: usize) usize {
    const units = @max(1, std.math.divCeil(usize, rows, grain) catch unreachable);
    return if (pool) |p| @max(1, @min(p.workerCount(), units)) else 1;
}
fn scan(comptime K: usize, comptime Job: type, jobs: []Job, summaries: [][K]Q, rows: usize) ![K]Q {
    var totals: [K]Q = @splat(Q.zero());
    for (summaries) |*summary| {
        const local = summary.*;
        summary.* = totals;
        for (&totals, local) |*total, value| total.* = total.add(value);
    }
    try jobs[0].validateTotals(totals);
    for (summaries) |*summary| for (summary, totals) |*offset, total| {
        offset.* = offset.sub(total);
    };
    for (jobs, 0..) |*job, i| {
        job.correct = true;
        job.start = rows * i / jobs.len;
        job.end = rows * (i + 1) / jobs.len;
    }
    return totals;
}
fn wave(comptime Job: type, lease: *work.WorkLease, jobs: []Job, fail_after: ?usize) !void {
    var group = std.Thread.WaitGroup{};
    var joined = false;
    defer {
        if (!joined) group.wait();
        lease.completeWave();
    }
    for (jobs[1..], 0..) |*job, submitted| {
        if (fail_after == submitted) return error.InjectedNativePrefixSubmissionFailure;
        try lease.spawnWg(&group, Job.run, .{job});
    }
    jobs[0].run();
    group.wait();
    joined = true;
    for (jobs) |job| if (job.failure) |err| return err;
}
pub const testing = if (@import("builtin").is_test) struct {
    pub fn failSubmission(comptime K: usize, comptime Job: type, jobs: []Job, summaries: [][K]Q, rows: usize, pool: *work.WorkPool, which_wave: usize, after: usize) ![K]Q {
        return runImpl(K, Job, jobs, summaries, rows, pool, which_wave, after);
    }
} else struct {};
