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
