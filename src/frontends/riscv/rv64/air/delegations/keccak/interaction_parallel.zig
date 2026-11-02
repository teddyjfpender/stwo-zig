//! Two joined waves: relative logical prefixes, then physical-column offsets.
//! All writes remain private until interaction.generate publishes the result.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const I = @import("interaction.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const work = engine.work_pool;
pub const MIN_STACK = if (@import("builtin").mode == .Debug) 1024 * 1024 else 256 * 1024;
pub const MIN_ROWS_PER_WORKER = 64;
const CORRECTION_ROWS = 256;
/// Non-default failure hooks are reachable only from the test-only wrapper.
pub const Faults = struct {
    prefix_spawn_after: ?usize = null,
    correction_spawn_after: ?usize = null,
    correction_fail_job: ?usize = null,
};
pub fn workerCount(n: usize, pool: ?*work.WorkPool) !usize {
    const active = pool orelse return 1;
    const workers = @min(active.workerCount(), @max(1, n / MIN_ROWS_PER_WORKER));
    if (workers > 1 and active.stackSize() < MIN_STACK) return error.InvalidKeccakInteractionWorkerStack;
    return workers;
}
pub fn generate(prepared: *const I.Prepared, pool: *work.WorkPool, workers: usize, recorder: ?*engine.stage_profile.Recorder, faults: Faults) !Q {
    std.debug.assert(workers > 1 and workers <= work.MAX_WORKERS);
    var lease = try pool.acquire(try work.WorkerBudget.init(workers));
    defer lease.deinit();
    var jobs: [work.MAX_WORKERS]Prefix = undefined;
    const n = prepared.trace.size();
    for (jobs[0..workers], 0..) |*job, i| job.* = .{ .prepared = prepared, .start = n * i / workers, .end = n * (i + 1) / workers };
    {
        var stage = try engine.stage_profile.StageScope.begin(recorder, "keccak_interaction_prefix", "Keccak chunk-relative lookup prefixes");
        defer stage.end();
        var group: std.Thread.WaitGroup = .{};
        defer {
            group.wait();
            lease.completeWave();
        }
        for (jobs[1..workers], 0..) |*job, submitted| {
            if (faults.prefix_spawn_after == submitted) return error.InjectedKeccakPrefixSubmissionFailure;
            try lease.spawnWg(&group, Prefix.run, .{job});
        }
        jobs[0].run();
    }
    // Stable logical chunk order determines both the final claim and offsets.
    var offsets: [work.MAX_WORKERS]Q = undefined;
    var claim = Q.zero();
    for (jobs[0..workers], offsets[0..workers]) |job, *offset| {
        if (job.err) |err| return err;
        offset.* = claim;
        claim = claim.add(job.sum);
    }
    var corrections: [work.MAX_WORKERS]Correction = undefined;
    for (corrections[0..workers], 0..) |*job, i| job.* = .{ .prepared = prepared, .offsets = &offsets, .workers = workers, .start = prepared.batch_policy.batches() * i / workers, .end = prepared.batch_policy.batches() * (i + 1) / workers, .fail = faults.correction_fail_job == i };
    {
        var stage = try engine.stage_profile.StageScope.begin(recorder, "keccak_interaction_correction", "Keccak physical prefix-offset pass");
        defer stage.end();
        var group: std.Thread.WaitGroup = .{};
        defer {
            group.wait();
            lease.completeWave();
        }
        for (corrections[1..workers], 0..) |*job, submitted| {
            if (faults.correction_spawn_after == submitted) return error.InjectedKeccakCorrectionSubmissionFailure;
            try lease.spawnWg(&group, Correction.run, .{job});
        }
        corrections[0].run();
    }
    for (corrections[0..workers]) |job| if (job.err) |err| return err;
    return claim;
}
const Prefix = struct {
    prepared: *const I.Prepared,
    start: usize,
    end: usize,
    sum: Q = Q.zero(),
    err: ?anyerror = null,
    fn run(self: *Prefix) void {
        self.sum = self.prepared.fillRange(self.start, self.end) catch |err| {
            self.err = err;
            return;
        };
    }
};
const Correction = struct {
    prepared: *const I.Prepared,
    offsets: *const [work.MAX_WORKERS]Q,
    workers: usize,
    start: usize,
    end: usize,
    fail: bool,
    err: ?anyerror = null,
    fn run(self: *Correction) void {
        const trace = self.prepared.trace;
        const n = trace.size();
        // Each worker owns disjoint secure-column groups. The bounded physical
        // tile computes inverse placement once, rather than once per column.
        var delta: [4][CORRECTION_ROWS]M = undefined;
        var begin: usize = 0;
        while (begin < n) : (begin += CORRECTION_ROWS) {
            const count = @min(CORRECTION_ROWS, n - begin);
            for (0..count) |r| {
                const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(begin + r, trace.log_size), trace.log_size);
                // Inverse of [floor(n*i/W),floor(n*(i+1)/W)); floor(r*W/n)
                // is wrong exactly at uneven chunk boundaries.
                const chunk = ((logical + 1) * self.workers - 1) / n;
                const limbs = self.offsets[chunk].toM31Array();
                for (0..4) |c| delta[c][r] = limbs[c];
            }
            for (self.start..self.end) |batch| for (0..4) |c| {
                const column = self.prepared.data[(4 * batch + c) * n + begin ..][0..count];
                for (column, delta[c][0..count]) |*value, offset| value.* = value.add(offset);
            };
            if (self.fail) {
                self.err = error.InjectedKeccakCorrectionFailure;
                return;
            }
        }
    }
};
