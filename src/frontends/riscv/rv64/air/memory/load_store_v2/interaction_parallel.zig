//! Two joined native waves, bounded scratch and provisional output. The one
//! row writer is shared with the explicit serial reference in interaction.zig.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const S = @import("source.zig");
const I = @import("interaction.zig");
const T = @import("types.zig");
const L = @import("layout.zig");
const M = T.M;
const Q = T.Q;
const work = engine.work_pool;
pub const MIN_STACK_BYTES = if (@import("builtin").mode == .Debug) 1024 * 1024 else 256 * 1024;
const CHUNK: usize = 4096;
const LOG_CHUNK: u32 = 12;
const BLOCK: usize = CHUNK / 16;
const LOG_BLOCK: u32 = LOG_CHUNK - 4;
const Prefix = @import("../../providers/prefix_waves.zig");
comptime {
    std.debug.assert(CHUNK == @as(usize, 1) << LOG_CHUNK);
}
const PREFIX = [_]usize{ 4, L.LOCAL_PREFIX };
pub fn generate(source: *S.Source, ch: T.Challenges, d16: []const Q, d8: []const Q, pool: ?*work.WorkPool) !T.Claims {
    return generateImpl(source, ch, d16, d8, pool, null, null);
}
fn generateImpl(source: *S.Source, ch: T.Challenges, d16: []const Q, d8: []const Q, pool: ?*work.WorkPool, fail_wave: ?usize, fail_after: ?usize) !T.Claims {
    if (pool) |p| if (p.stackSize() < MIN_STACK_BYTES) return error.InvalidLsInteractionStack;
    const n = try I.validateMetadata(source);
    const chunks = std.math.divCeil(usize, n, CHUNK) catch unreachable;
    // Line-complete groups (prefix_waves.lineGroupSegments) when the domain
    // gives every worker several groups; otherwise round-robin chunks.
    const segment_log = if (pool) |p| Prefix.lineSegmentLog(source.log_size, LOG_CHUNK, LOG_BLOCK, p.workerCount()) else null;
    const units = if (segment_log) |log| Prefix.lineGroupCount(source.log_size, log) else chunks;
    const segments = if (segment_log) |log| n >> @intCast(log) else chunks;
    const workers: usize = if (pool) |p| @min(p.workerCount(), units) else 1;
    if (workers <= 1) return I.generateSerial(source, ch, d16, d8);
    try I.validateDictionary(ch.range16, d16, 65536);
    try I.validateDictionary(ch.range8, d8, 256);
    const a = source.allocator;
    const selection = try I.ParallelSupport.selectionDictionary(a, ch.selection);
    defer a.free(selection);
    var claims = T.Claims.zero();
    claims.range16 = try I.countDot(source.counts16, d16);
    claims.range8 = try I.countDot(source.counts8, d8);
    claims.selection = try I.countDot(source.selection_counts, selection);
    const output = try a.alloc(M, L.INTERACTION * n);
    errdefer a.free(output);
    @import("../../native_output_pages.zig").prepare(output);
    const scratch = try a.alloc(Q, workers * 5 * CHUNK);
    defer a.free(scratch);
    const summaries = try a.alloc([5]Q, segments);
    defer a.free(summaries);
    var jobs: [work.MAX_WORKERS]Job = undefined;
    for (jobs[0..workers], 0..) |*job, i| job.* = .{ .source = source, .ch = ch, .d16 = d16, .d8 = d8, .selection = selection, .output = output, .scratch = scratch[i * 5 * CHUNK ..][0 .. 5 * CHUNK], .summaries = summaries, .start = i, .end = units, .stride = workers, .segment_log = segment_log orelse LOG_CHUNK, .grouped = segment_log != null };
    var lease = try pool.?.acquire(try work.WorkerBudget.init(workers));
    defer lease.deinit();
    try wave(&lease, jobs[0..workers], if (fail_wave == 0) fail_after else null);
    var totals: [5]Q = @splat(Q.zero());
    for (summaries) |*summary| {
        const local = summary.*;
        summary.* = totals;
        for (&totals, local) |*sum, value| sum.* = sum.add(value);
    }
    if (!totals[2].eql(claims.range16) or !totals[3].eql(claims.range8) or !totals[4].eql(claims.selection)) return error.InvalidLsCounts;
    claims.ram = totals[0];
    claims.owner = totals[1];
    for (summaries) |*summary| for (summary, totals) |*offset, total| {
        offset.* = offset.sub(total);
    };
    for (jobs[0..workers], 0..) |*job, i| {
        job.correct = true;
        job.start = n * i / workers;
        job.end = n * (i + 1) / workers;
    }
    try wave(&lease, jobs[0..workers], if (fail_wave == 1) fail_after else null);
    source.interaction = output;
    a.free(source.metadata);
    source.metadata = &.{};
    return claims;
}
const Job = struct {
    source: *const S.Source,
    ch: T.Challenges,
    d16: []const Q,
    d8: []const Q,
    selection: []const Q,
    output: []M,
    scratch: []Q,
    summaries: [][5]Q,
    start: usize,
    end: usize,
    stride: usize,
    segment_log: u32,
    grouped: bool,
    correct: bool = false,
    failure: ?anyerror = null,
    fn run(self: *Job) void {
        self.execute() catch |err| {
            self.failure = err;
        };
    }
    fn execute(self: *Job) !void {
        const n = self.source.size();
        if (self.correct) {
            for (self.start..self.end) |physical| {
                const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(physical, self.source.log_size), self.source.log_size);
                const sums = self.summaries[logical >> @intCast(self.segment_log)];
                const offsets = [2]Q{ sums[0], sums[1].add(sums[2]).add(sums[3]).add(sums[4]) };
                for (PREFIX, offsets) |column, offset| for (offset.toM31Array(), 0..) |value, c| {
                    const at = (column + c) * n + physical;
                    self.output[at] = self.output[at].add(value);
                };
            }
        } else if (self.grouped) {
            var group = self.start;
            while (group < self.end) : (group += self.stride) try self.fillGroup(group);
        } else {
            // Round-robin logical chunks keep each worker's low physical runs
            // together under bit reversal, reducing cache-line sharing.
            var chunk = self.start;
            while (chunk < self.end) : (chunk += self.stride) {
                var sums: [5]Q = @splat(Q.zero());
                try I.ParallelSupport.fillChunk(self.source, self.ch, self.d16, self.d8, self.selection, self.output, self.scratch, chunk * CHUNK, &sums);
                self.summaries[chunk] = sums;
            }
        }
    }
    /// Row r of the group's 16 segments back to back: whole-line stores.
    /// Each segment keeps its own logical running sums, as fillChunk does.
    fn fillGroup(self: *Job, group: usize) !void {
        const segments = Prefix.lineGroupSegments(self.source.log_size, self.segment_log, group);
        const size = @as(usize, 1) << @intCast(self.segment_log);
        var sums: [16][5]Q = @splat(@splat(Q.zero()));
        const product = self.scratch[0..CHUNK];
        const delta = self.scratch[CHUNK..][0..CHUNK];
        const owner = self.scratch[2 * CHUNK ..][0..CHUNK];
        const inv = self.scratch[3 * CHUNK ..][0..CHUNK];
        const inv_owner = self.scratch[4 * CHUNK ..][0..CHUNK];
        var r0: usize = 0;
        while (r0 < size) : (r0 += BLOCK) {
            for (segments, 0..) |segment, t| I.ParallelSupport.rowDenominators(self.source.metadata[segment * size + r0 ..][0..BLOCK], self.ch, product[t * BLOCK ..][0..BLOCK], delta[t * BLOCK ..][0..BLOCK], owner[t * BLOCK ..][0..BLOCK]);
            try core.fields.batchInverseInPlace(Q, product, inv);
            try core.fields.batchInverseInPlace(Q, owner, inv_owner);
            for (0..BLOCK) |r| for (segments, 0..) |segment, t| {
                const k = t * BLOCK + r;
                I.ParallelSupport.fillRow(self.source, self.d16, self.d8, self.selection, self.output, segment * size + r0 + r, inv[k], delta[k], inv_owner[k], &sums[t]);
            };
        }
        for (segments, sums) |segment, sum| self.summaries[segment] = sum;
    }
};
fn wave(lease: *work.WorkLease, jobs: []Job, fail_after: ?usize) !void {
    var group = std.Thread.WaitGroup{};
    var joined = false;
    defer {
        if (!joined) group.wait();
        lease.completeWave();
    }
    for (jobs[1..], 0..) |*job, submitted| {
        if (fail_after == submitted) return error.InjectedLsInteractionSubmissionFailure;
        try lease.spawnWg(&group, Job.run, .{job});
    }
    jobs[0].run();
    group.wait();
    joined = true;
    for (jobs) |job| if (job.failure) |failure| return failure;
}
pub const testing = if (@import("builtin").is_test) struct {
    pub fn failSubmission(source: *S.Source, ch: T.Challenges, d16: []const Q, d8: []const Q, pool: *work.WorkPool, which_wave: usize, after: usize) !T.Claims {
        return generateImpl(source, ch, d16, d8, pool, which_wave, after);
    }
} else struct {};
