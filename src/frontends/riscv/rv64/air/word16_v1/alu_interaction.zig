//! Two joined waves over the existing native ALU interaction authority.
//! Provisional output and per-worker heap scratch publish only on full success.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const S = @import("alu_source.zig");
const P = @import("alu_lookup.zig");
const Support = S.InteractionSupport;
const work = engine.work_pool;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
pub const MIN_STACK_BYTES = if (@import("builtin").mode == .Debug) 1024 * 1024 else 256 * 1024;
const CHUNK: usize = Support.CHUNK_ROWS;
pub fn generate(source: *S.Source, challenges: P.Challenges, dictionary: []const Q, pool: ?*work.WorkPool) !P.Claims {
    return generateImpl(source, challenges, dictionary, pool, null, null);
}
fn generateImpl(source: *S.Source, challenges: P.Challenges, dictionary: []const Q, pool: ?*work.WorkPool, fail_wave: ?usize, fail_after: ?usize) !P.Claims {
    _ = try S.massForLog(source.log_size);
    if (pool) |active| if (active.stackSize() < MIN_STACK_BYTES) return error.InvalidAluInteractionStack;
    const n = source.size();
    const chunks = std.math.divCeil(usize, n, CHUNK) catch unreachable;
    const workers: usize = if (pool) |active| @min(active.workerCount(), chunks) else 1;
    if (workers <= 1) return source.generateSerial(challenges, dictionary);
    if (source.interaction.len != 0 or source.metadata.len != n) return error.InvalidAluSourcePhase;
    if (dictionary.len != 65536 or source.range16_counts.len != 65536 or source.fact_count > n) return error.InvalidAluDictionary;
    try Support.validateMetadata(source);
    try Support.validateDictionary(challenges, dictionary);
    var range_claim = Q.zero();
    for (source.range16_counts, dictionary) |count, inverse| {
        if (count >= core.fields.m31.Modulus) return error.InvalidAluMetadata;
        range_claim = range_claim.add(inverse.mulM31(M.fromCanonical(@intCast(count))));
    }
    const a = source.allocator;
    const output = try a.alloc(M, P.INTERACTION * n);
    errdefer a.free(output);
    @import("../native_output_pages.zig").prepare(output);
    const scratch = try a.alloc(Q, 2 * CHUNK * workers);
    defer a.free(scratch);
    const summaries = try a.alloc([2]Q, chunks);
    defer a.free(summaries);
    const ctx = Context{ .metadata = source.metadata, .fact_count = source.fact_count, .log = source.log_size, .challenges = challenges, .dictionary = dictionary, .output = output };
    var jobs: [work.MAX_WORKERS]Job = undefined;
    for (jobs[0..workers], 0..) |*job, i| job.* = .{ .ctx = ctx, .summaries = summaries, .scratch = scratch[2 * CHUNK * i ..][0 .. 2 * CHUNK], .start = chunks * i / workers, .end = chunks * (i + 1) / workers };
    var lease = try pool.?.acquire(try work.WorkerBudget.init(workers));
    defer lease.deinit();
    try wave(&lease, jobs[0..workers], if (fail_wave == 0) fail_after else null);
    var sums: [2]Q = @splat(Q.zero());
    for (summaries) |*summary| {
        const local = summary.*;
        summary.* = sums;
        for (&sums, local) |*sum, value| sum.* = sum.add(value);
    }
    if (!sums[0].eql(range_claim)) return error.InvalidAluMetadata;
    for (summaries) |*summary| for (summary, sums) |*offset, total| {
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
    return .{ .range16 = range_claim, .function = sums[1] };
}
const Context = struct {
    metadata: []const S.Metadata,
    fact_count: usize,
    log: u32,
    challenges: P.Challenges,
    dictionary: []const Q,
    output: []M,
};
const Job = struct {
    ctx: Context,
    summaries: [][2]Q,
    scratch: []Q,
    start: usize,
    end: usize,
    correct: bool = false,
    failure: ?anyerror = null,
    fn run(self: *Job) void {
        self.execute() catch |err| {
            self.failure = err;
        };
    }
    fn execute(self: *Job) !void {
        const n = self.ctx.metadata.len;
        if (!self.correct) {
            for (self.start..self.end) |chunk| {
                const start = chunk * CHUNK;
                const count: usize = @min(CHUNK, n - start);
                Support.functionDenominators(self.ctx.metadata[start..][0..count], self.scratch[0..count], self.ctx.challenges.function);
                try core.fields.batchInverseInPlace(Q, self.scratch[0..count], self.scratch[CHUNK..][0..count]);
                var sums: [2]Q = @splat(Q.zero());
                for (0..count) |i| {
                    const logical = start + i;
                    const position = @import("../witness.zig").physical(logical, self.ctx.log);
                    const metadata = self.ctx.metadata[logical];
                    for (0..10) |batch| {
                        const x = self.ctx.dictionary[metadata.range_indices[2 * batch]];
                        const y = self.ctx.dictionary[metadata.range_indices[2 * batch + 1]];
                        Support.store(self.ctx.output, n, position, 4 * batch, x.mul(y));
                        sums[0] = sums[0].add(x).add(y);
                    }
                    Support.store(self.ctx.output, n, position, 40, sums[0]);
                    const inverse = self.scratch[CHUNK + i];
                    Support.store(self.ctx.output, n, position, 44, inverse);
                    sums[1] = sums[1].sub(inverse.mulM31(M.fromCanonical(metadata.multiplicity())));
                    Support.store(self.ctx.output, n, position, 48, sums[1]);
                }
                self.summaries[chunk] = sums;
            }
        } else {
            for (self.start..self.end) |position| {
                const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(position, self.ctx.log), self.ctx.log);
                for ([_]usize{ 40, 48 }, self.summaries[logical / CHUNK]) |column, offset| for (offset.toM31Array(), 0..) |coordinate, i| {
                    const at = (column + i) * n + position;
                    self.ctx.output[at] = self.ctx.output[at].add(coordinate);
                };
            }
        }
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
        if (fail_after == submitted) return error.InjectedAluInteractionSubmissionFailure;
        try lease.spawnWg(&group, Job.run, .{job});
    }
    jobs[0].run();
    group.wait();
    joined = true;
    for (jobs) |job| if (job.failure) |failure| return failure;
}
pub const testing = if (@import("builtin").is_test) struct {
    pub fn failSubmission(source: *S.Source, ch: P.Challenges, dictionary: []const Q, pool: *work.WorkPool, which_wave: usize, after: usize) !P.Claims {
        return generateImpl(source, ch, dictionary, pool, which_wave, after);
    }
} else struct {};
