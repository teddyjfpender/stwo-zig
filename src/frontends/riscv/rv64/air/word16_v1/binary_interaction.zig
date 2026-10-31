//! BINARY native metadata adapter to the shared joined prefix kernel. The
//! original serial source is the independent numerical/physical-byte oracle.
const std = @import("std");
const core = @import("stwo_core");
const work = @import("stwo_prover_engine").work_pool;
const Prefix = @import("../providers/prefix_waves.zig");
const S = @import("binary_source.zig");
const P = @import("binary_lookup.zig");
const Support = S.InteractionSupport;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const CHUNK: usize = Support.CHUNK_ROWS;
pub const MIN_STACK_BYTES = if (@import("builtin").mode == .Debug) 1024 * 1024 else 256 * 1024;
pub fn generate(source: *S.Source, ch: P.Challenges, pool: ?*work.WorkPool) !P.Claims {
    return generateImpl(source, ch, pool, null, null);
}
fn generateImpl(source: *S.Source, ch: P.Challenges, pool: ?*work.WorkPool, fail_wave: ?usize, fail_after: ?usize) !P.Claims {
    if (pool) |p| if (p.stackSize() < MIN_STACK_BYTES) return error.InvalidBinaryInteractionStack;
    const n = source.size();
    const chunks = std.math.divCeil(usize, n, CHUNK) catch unreachable;
    const workers = if (pool) |p| @min(p.workerCount(), chunks) else 1;
    if (workers == 1) return source.generateSerial(ch);
    try Support.validate(source);
    const a = source.allocator;
    const output = try a.alloc(M, S.INTERACTION * n);
    errdefer a.free(output);
    const dictionary = try a.alloc(Q, 65536);
    defer a.free(dictionary);
    const scratch = try a.alloc(Q, 2 * CHUNK * workers);
    defer a.free(scratch);
    try Support.dictionary(dictionary, scratch[0 .. 2 * CHUNK], ch);
    var and_claim = Q.zero();
    for (source.and_counts, dictionary) |count, inverse| {
        if (count >= core.fields.m31.Modulus) return error.InvalidBinaryMetadata;
        and_claim = and_claim.add(inverse.mulM31(M.fromCanonical(@intCast(count))));
    }
    const summaries = try a.alloc([2]Q, chunks);
    defer a.free(summaries);
    @import("../native_output_pages.zig").prepare(output);
    var jobs: [work.MAX_WORKERS]Job = undefined;
    for (jobs[0..workers], 0..) |*job, i| job.* = .{ .metadata = source.metadata, .log = source.log_size, .ch = ch, .and_claim = and_claim, .dictionary = dictionary, .output = output, .scratch = scratch[2 * CHUNK * i ..][0 .. 2 * CHUNK], .summaries = summaries, .start = i, .end = chunks, .stride = workers };
    const totals = if (comptime @import("builtin").is_test) test_or_run: {
        if (fail_wave) |which| break :test_or_run try Prefix.testing.failSubmission(2, Job, jobs[0..workers], summaries, n, pool.?, which, fail_after.?);
        break :test_or_run try Prefix.run(2, Job, jobs[0..workers], summaries, n, pool);
    } else try Prefix.run(2, Job, jobs[0..workers], summaries, n, pool);
    source.interaction = output;
    a.free(source.metadata);
    source.metadata = &.{};
    return .{ .and_ = and_claim, .function = totals[1] };
}
const Job = struct {
    metadata: []const S.Metadata,
    log: u32,
    ch: P.Challenges,
    and_claim: Q,
    dictionary: []const Q,
    output: []M,
    scratch: []Q,
    summaries: [][2]Q,
    start: usize,
    end: usize,
    stride: usize,
    correct: bool = false,
    failure: ?anyerror = null,
    pub fn validateTotals(self: *const Job, totals: [2]Q) !void {
        if (!totals[0].eql(self.and_claim)) return error.InvalidBinaryMetadata;
    }
    pub fn run(self: *Job) void {
        self.execute() catch |err| {
            self.failure = err;
        };
    }
    fn execute(self: *Job) !void {
        const n = self.metadata.len;
        if (self.correct) {
            for (self.start..self.end) |position| {
                const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(position, self.log), self.log);
                const offsets = self.summaries[logical / CHUNK];
                for (offsets[0].add(offsets[1]).toM31Array(), 0..) |value, coordinate| {
                    const at = (20 + coordinate) * n + position;
                    self.output[at] = self.output[at].add(value);
                }
            }
            return;
        }
        var chunk = self.start;
        while (chunk < self.end) : (chunk += self.stride) {
            var sums: [2]Q = @splat(Q.zero());
            try Support.fillChunk(self.metadata, self.log, self.ch, self.dictionary, self.scratch, self.output, chunk * CHUNK, &sums);
            self.summaries[chunk] = sums;
        }
    }
};
pub const testing = if (@import("builtin").is_test) struct {
    pub fn failSubmission(source: *S.Source, ch: P.Challenges, pool: *work.WorkPool, which: usize, after: usize) !P.Claims {
        return generateImpl(source, ch, pool, which, after);
    }
} else struct {};
