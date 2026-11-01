//! SHIFT native metadata adapter to the shared joined prefix kernel. The
//! serial `Source.generateSerial` is the independent numerical/physical oracle;
//! this path produces identical field elements in the same physical layout and
//! writes the final prefix with one physical-order correction wave.
const std = @import("std");
const core = @import("stwo_core");
const work = @import("stwo_prover_engine").work_pool;
const Prefix = @import("../providers/prefix_waves.zig");
const PackedTable = @import("shift_word_packed_table.zig");
const S = @import("shift_word_source.zig");
const P = @import("shift_word_lookup.zig");
const E = @import("../evaluation.zig");
const Support = S.InteractionSupport;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const CHUNK: usize = Support.CHUNK_ROWS;
const LOG_CHUNK: u32 = std.math.log2_int(usize, CHUNK);
const BLOCK: usize = CHUNK / 16;
const LOG_BLOCK: u32 = LOG_CHUNK - 4;
comptime {
    std.debug.assert(CHUNK == @as(usize, 1) << LOG_CHUNK and BLOCK % E.LANES == 0);
}
pub const MIN_STACK_BYTES = if (@import("builtin").mode == .Debug) 1024 * 1024 else 256 * 1024;

pub fn generate(source: *S.Source, ch: P.Challenges, shift_dictionary: []const Q, range_dictionary: []const Q, pool: ?*work.WorkPool) !P.Claims {
    return generateImpl(source, ch, shift_dictionary, range_dictionary, pool, null, null);
}
fn generateImpl(source: *S.Source, ch: P.Challenges, shift_dictionary: []const Q, range_dictionary: []const Q, pool: ?*work.WorkPool, fail_wave: ?usize, fail_after: ?usize) !P.Claims {
    const n = source.size();
    const chunks = std.math.divCeil(usize, n, CHUNK) catch unreachable;
    const segment_log = if (pool) |p| Prefix.lineSegmentLog(source.log_size, LOG_CHUNK, LOG_BLOCK, p.workerCount()) else null;
    const units = if (segment_log) |log| Prefix.lineGroupCount(source.log_size, log) else chunks;
    const segments = if (segment_log) |log| n >> @intCast(log) else chunks;
    const workers = if (pool) |p| @min(p.workerCount(), units) else 1;
    if (workers <= 1) return source.generateSerial(ch, shift_dictionary, range_dictionary);
    if (pool.?.stackSize() < MIN_STACK_BYTES) return error.InvalidShiftInteractionStack;
    try Support.precheck(source, shift_dictionary, range_dictionary);
    try validateDictionaries(ch, shift_dictionary, range_dictionary, pool.?);
    const shift_claim = Support.dot(source.shift_counts, shift_dictionary);
    const range_claim = Support.dot(source.range16_counts, range_dictionary);
    const a = source.allocator;
    const output = try a.alloc(M, P.INTERACTION * n);
    errdefer a.free(output);
    const scratch = try a.alloc(Q, 2 * CHUNK * workers);
    defer a.free(scratch);
    const summaries = try a.alloc([3]Q, segments);
    defer a.free(summaries);
    @import("../native_output_pages.zig").prepare(output);
    var jobs: [work.MAX_WORKERS]Job = undefined;
    for (jobs[0..workers], 0..) |*job, i| job.* = .{ .metadata = source.metadata, .fact_count = source.fact_count, .log = source.log_size, .ch = ch, .shift_dictionary = shift_dictionary, .range_dictionary = range_dictionary, .claims = .{ shift_claim, range_claim }, .output = output, .scratch = scratch[2 * CHUNK * i ..][0 .. 2 * CHUNK], .summaries = summaries, .start = i, .end = units, .stride = workers, .segment_log = segment_log orelse LOG_CHUNK, .grouped = segment_log != null };
    const totals = if (comptime @import("builtin").is_test) test_or_run: {
        if (fail_wave) |which| break :test_or_run try Prefix.testing.failSubmission(3, Job, jobs[0..workers], summaries, n, pool.?, which, fail_after.?);
        break :test_or_run try Prefix.run(3, Job, jobs[0..workers], summaries, n, pool);
    } else try Prefix.run(3, Job, jobs[0..workers], summaries, n, pool);
    source.interaction = output;
    a.free(source.metadata);
    source.metadata = &.{};
    return .{ .shift = shift_claim, .range16 = range_claim, .function = totals[2] };
}
const ValidateJob = struct {
    ch: P.Challenges,
    prepared: *const PackedTable.Prepared,
    shift: []const Q,
    range: []const Q,
    first: usize,
    last: usize,
    failure: ?anyerror = null,
    pub fn run(self: *ValidateJob) void {
        Support.validateRange(self.ch, self.prepared, self.shift, self.range, self.first, self.last) catch |err| {
            self.failure = err;
        };
    }
};
fn validateDictionaries(ch: P.Challenges, shift: []const Q, range: []const Q, pool: *work.WorkPool) !void {
    const prepared = PackedTable.Prepared.init(ch.shift);
    const blocks = 65536 / E.LANES;
    const workers = @min(pool.workerCount(), blocks);
    var jobs: [work.MAX_WORKERS]ValidateJob = undefined;
    for (jobs[0..workers], 0..) |*job, i| job.* = .{ .ch = ch, .prepared = &prepared, .shift = shift, .range = range, .first = E.LANES * (blocks * i / workers), .last = E.LANES * (blocks * (i + 1) / workers) };
    try Prefix.single(ValidateJob, jobs[0..workers], pool);
}
const Job = struct {
    metadata: []const S.Metadata,
    fact_count: usize,
    log: u32,
    ch: P.Challenges,
    shift_dictionary: []const Q,
    range_dictionary: []const Q,
    claims: [2]Q,
    output: []M,
    scratch: []Q,
    summaries: [][3]Q,
    start: usize,
    end: usize,
    stride: usize,
    segment_log: u32,
    grouped: bool,
    correct: bool = false,
    failure: ?anyerror = null,
    pub fn validateTotals(self: *const Job, totals: [3]Q) !void {
        if (!totals[0].eql(self.claims[0]) or !totals[1].eql(self.claims[1])) return error.InvalidShiftMetadata;
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
                const offsets = self.summaries[logical >> @intCast(self.segment_log)];
                for (offsets[0].add(offsets[1]).add(offsets[2]).toM31Array(), 0..) |value, coordinate| {
                    const at = (P.PREFIX + coordinate) * n + position;
                    self.output[at] = self.output[at].add(value);
                }
            }
            return;
        }
        if (self.grouped) {
            var group = self.start;
            while (group < self.end) : (group += self.stride) try self.fillGroup(group);
            return;
        }
        var chunk = self.start;
        while (chunk < self.end) : (chunk += self.stride) self.summaries[chunk] = try self.fill(chunk * CHUNK);
    }
    /// Line-complete order (see prefix_waves.lineGroupSegments): row r of the
    /// group's 16 segments is emitted back to back, so each column store
    /// completes whole physical lines. Each segment keeps its own logical
    /// running sums, identical to `fill`.
    fn fillGroup(self: *Job, group: usize) !void {
        const segments = Prefix.lineGroupSegments(self.log, self.segment_log, group);
        const size = @as(usize, 1) << @intCast(self.segment_log);
        var sums: [16][3]Q = @splat(@splat(Q.zero()));
        const denominators = self.scratch[0..CHUNK];
        const inverses = self.scratch[CHUNK..][0..CHUNK];
        var r0: usize = 0;
        while (r0 < size) : (r0 += BLOCK) {
            for (segments, 0..) |segment, t| Support.denominators(self.metadata[segment * size + r0 ..][0..BLOCK], denominators[t * BLOCK ..][0..BLOCK], self.ch.function);
            try core.fields.batchInverseInPlace(Q, denominators, inverses);
            for (0..BLOCK) |r| for (segments, 0..) |segment, t| try self.row(segment * size + r0 + r, inverses[t * BLOCK + r], &sums[t]);
        }
        for (segments, sums) |segment, sum| self.summaries[segment] = sum;
    }
    /// Local prefix from zero; ordered (shift, range, function) chunk sums.
    fn fill(self: *Job, begin: usize) ![3]Q {
        const n = self.metadata.len;
        const count: usize = @min(CHUNK, n - begin);
        const denominators = self.scratch[0..count];
        const inverses = self.scratch[CHUNK..][0..count];
        Support.denominators(self.metadata[begin..][0..count], denominators, self.ch.function);
        try core.fields.batchInverseInPlace(Q, denominators, inverses);
        var sums: [3]Q = @splat(Q.zero());
        for (0..count) |i| try self.row(begin + i, inverses[i], &sums);
        return sums;
    }
    /// One row: identical stores and (shift, range, function) running sums.
    fn row(self: *Job, logical: usize, inverse: Q, sums: *[3]Q) !void {
        const n = self.metadata.len;
        const p = @import("../witness.zig").physical(logical, self.log);
        const meta = self.metadata[logical];
        if (logical < self.fact_count) {
            if (meta.payload[0] < 32 or meta.payload[0] > 37) return error.InvalidShiftMetadata;
        } else for (meta.payload) |value| if (value != 0) return error.InvalidShiftMetadata;
        var shift_sum = sums[0];
        var range_sum = sums[1];
        var function_sum = sums[2];
        for (0..P.encoding.PAIRS) |pair| {
            const qa = 2 * pair;
            const qb = qa + 1;
            const x = if (qa < 5) self.shift_dictionary[Support.table(meta, qa)] else self.range_dictionary[Support.range(meta, qa - 5)];
            const y = if (qb < 5) self.shift_dictionary[Support.table(meta, qb)] else self.range_dictionary[Support.range(meta, qb - 5)];
            if (qa < 5) shift_sum = shift_sum.add(x) else range_sum = range_sum.add(x);
            if (qb < 5) shift_sum = shift_sum.add(y) else range_sum = range_sum.add(y);
            Support.put(self.output, n, p, 4 * pair, x.mul(y));
        }
        Support.put(self.output, n, p, P.FUNCTION_INVERSE, inverse);
        const weight = meta.multiplicity();
        if (weight == 1) function_sum = function_sum.sub(inverse) else if (weight != 0) function_sum = function_sum.sub(inverse.mulM31(M.fromCanonical(weight)));
        Support.put(self.output, n, p, P.PREFIX, shift_sum.add(range_sum).add(function_sum));
        sums.* = .{ shift_sum, range_sum, function_sum };
    }
};
pub const testing = if (@import("builtin").is_test) struct {
    pub fn failSubmission(source: *S.Source, ch: P.Challenges, shift_dictionary: []const Q, range_dictionary: []const Q, pool: *work.WorkPool, which: usize, after: usize) !P.Claims {
        return generateImpl(source, ch, shift_dictionary, range_dictionary, pool, which, after);
    }
} else struct {};
