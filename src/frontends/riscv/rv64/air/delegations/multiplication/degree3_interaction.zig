//! Joined parallel MUL degree-3 interaction generation on the shared two-wave
//! prefix kernel. `degree3_source.generateLegacySerial` is the independent
//! numerical/physical oracle; outputs are identical field elements in the
//! identical physical layout.
const std = @import("std");
const core = @import("stwo_core");
const work = @import("stwo_prover_engine").work_pool;
const E = @import("../../evaluation.zig");
const Old = @import("trace.zig");
const L = @import("degree3_layout.zig");
const P = @import("provider.zig");
const Prefix = @import("../../providers/prefix_waves.zig");
const Serial = @import("degree3_source.zig");
const physical = @import("../../witness.zig").physical;
const M = core.fields.m31.M31;
const Q = E.Q;
const CHUNK: usize = 4096;
const LOG_CHUNK: u32 = 12;
const BLOCK: usize = CHUNK / 16;
const LOG_BLOCK: u32 = LOG_CHUNK - 4;
comptime {
    std.debug.assert(CHUNK == @as(usize, 1) << LOG_CHUNK);
}
pub const MIN_STACK_BYTES = if (@import("builtin").mode == .Debug) 1024 * 1024 else 256 * 1024;

pub fn generate(b: *Old.Trace, ch: P.Challenges, alpha: Q, pool: ?*work.WorkPool) !Q {
    if (b.log_size < 5 or b.log_size > L.MAX_LOG) return error.InvalidRv64MultiplicationShape;
    const n = b.domainSize();
    const chunks = std.math.divCeil(usize, n, CHUNK) catch unreachable;
    const segment_log = if (pool) |p| Prefix.lineSegmentLog(b.log_size, LOG_CHUNK, LOG_BLOCK, p.workerCount()) else null;
    const units = if (segment_log) |log| Prefix.lineGroupCount(b.log_size, log) else chunks;
    const segments = if (segment_log) |log| n >> @intCast(log) else chunks;
    const workers = if (pool) |p| @min(p.workerCount(), units) else 1;
    if (workers <= 1) return Serial.generateLegacySerial(b, ch, alpha);
    if (pool.?.stackSize() < MIN_STACK_BYTES) return error.InvalidRv64MultiplicationStack;
    if (b.interaction.len != 0 or b.request_metadata.len != b.count) return error.InvalidRv64MultiplicationPhase;
    if (b.count > n) return error.InvalidRv64MultiplicationShape;
    const a = b.allocator;
    const data = try a.alloc(M, L.INTERACTION * n);
    errdefer a.free(data);
    var bytes: [256]Q = undefined;
    for (&bytes, 0..) |*v, i| v.* = try alpha.sub(E.q(@intCast(i))).inv();
    const padding_inverse = if (b.count < n) try ch.offset.inv() else Q.zero();
    const padding_values = try Old.byteValuesNative(&([_]M{M.zero()} ** L.MAIN));
    const scratch = try a.alloc(Q, 2 * CHUNK * workers);
    defer a.free(scratch);
    const summaries = try a.alloc([1]Q, segments);
    defer a.free(summaries);
    @import("../../native_output_pages.zig").prepare(data);
    var jobs: [work.MAX_WORKERS]Job = undefined;
    for (jobs[0..workers], 0..) |*job, i| job.* = .{ .metadata = b.request_metadata, .count = b.count, .n = n, .log = b.log_size, .ch = ch, .bytes = &bytes, .padding_inverse = padding_inverse, .padding_values = padding_values, .output = data, .scratch = scratch[2 * CHUNK * i ..][0 .. 2 * CHUNK], .summaries = summaries, .start = i, .end = units, .stride = workers, .segment_log = segment_log orelse LOG_CHUNK, .grouped = segment_log != null };
    const totals = try Prefix.run(1, Job, jobs[0..workers], summaries, n, pool);
    b.interaction = data;
    b.allocator.free(b.request_metadata);
    b.request_metadata = &.{};
    return totals[0];
}
const Job = struct {
    metadata: []const Old.Request,
    count: usize,
    n: usize,
    log: u32,
    ch: P.Challenges,
    bytes: *const [256]Q,
    padding_inverse: Q,
    padding_values: [L.BYTE_QUERIES]u8,
    output: []M,
    scratch: []Q,
    summaries: [][1]Q,
    start: usize,
    end: usize,
    stride: usize,
    segment_log: u32,
    grouped: bool,
    correct: bool = false,
    failure: ?anyerror = null,
    pub fn validateTotals(_: *const Job, _: [1]Q) !void {}
    pub fn run(self: *Job) void {
        self.execute() catch |err| {
            self.failure = err;
        };
    }
    fn execute(self: *Job) !void {
        const n = self.n;
        if (self.correct) {
            for (self.start..self.end) |position| {
                const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(position, self.log), self.log);
                for (self.summaries[logical >> @intCast(self.segment_log)][0].toM31Array(), 0..) |value, c| {
                    const at = (L.PREFIX + c) * n + position;
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
        while (chunk < self.end) : (chunk += self.stride) self.summaries[chunk] = .{try self.fill(chunk * CHUNK)};
    }
    /// Line-complete order (see prefix_waves.lineGroupSegments). Padding rows
    /// take a unit placeholder denominator whose inverse is never read.
    fn fillGroup(self: *Job, group: usize) !void {
        const segments = Prefix.lineGroupSegments(self.log, self.segment_log, group);
        const size = @as(usize, 1) << @intCast(self.segment_log);
        var sums: [16]Q = @splat(Q.zero());
        const denominators = self.scratch[0..CHUNK];
        const inverses = self.scratch[CHUNK..][0..CHUNK];
        var r0: usize = 0;
        while (r0 < size) : (r0 += BLOCK) {
            var any = false;
            for (segments, 0..) |segment, t| for (0..BLOCK) |r| {
                const logical = segment * size + r0 + r;
                denominators[t * BLOCK + r] = if (logical < self.count) self.ch.denominator(&try Old.requestTuple(self.metadata[logical])) else Q.one();
                any = any or logical < self.count;
            };
            if (any) try core.fields.batchInverseInPlace(Q, denominators, inverses);
            for (0..BLOCK) |r| for (segments, 0..) |segment, t| try self.row(segment * size + r0 + r, inverses[t * BLOCK + r], &sums[t]);
        }
        for (segments, sums) |segment, sum| self.summaries[segment] = .{sum};
    }
    fn row(self: *Job, logical: usize, active_inverse: Q, sum: *Q) !void {
        const n = self.n;
        const active = logical < self.count;
        const p = physical(logical, self.log);
        const values = if (active) try Old.byteValuesNative(&try Old.row(self.metadata[logical])) else self.padding_values;
        var s = sum.*;
        for (0..L.BYTE_PAIRS) |pair| {
            const x = self.bytes[values[2 * pair]];
            const y = self.bytes[values[2 * pair + 1]];
            store(self.output, n, p, 4 * pair, x.mul(y));
            s = s.add(x).add(y);
        }
        const inverse = if (active) active_inverse else self.padding_inverse;
        store(self.output, n, p, L.FUNCTION_INVERSE, inverse);
        if (active) s = s.sub(inverse);
        store(self.output, n, p, L.PREFIX, s);
        sum.* = s;
    }
    fn fill(self: *Job, first: usize) !Q {
        const n = self.n;
        const count: usize = @min(CHUNK, n - first);
        const active = @min(count, self.count -| first);
        const denominators = self.scratch[0..active];
        const inverses = self.scratch[CHUNK..][0..active];
        for (denominators, 0..) |*d, j| d.* = self.ch.denominator(&try Old.requestTuple(self.metadata[first + j]));
        if (active != 0) try core.fields.batchInverseInPlace(Q, denominators, inverses);
        var sum = Q.zero();
        for (0..count) |j| try self.row(first + j, if (j < active) inverses[j] else Q.zero(), &sum);
        return sum;
    }
};
fn store(data: []M, n: usize, row: usize, column: usize, value: Q) void {
    for (value.toM31Array(), 0..) |v, c| data[(column + c) * n + row] = v;
}
