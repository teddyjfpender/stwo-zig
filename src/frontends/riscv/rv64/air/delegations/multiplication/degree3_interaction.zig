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
const PL = @import("pairs_layout.zig");
const P = @import("provider.zig");
const Prefix = @import("../../providers/prefix_waves.zig");
const Serial = @import("degree3_source.zig");
const physical = @import("../../witness.zig").physical;
const M = core.fields.m31.M31;
const Q = E.Q;
const CHUNK: usize = 4096;
const LOG_CHUNK: u32 = 12;
const BLOCK: usize = CHUNK / Prefix.GROUP_ROWS;
const LOG_BLOCK: u32 = LOG_CHUNK - Prefix.GROUP_LOG_ROWS;
comptime {
    std.debug.assert(CHUNK == @as(usize, 1) << LOG_CHUNK);
}
pub const MIN_STACK_BYTES = if (@import("builtin").mode == .Debug) 1024 * 1024 else 256 * 1024;

pub fn generate(b: *Old.Trace, ch: P.Challenges, alpha: Q, pool: ?*work.WorkPool) !Q {
    return generateFor(b, ch, .{ .alpha = alpha }, pool);
}
/// Byte-pair layout (pairs_layout): `dictionary[x*256+y] = 1/p(x,y)` is the
/// AND pair table's dictionary; the serial oracle is `generatePairsSerial`.
pub fn generatePairs(b: *Old.Trace, ch: P.Challenges, dictionary: []const Q, pool: ?*work.WorkPool) !Q {
    if (dictionary.len != 65536) return error.InvalidRv64MultiplicationPairDictionary;
    return generateFor(b, ch, .{ .pairs = dictionary }, pool);
}
pub const Bytes = union(enum) { alpha: Q, pairs: []const Q };
fn generateFor(b: *Old.Trace, ch: P.Challenges, mode: Bytes, pool: ?*work.WorkPool) !Q {
    if (b.log_size < 5 or b.log_size > L.MAX_LOG) return error.InvalidRv64MultiplicationShape;
    const n = b.domainSize();
    const chunks = std.math.divCeil(usize, n, CHUNK) catch unreachable;
    const segment_log = if (pool) |p| Prefix.lineSegmentLog(b.log_size, LOG_CHUNK, LOG_BLOCK, p.workerCount()) else null;
    const units = if (segment_log) |log| Prefix.lineGroupCount(b.log_size, log) else chunks;
    const segments = if (segment_log) |log| n >> @intCast(log) else chunks;
    const workers = if (pool) |p| @min(p.workerCount(), units) else 1;
    if (workers <= 1) return switch (mode) {
        .alpha => |alpha| Serial.generateLegacySerial(b, ch, alpha),
        .pairs => |dictionary| Serial.generatePairsSerial(b, ch, dictionary),
    };
    if (pool.?.stackSize() < MIN_STACK_BYTES) return error.InvalidRv64MultiplicationStack;
    if (b.interaction.len != 0 or b.request_metadata.len != b.count) return error.InvalidRv64MultiplicationPhase;
    if (b.count > n) return error.InvalidRv64MultiplicationShape;
    const a = b.allocator;
    const pairs: []const Q = if (mode == .pairs) mode.pairs else &.{};
    const width: usize = if (mode == .pairs) PL.INTERACTION else L.INTERACTION;
    const data = try a.alloc(M, width * n);
    errdefer a.free(data);
    var bytes: [256]Q = @splat(Q.zero());
    if (mode == .alpha) for (&bytes, 0..) |*v, i| {
        v.* = try mode.alpha.sub(E.q(@intCast(i))).inv();
    };
    const padding_inverse = if (b.count < n and mode == .alpha) try ch.offset.inv() else Q.zero();
    const padding_values = try Old.byteValuesNative(&([_]M{M.zero()} ** L.MAIN));
    const scratch = try a.alloc(Q, 2 * CHUNK * workers);
    defer a.free(scratch);
    const summaries = try a.alloc([1]Q, segments);
    defer a.free(summaries);
    @import("../../native_output_pages.zig").prepare(data);
    var jobs: [work.MAX_WORKERS]Job = undefined;
    for (jobs[0..workers], 0..) |*job, i| job.* = .{ .metadata = b.request_metadata, .count = b.count, .n = n, .log = b.log_size, .ch = ch, .bytes = &bytes, .pairs = pairs, .prefix_column = if (mode == .pairs) PL.PREFIX else L.PREFIX, .padding_inverse = padding_inverse, .padding_values = padding_values, .output = data, .scratch = scratch[2 * CHUNK * i ..][0 .. 2 * CHUNK], .summaries = summaries, .start = i, .end = units, .stride = workers, .segment_log = segment_log orelse LOG_CHUNK, .grouped = segment_log != null };
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
    /// Nonempty exactly in the byte-pair layout.
    pairs: []const Q,
    prefix_column: usize,
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
                    const at = (self.prefix_column + c) * n + position;
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
    /// Relative-block-owned groups (see prefix_waves.lineGroupSegments). Padding rows
    /// take a unit placeholder denominator whose inverse is never read.
    fn fillGroup(self: *Job, group: usize) !void {
        const segments = Prefix.lineGroupSegments(self.log, self.segment_log, group);
        const size = @as(usize, 1) << @intCast(self.segment_log);
        var sums: [Prefix.GROUP_ROWS]Q = @splat(Q.zero());
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
        if (self.pairs.len != 0) {
            // 24 strict inverses 1/(p*q); the FUNCTION fraction is fused.
            for (0..PL.PAIR_COLUMNS) |j| {
                const x = self.pairs[@as(usize, values[4 * j]) * 256 + values[4 * j + 1]];
                const y = self.pairs[@as(usize, values[4 * j + 2]) * 256 + values[4 * j + 3]];
                store(self.output, n, p, 4 * j, x.mul(y));
                s = s.add(x).add(y);
            }
            if (active) s = s.sub(active_inverse);
            store(self.output, n, p, PL.PREFIX, s);
            sum.* = s;
            return;
        }
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
