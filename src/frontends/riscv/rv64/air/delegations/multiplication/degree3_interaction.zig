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
pub const MIN_STACK_BYTES = if (@import("builtin").mode == .Debug) 1024 * 1024 else 256 * 1024;

pub fn generate(b: *Old.Trace, ch: P.Challenges, alpha: Q, pool: ?*work.WorkPool) !Q {
    if (b.log_size < 5 or b.log_size > L.MAX_LOG) return error.InvalidRv64MultiplicationShape;
    const n = b.domainSize();
    const chunks = std.math.divCeil(usize, n, CHUNK) catch unreachable;
    const workers = if (pool) |p| @min(p.workerCount(), chunks) else 1;
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
    const summaries = try a.alloc([1]Q, chunks);
    defer a.free(summaries);
    @import("../../native_output_pages.zig").prepare(data);
    var jobs: [work.MAX_WORKERS]Job = undefined;
    for (jobs[0..workers], 0..) |*job, i| job.* = .{ .metadata = b.request_metadata, .count = b.count, .n = n, .log = b.log_size, .ch = ch, .bytes = &bytes, .padding_inverse = padding_inverse, .padding_values = padding_values, .output = data, .scratch = scratch[2 * CHUNK * i ..][0 .. 2 * CHUNK], .summaries = summaries, .start = i, .end = chunks, .stride = workers };
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
                for (self.summaries[logical / CHUNK][0].toM31Array(), 0..) |value, c| {
                    const at = (L.PREFIX + c) * n + position;
                    self.output[at] = self.output[at].add(value);
                }
            }
            return;
        }
        var chunk = self.start;
        while (chunk < self.end) : (chunk += self.stride) self.summaries[chunk] = .{try self.fill(chunk * CHUNK)};
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
        for (0..count) |j| {
            const logical = first + j;
            const row = physical(logical, self.log);
            const values = if (j < active) try Old.byteValuesNative(&try Old.row(self.metadata[logical])) else self.padding_values;
            for (0..L.BYTE_PAIRS) |pair| {
                const x = self.bytes[values[2 * pair]];
                const y = self.bytes[values[2 * pair + 1]];
                store(self.output, n, row, 4 * pair, x.mul(y));
                sum = sum.add(x).add(y);
            }
            const inverse = if (j < active) inverses[j] else self.padding_inverse;
            store(self.output, n, row, L.FUNCTION_INVERSE, inverse);
            if (j < active) sum = sum.sub(inverse);
            store(self.output, n, row, L.PREFIX, sum);
        }
        return sum;
    }
};
fn store(data: []M, n: usize, row: usize, column: usize, value: Q) void {
    for (value.toM31Array(), 0..) |v, c| data[(column + c) * n + row] = v;
}
