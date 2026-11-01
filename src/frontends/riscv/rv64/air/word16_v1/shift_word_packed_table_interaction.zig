//! Joined parallel packed SHIFT table interaction generation on the shared
//! two-wave prefix kernel. `Request.generateInteractionSerial` is the
//! independent oracle; dictionary and columns are identical field elements.
const std = @import("std");
const core = @import("stwo_core");
const work = @import("stwo_prover_engine").work_pool;
const Prefix = @import("../providers/prefix_waves.zig");
const T = @import("shift_word_packed_table.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const CHUNK = T.Request.CHUNK_ROWS;
pub const MIN_STACK_BYTES = if (@import("builtin").mode == .Debug) 1024 * 1024 else 256 * 1024;

pub fn generate(self: *T.Request, ch: T.Challenges, pool: ?*work.WorkPool) !Q {
    const chunks = T.SIZE / CHUNK;
    const workers = if (pool) |p| @min(p.workerCount(), chunks) else 1;
    if (workers <= 1) return self.generateInteractionSerial(ch);
    if (pool.?.stackSize() < MIN_STACK_BYTES) return error.InvalidPackedWordShiftStack;
    if (self.interaction.len != 0) return error.InvalidPackedWordShiftPhase;
    const a = self.allocator;
    const output = try a.alloc(M, T.INTERACTION * T.SIZE);
    errdefer a.free(output);
    const dictionary = try a.alloc(Q, T.SEMANTIC_FACTS);
    errdefer a.free(dictionary);
    const scratch = try a.alloc(Q, T.Request.CHUNK_SCRATCH * workers);
    defer a.free(scratch);
    const summaries = try a.alloc([1]Q, chunks);
    defer a.free(summaries);
    const prepared = T.Prepared.init(ch);
    var jobs: [work.MAX_WORKERS]Job = undefined;
    for (jobs[0..workers], 0..) |*job, i| job.* = .{ .request = self, .prepared = &prepared, .dictionary = dictionary, .output = output, .scratch = scratch[T.Request.CHUNK_SCRATCH * i ..][0..T.Request.CHUNK_SCRATCH], .summaries = summaries, .start = i, .end = chunks, .stride = workers };
    const totals = try Prefix.run(1, Job, jobs[0..workers], summaries, T.SIZE, pool);
    self.interaction = output;
    self.dictionary = dictionary;
    return totals[0];
}
const Job = struct {
    request: *const T.Request,
    prepared: *const T.Prepared,
    dictionary: []Q,
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
        if (self.correct) {
            for (self.start..self.end) |p| {
                const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(p, T.LOG), T.LOG);
                for (self.summaries[logical / CHUNK][0].toM31Array(), 0..) |value, c| {
                    const at = (32 + c) * T.SIZE + p;
                    self.output[at] = self.output[at].add(value);
                }
            }
            return;
        }
        var chunk = self.start;
        while (chunk < self.end) : (chunk += self.stride) {
            var sum = Q.zero();
            try self.request.fillChunk(self.prepared, chunk * CHUNK, self.scratch, self.dictionary, self.output, &sum);
            self.summaries[chunk] = .{sum};
        }
    }
};
