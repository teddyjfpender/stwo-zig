//! Joined parallel ROM interaction generation. Wave one walks PHYSICAL ranges:
//! denominators, batch inverses, the inverse columns and the claim parts are
//! written contiguously. The logical-order prefix then runs on the shared
//! two-wave prefix kernel. `Source.generateSerial` is the independent oracle;
//! outputs are identical field elements in the identical physical layout.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const X = @import("stwo_riscv_frontend").rv64_air.word16_execution;
const Prefix = @import("stwo_riscv_frontend").rv64_air.providers.prefix_waves;
const Source = @import("rom_source.zig").Source;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const work = engine.work_pool;
const Challenges = @FieldType(X.types.Challenges, "rom");
const CHUNK = @import("rom_source.zig").CHUNK;
pub const MIN_STACK_BYTES = if (@import("builtin").mode == .Debug) 1024 * 1024 else 256 * 1024;

fn logicalOf(p: usize, log: u32) usize {
    return core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(p, log), log);
}
pub fn generate(self: *Source, ch: Challenges, pool: ?*work.WorkPool) !Q {
    const n = self.program.size();
    const chunks = std.math.divCeil(usize, n, CHUNK) catch unreachable;
    const workers = if (pool) |p| @min(p.workerCount(), chunks) else 1;
    if (workers <= 1) return self.generateSerial(ch);
    if (pool.?.stackSize() < MIN_STACK_BYTES) return error.InvalidExecutionRomStack;
    if (self.interaction.len != 0 or self.dictionary.len != 0) return error.InvalidExecutionRomPhase;
    if (!self.program.fixed_retired) try self.program.validateFixedWitness();
    const a = self.allocator;
    const dictionary = try a.alloc(Q, n);
    errdefer a.free(dictionary);
    const output = try a.alloc(M, 8 * n);
    errdefer a.free(output);
    const scratch = try a.alloc(Q, CHUNK * workers);
    defer a.free(scratch);
    const summaries = try a.alloc([1]Q, chunks);
    defer a.free(summaries);
    var dictionary_jobs: [work.MAX_WORKERS]DictionaryJob = undefined;
    for (dictionary_jobs[0..workers], 0..) |*job, i| job.* = .{ .source = self, .ch = ch, .dictionary = dictionary, .output = output, .scratch = scratch[CHUNK * i ..][0..CHUNK], .first = CHUNK * (chunks * i / workers), .last = @min(n, CHUNK * (chunks * (i + 1) / workers)) };
    try Prefix.single(DictionaryJob, dictionary_jobs[0..workers], pool);
    var claim = Q.zero();
    for (dictionary_jobs[0..workers]) |job| claim = claim.add(job.claim);
    var jobs: [work.MAX_WORKERS]PrefixJob = undefined;
    for (jobs[0..workers], 0..) |*job, i| job.* = .{ .counts = self.counts, .dictionary = dictionary, .log = self.program.log_size, .claim = claim, .output = output, .summaries = summaries, .start = i, .end = chunks, .stride = workers };
    _ = try Prefix.run(1, PrefixJob, jobs[0..workers], summaries, n, pool);
    self.dictionary = dictionary;
    self.interaction = output;
    return claim;
}
const DictionaryJob = struct {
    source: *const Source,
    ch: Challenges,
    dictionary: []Q,
    output: []M,
    scratch: []Q,
    first: usize,
    last: usize,
    claim: Q = Q.zero(),
    failure: ?anyerror = null,
    pub fn run(self: *DictionaryJob) void {
        self.execute() catch |err| {
            self.failure = err;
        };
    }
    fn execute(self: *DictionaryJob) !void {
        const program = self.source.program;
        const n = program.size();
        var begin = self.first;
        while (begin < self.last) : (begin += CHUNK) {
            const count = @min(CHUNK, self.last - begin);
            const denominators = self.dictionary[begin..][0..count];
            for (denominators, begin..) |*d, p| {
                d.* = self.ch.offset;
                if (program.fixed_retired) {
                    const tuple = try program.tupleAt(logicalOf(p, program.log_size));
                    for (self.ch.coefficients, tuple) |coef, value| d.* = d.sub(coef.mulM31(value));
                } else for (self.ch.coefficients, 0..) |coef, c| {
                    d.* = d.sub(coef.mulM31(program.fixed[c * n + p]));
                }
            }
            const inverses = self.scratch[0..count];
            try core.fields.batchInverseInPlace(Q, denominators, inverses);
            @memcpy(denominators, inverses);
            for (inverses, begin..) |inverse, p| {
                self.claim = self.claim.sub(inverse.mulM31(M.fromCanonical(@intCast(self.source.counts[p]))));
                for (inverse.toM31Array(), 0..) |value, c| self.output[c * n + p] = value;
            }
        }
    }
};
const PrefixJob = struct {
    counts: []const u64,
    dictionary: []const Q,
    log: u32,
    claim: Q,
    output: []M,
    summaries: [][1]Q,
    start: usize,
    end: usize,
    stride: usize,
    correct: bool = false,
    failure: ?anyerror = null,
    pub fn validateTotals(self: *const PrefixJob, totals: [1]Q) !void {
        if (!totals[0].eql(self.claim)) return error.InvalidExecutionRomLedger;
    }
    pub fn run(self: *PrefixJob) void {
        const n = self.dictionary.len;
        if (self.correct) {
            for (self.start..self.end) |p| {
                const offset = self.summaries[logicalOf(p, self.log) / CHUNK][0];
                for (offset.toM31Array(), 0..) |value, c| {
                    const at = (4 + c) * n + p;
                    self.output[at] = self.output[at].add(value);
                }
            }
            return;
        }
        var chunk = self.start;
        while (chunk < self.end) : (chunk += self.stride) {
            const begin = chunk * CHUNK;
            var sum = Q.zero();
            for (begin..@min(n, begin + CHUNK)) |logical| {
                const p = X.layout.physical(logical, self.log);
                sum = sum.sub(self.dictionary[p].mulM31(M.fromCanonical(@intCast(self.counts[p]))));
                for (sum.toM31Array(), 0..) |value, c| self.output[(4 + c) * n + p] = value;
            }
            self.summaries[chunk] = .{sum};
        }
    }
};
