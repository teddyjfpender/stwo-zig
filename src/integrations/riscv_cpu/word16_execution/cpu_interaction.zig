//! Joined native prefix waves, using five variable batch inversions per row.
//! ROM and scalar ranges reuse their sealed providers' dictionaries. Output
//! stays provisional until every worker is joined and all ledgers agree.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const X = @import("stwo_riscv_frontend").rv64_air.word16_execution;
const Source = @import("cpu_source.zig").Source;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const work = engine.work_pool;
const Prefix = @import("stwo_riscv_frontend").rv64_air.providers.prefix_waves;
const CHUNK = 1024;
const LOG_CHUNK = 10;
const GROUP_BLOCK = CHUNK / 16;
comptime {
    std.debug.assert(CHUNK == 1 << LOG_CHUNK);
}
pub const Dictionaries = struct { rom: []const Q, range16: []const Q, range8: []const Q };
const Hint = struct { delta: [3]Q, enabled: [3]M, function: M, active: M, gap16: [3]u16, gap8: [3]u8, rom_physical: u32 };
const Ds = struct { before: [3]Q, after: [3]Q, function: Q, owner: Q };
fn dot(ch: anytype, tuple: anytype) Q {
    var result = ch.offset;
    for (ch.coefficients, tuple) |coefficient, value| result = result.sub(coefficient.mulM31(value));
    return result;
}
fn denominators(ch: X.types.Challenges, row: []const M, index: usize, epoch: u16) Ds {
    const fixed = [_]M{ M.fromCanonical(@intCast(index)), M.zero(), M.zero() };
    var result: Ds = undefined;
    for (0..3) |slot| {
        result.before[slot] = dot(ch.register, X.tuples.register(M, &fixed, row, slot, false));
        result.after[slot] = dot(ch.register, X.tuples.register(M, &fixed, row, slot, true));
    }
    result.function = dot(ch.function, X.tuples.function(M, row));
    result.owner = dot(ch.owner, X.tuples.owner(M, &fixed, row, M.fromCanonical(epoch)));
    return result;
}
fn validate(source: *const Source, ch: X.types.Challenges, dict: Dictionaries, pool: ?*work.WorkPool) !Q {
    if (source.interaction.len != 0 or source.metadata.len != source.public.steps) return error.InvalidExecutionInteractionPhase;
    if (dict.rom.len != source.program.size() or dict.range16.len != 65536 or dict.range8.len != 256) return error.InvalidExecutionDictionary;
    for (dict.range16, 0..) |inverse, i| {
        const d = ch.range16.offset.sub(ch.range16.coefficient.mulM31(M.fromCanonical(@intCast(i))));
        if (!d.mul(inverse).eql(Q.one())) return error.InvalidExecutionDictionary;
    }
    for (dict.range8, 0..) |inverse, i| {
        const d = ch.range8.offset.sub(ch.range8.coefficient.mulM31(M.fromCanonical(@intCast(i))));
        if (!d.mul(inverse).eql(Q.one())) return error.InvalidExecutionDictionary;
    }
    if (source.program.fixed_retired) {
        try validateRetiredRom(source.program, ch.rom, dict.rom, pool);
    } else {
        try source.program.validateFixedWitness();
        for (dict.rom, 0..) |inverse, p| {
            var tuple: [30]M = undefined;
            for (&tuple, 0..) |*value, c| value.* = source.program.fixed[c * source.program.size() + p];
            if (!dot(ch.rom, tuple).mul(inverse).eql(Q.one())) return error.InvalidExecutionDictionary;
        }
    }
    const padding = try X.row.padding(0, source.public.final_pc);
    const padding_denominator = dot(ch.rom, X.tuples.rom(M, &padding));
    if (padding_denominator.isZero()) return error.DivisionByZero;
    return padding_denominator.inv();
}
/// Physical-range ROM dictionary check; any failing row rejects the whole
/// dictionary exactly as the serial logical walk did (same error set).
const RomCheckJob = struct {
    program: *const Program,
    ch: RomChallenges,
    rom: []const Q,
    first: usize,
    last: usize,
    failure: ?anyerror = null,
    pub fn run(self: *RomCheckJob) void {
        self.execute() catch |err| {
            self.failure = err;
        };
    }
    fn execute(self: *RomCheckJob) !void {
        const log = self.program.log_size;
        for (self.first..self.last) |p| {
            const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(p, log), log);
            const tuple = try self.program.tupleAt(logical);
            if (!dot(self.ch, tuple).mul(self.rom[p]).eql(Q.one())) return error.InvalidExecutionDictionary;
        }
    }
};
const Program = @import("program.zig").Program;
const RomChallenges = @FieldType(X.types.Challenges, "rom");
fn validateRetiredRom(program: *const Program, ch: RomChallenges, rom: []const Q, pool: ?*work.WorkPool) !void {
    const n = program.size();
    if (rom.len != n) return error.InvalidExecutionDictionary;
    const workers = Prefix.workers(pool, n, 4096);
    var jobs: [work.MAX_WORKERS]RomCheckJob = undefined;
    for (jobs[0..workers], 0..) |*job, i| job.* = .{ .program = program, .ch = ch, .rom = rom, .first = n * i / workers, .last = n * (i + 1) / workers };
    try Prefix.single(RomCheckJob, jobs[0..workers], pool);
}
pub const testing = if (@import("builtin").is_test) struct {
    pub const validateRom = validateRetiredRom;
} else struct {};
pub fn generate(source: *Source, ch: X.types.Challenges, dictionaries: Dictionaries, pool: ?*work.WorkPool) !Q {
    const padding_rom = try validate(source, ch, dictionaries, pool);
    if (pool) |active| if (active.stackSize() < (if (@import("builtin").mode == .Debug) @as(usize, 1048576) else 262144)) return error.InvalidExecutionInteractionStack;
    const n = source.size();
    const chunks = std.math.divCeil(usize, n, CHUNK) catch unreachable;
    const segment_log = if (pool) |active| Prefix.lineSegmentLog(source.log_size, LOG_CHUNK, LOG_CHUNK - 4, active.workerCount()) else null;
    const units = if (segment_log) |log| Prefix.lineGroupCount(source.log_size, log) else chunks;
    const segments = if (segment_log) |log| n >> @intCast(log) else chunks;
    const workers = if (pool) |active| @min(active.workerCount(), units) else 1;
    const a = source.allocator;
    const output = try a.alloc(M, X.layout.inter.COUNT * n);
    errdefer a.free(output);
    @import("stwo_riscv_frontend").rv64_air.native_output_pages.prepare(output);
    const summaries = try a.alloc([1]Q, segments);
    defer a.free(summaries);
    const scratch = try a.alloc(Q, workers * 10 * CHUNK);
    defer a.free(scratch);
    const hints = try a.alloc(Hint, workers * CHUNK);
    defer a.free(hints);
    var jobs: [work.MAX_WORKERS]Job = undefined;
    for (jobs[0..workers], 0..) |*job, i| job.* = .{ .source = source, .ch = ch, .dict = dictionaries, .padding_rom = padding_rom, .output = output, .summaries = summaries, .scratch = scratch[i * 10 * CHUNK ..][0 .. 10 * CHUNK], .hints = hints[i * CHUNK ..][0..CHUNK], .start = i, .end = units, .stride = workers, .segment_log = segment_log orelse LOG_CHUNK, .grouped = segment_log != null };
    const totals = try Prefix.run(1, Job, jobs[0..workers], summaries, n, pool);
    source.interaction = output;
    a.free(source.metadata);
    source.metadata = &.{};
    return totals[0];
}
const Job = struct {
    source: *const Source,
    ch: X.types.Challenges,
    dict: Dictionaries,
    padding_rom: Q,
    output: []M,
    summaries: [][1]Q,
    scratch: []Q,
    hints: []Hint,
    start: usize,
    end: usize,
    stride: usize,
    segment_log: u32 = LOG_CHUNK,
    grouped: bool = false,
    correct: bool = false,
    failure: ?anyerror = null,
    pub fn validateTotals(_: *const Job, _: [1]Q) !void {}
    pub fn run(self: *Job) void {
        self.execute() catch |err| {
            self.failure = err;
        };
    }
    fn execute(self: *Job) !void {
        const n = self.source.size();
        if (self.correct) {
            for (self.start..self.end) |p| {
                const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(p, self.source.log_size), self.source.log_size);
                const correction = self.summaries[logical >> @intCast(self.segment_log)][0].toM31Array();
                for (correction, 0..) |value, c| self.output[(X.layout.inter.sum + c) * n + p] = self.output[(X.layout.inter.sum + c) * n + p].add(value);
            }
            return;
        }
        if (self.grouped) return self.executeGrouped();
        // Logical consecutive ranges interleave physical cache lines after
        // bit reversal. For power-of-two teams, round-robin chunks isolate
        // physical regions; summaries retain exact logical-prefix ordering.
        var chunk = self.start;
        while (chunk < self.end) : (chunk += self.stride) {
            const begin = chunk * CHUNK;
            const count: usize = @min(CHUNK, n - begin);
            for (0..count) |i| try self.prepareRow(i, begin + i);
            try core.fields.batchInverseInPlace(Q, self.scratch[0 .. 5 * count], self.scratch[5 * CHUNK ..][0 .. 5 * count]);
            var sum = Q.zero();
            for (0..count) |i| self.emitRow(i, begin + i, &sum);
            self.summaries[chunk] = .{sum};
        }
    }
    /// Line-complete order. The 16 logical rows that share one physical cache
    /// line differ only in logical bits log-5..log-2, i.e. they sit at the
    /// same offset of 16 prefix segments spaced 2^(log-5) rows apart (see
    /// prefix_waves.lineGroupSegments). A group
    /// owns exactly those 16 segments, keeps one running sum per segment in
    /// logical order, and emits row r of all 16 segments back to back so every
    /// column store fills whole lines. Per-row values and per-segment local
    /// prefixes are identical to the chunked order above.
    fn executeGrouped(self: *Job) !void {
        const size = @as(usize, 1) << @intCast(self.segment_log);
        var group = self.start;
        while (group < self.end) : (group += self.stride) {
            const segments = Prefix.lineGroupSegments(self.source.log_size, self.segment_log, group);
            var sums: [16]Q = @splat(Q.zero());
            var r0: usize = 0;
            while (r0 < size) : (r0 += GROUP_BLOCK) {
                for (0..GROUP_BLOCK) |r| for (segments, 0..) |segment, t| try self.prepareRow(16 * r + t, segment * size + r0 + r);
                try core.fields.batchInverseInPlace(Q, self.scratch[0 .. 5 * CHUNK], self.scratch[5 * CHUNK ..][0 .. 5 * CHUNK]);
                for (0..GROUP_BLOCK) |r| for (segments, 0..) |segment, t| self.emitRow(16 * r + t, segment * size + r0 + r, &sums[t]);
            }
            for (segments, sums) |segment, sum| self.summaries[segment] = .{sum};
        }
    }
    fn prepareRow(self: *Job, i: usize, logical: usize) !void {
        const row = try self.source.row(logical);
        const ds = denominators(self.ch, &row, logical, self.source.epoch);
        for (0..3) |slot| self.scratch[5 * i + slot] = ds.before[slot].mul(ds.after[slot]);
        self.scratch[5 * i + 3] = ds.function;
        self.scratch[5 * i + 4] = ds.owner;
        self.hints[i] = .{ .delta = .{ ds.after[0].sub(ds.before[0]), ds.after[1].sub(ds.before[1]), ds.after[2].sub(ds.before[2]) }, .enabled = row[X.layout.main.enabled..][0..3].*, .function = row[X.layout.main.function], .active = row[X.layout.main.active], .gap16 = undefined, .gap8 = undefined, .rom_physical = if (logical < self.source.metadata.len) @intCast(X.layout.physical(self.source.metadata[logical].rom_row, self.source.program.log_size)) else std.math.maxInt(u32) };
        for (0..3) |slot| {
            self.hints[i].gap16[slot] = @intCast(row[X.layout.main.gap16 + slot].v);
            self.hints[i].gap8[slot] = @intCast(row[X.layout.main.gap8 + slot].v);
        }
    }
    fn emitRow(self: *Job, i: usize, logical: usize, sum: *Q) void {
        const n = self.source.size();
        const hint = self.hints[i];
        const source_inv = self.scratch[5 * CHUNK + 5 * i ..][0..5];
        var inverses: [9]Q = undefined;
        @memcpy(inverses[0..4], source_inv[0..4]);
        inverses[4] = if (hint.rom_physical != std.math.maxInt(u32)) self.dict.rom[hint.rom_physical] else self.padding_rom;
        const r16 = [3]Q{ self.dict.range16[hint.gap16[0]], self.dict.range16[hint.gap16[1]], self.dict.range16[hint.gap16[2]] };
        const r8 = [3]Q{ self.dict.range8[hint.gap8[0]], self.dict.range8[hint.gap8[1]], self.dict.range8[hint.gap8[2]] };
        inverses[5] = source_inv[4].mul(r16[0]);
        inverses[6] = r16[1].mul(r16[2]);
        inverses[7] = r8[0].mul(r8[1]);
        inverses[8] = r8[2];
        const p = X.layout.physical(logical, self.source.log_size);
        for (inverses, 0..) |value, column| store(self.output, n, p, 4 * column, value);
        var s = sum.*;
        for (0..3) |slot| s = s.add(hint.delta[slot].mul(inverses[slot]).mulM31(hint.enabled[slot]));
        s = s.add(inverses[3].mulM31(hint.function)).add(inverses[4].mulM31(hint.active));
        s = s.add(source_inv[4].mulM31(hint.active.sub(hint.function)));
        for (r16) |inverse| s = s.add(inverse);
        for (r8) |inverse| s = s.add(inverse);
        store(self.output, n, p, X.layout.inter.sum, s);
        sum.* = s;
    }
};
fn store(output: []M, n: usize, p: usize, column: usize, value: Q) void {
    for (value.toM31Array(), 0..) |v, c| output[(column + c) * n + p] = v;
}
