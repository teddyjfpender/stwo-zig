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
const CHUNK = 1024;
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
fn validate(source: *const Source, ch: X.types.Challenges, dict: Dictionaries) !Q {
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
    for (dict.rom, 0..) |inverse, p| {
        var tuple: [30]M = undefined;
        for (&tuple, 0..) |*value, c| value.* = source.program.fixed[c * source.program.size() + p];
        if (!dot(ch.rom, tuple).mul(inverse).eql(Q.one())) return error.InvalidExecutionDictionary;
    }
    const padding = try X.row.padding(0, source.public.final_pc);
    const padding_denominator = dot(ch.rom, X.tuples.rom(M, &padding));
    if (padding_denominator.isZero()) return error.DivisionByZero;
    return padding_denominator.inv();
}
pub fn generate(source: *Source, ch: X.types.Challenges, dictionaries: Dictionaries, pool: ?*work.WorkPool) !Q {
    const padding_rom = try validate(source, ch, dictionaries);
    if (pool) |active| if (active.stackSize() < (if (@import("builtin").mode == .Debug) @as(usize, 1048576) else 262144)) return error.InvalidExecutionInteractionStack;
    const n = source.size();
    const chunks = std.math.divCeil(usize, n, CHUNK) catch unreachable;
    const workers = if (pool) |active| @min(active.workerCount(), chunks) else 1;
    const a = source.allocator;
    const output = try a.alloc(M, X.layout.inter.COUNT * n);
    errdefer a.free(output);
    const summaries = try a.alloc(Q, chunks);
    defer a.free(summaries);
    const scratch = try a.alloc(Q, workers * 10 * CHUNK);
    defer a.free(scratch);
    const hints = try a.alloc(Hint, workers * CHUNK);
    defer a.free(hints);
    var jobs: [work.MAX_WORKERS]Job = undefined;
    for (jobs[0..workers], 0..) |*job, i| job.* = .{ .source = source, .ch = ch, .dict = dictionaries, .padding_rom = padding_rom, .output = output, .summaries = summaries, .scratch = scratch[i * 10 * CHUNK ..][0 .. 10 * CHUNK], .hints = hints[i * CHUNK ..][0..CHUNK], .start = chunks * i / workers, .end = chunks * (i + 1) / workers };
    if (workers > 1) {
        var lease = try pool.?.acquire(try work.WorkerBudget.init(workers));
        defer lease.deinit();
        try wave(&lease, jobs[0..workers]);
        var total = Q.zero();
        for (summaries) |*summary| {
            const local = summary.*;
            summary.* = total;
            total = total.add(local);
        }
        for (summaries) |*summary| summary.* = summary.sub(total);
        for (jobs[0..workers], 0..) |*job, i| {
            job.correct = true;
            job.start = n * i / workers;
            job.end = n * (i + 1) / workers;
        }
        try wave(&lease, jobs[0..workers]);
        source.interaction = output;
        a.free(source.metadata);
        source.metadata = &.{};
        return total;
    }
    jobs[0].run();
    if (jobs[0].failure) |failure| return failure;
    var total = Q.zero();
    for (summaries) |*summary| {
        const local = summary.*;
        summary.* = total;
        total = total.add(local);
    }
    for (summaries) |*summary| summary.* = summary.sub(total);
    jobs[0].correct = true;
    jobs[0].start = 0;
    jobs[0].end = n;
    jobs[0].run();
    if (jobs[0].failure) |failure| return failure;
    source.interaction = output;
    a.free(source.metadata);
    source.metadata = &.{};
    return total;
}
const Job = struct {
    source: *const Source,
    ch: X.types.Challenges,
    dict: Dictionaries,
    padding_rom: Q,
    output: []M,
    summaries: []Q,
    scratch: []Q,
    hints: []Hint,
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
        const n = self.source.size();
        if (self.correct) {
            for (self.start..self.end) |p| {
                const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(p, self.source.log_size), self.source.log_size);
                const correction = self.summaries[logical / CHUNK].toM31Array();
                for (correction, 0..) |value, c| self.output[(X.layout.inter.sum + c) * n + p] = self.output[(X.layout.inter.sum + c) * n + p].add(value);
            }
            return;
        }
        for (self.start..self.end) |chunk| {
            const begin = chunk * CHUNK;
            const count: usize = @min(CHUNK, n - begin);
            for (0..count) |i| {
                const row = try self.source.row(begin + i);
                const ds = denominators(self.ch, &row, begin + i, self.source.epoch);
                for (0..3) |slot| self.scratch[5 * i + slot] = ds.before[slot].mul(ds.after[slot]);
                self.scratch[5 * i + 3] = ds.function;
                self.scratch[5 * i + 4] = ds.owner;
                self.hints[i] = .{ .delta = .{ ds.after[0].sub(ds.before[0]), ds.after[1].sub(ds.before[1]), ds.after[2].sub(ds.before[2]) }, .enabled = row[X.layout.main.enabled..][0..3].*, .function = row[X.layout.main.function], .active = row[X.layout.main.active], .gap16 = undefined, .gap8 = undefined, .rom_physical = if (begin + i < self.source.metadata.len) @intCast(X.layout.physical(self.source.metadata[begin + i].rom_row, self.source.program.log_size)) else std.math.maxInt(u32) };
                for (0..3) |slot| {
                    self.hints[i].gap16[slot] = @intCast(row[X.layout.main.gap16 + slot].v);
                    self.hints[i].gap8[slot] = @intCast(row[X.layout.main.gap8 + slot].v);
                }
            }
            try core.fields.batchInverseInPlace(Q, self.scratch[0 .. 5 * count], self.scratch[5 * CHUNK ..][0 .. 5 * count]);
            var sum = Q.zero();
            for (0..count) |i| {
                const logical = begin + i;
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
                for (0..3) |slot| sum = sum.add(hint.delta[slot].mul(inverses[slot]).mulM31(hint.enabled[slot]));
                sum = sum.add(inverses[3].mulM31(hint.function)).add(inverses[4].mulM31(hint.active));
                sum = sum.add(source_inv[4].mulM31(hint.active.sub(hint.function)));
                for (r16) |inverse| sum = sum.add(inverse);
                for (r8) |inverse| sum = sum.add(inverse);
                store(self.output, n, p, X.layout.inter.sum, sum);
            }
            self.summaries[chunk] = sum;
        }
    }
};
fn store(output: []M, n: usize, p: usize, column: usize, value: Q) void {
    for (value.toM31Array(), 0..) |v, c| output[(column + c) * n + p] = v;
}
fn wave(lease: *work.WorkLease, jobs: []Job) !void {
    var group = std.Thread.WaitGroup{};
    var joined = false;
    defer {
        if (!joined) group.wait();
        lease.completeWave();
    }
    for (jobs[1..]) |*job| try lease.spawnWg(&group, Job.run, .{job});
    jobs[0].run();
    group.wait();
    joined = true;
    for (jobs) |job| if (job.failure) |failure| return failure;
}
