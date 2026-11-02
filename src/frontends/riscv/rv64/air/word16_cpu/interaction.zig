//! Bounded batched inversion from48-byte native projection metadata. Clock
//! range inverses are shared with the small typed range tables, not recomputed
//! for every CPU query. There is no full-row QM31 advice matrix or ISA replay.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const work = engine.work_pool;
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const L = @import("layout.zig");
const P = @import("public.zig");
const Lookup = @import("lookup.zig");
const Eq = @import("equations.zig");
const Source = @import("trace.zig").Source;
const M = core.fields.m31.M31;
const Q = E.Q;
const CHUNK = 4096;
fn affine(offset: Q, coefficients: []const Q, tuple: []const M) Q {
    var result = offset;
    for (coefficients, tuple) |coefficient, value| result = result.sub(coefficient.mulM31(value));
    return result;
}
fn store(output: []M, n: usize, position: usize, column: usize, value: Q) void {
    for (value.toM31Array(), 0..) |coordinate, i| output[(column + i) * n + position] = coordinate;
}
pub fn generate(source: *Source, challenges: Lookup.Challenges, range16: []const Q, range8: []const Q) !P.Claims {
    return generateWithRomCache(source, challenges, range16, range8, null);
}
pub const RomCache = struct { inverses: []const Q, padding_inverse: Q };
pub fn generateWithRomCache(source: *Source, challenges: Lookup.Challenges, range16: []const Q, range8: []const Q, rom_cache: ?RomCache) !P.Claims {
    try validate(source, range16, range8, rom_cache);
    const a = source.allocator;
    const n = source.size();
    const output = try a.alloc(M, n * L.inter.COUNT);
    errdefer a.free(output);
    const denominators = try a.alloc(Q, 8 * CHUNK);
    defer a.free(denominators);
    const width: usize = if (rom_cache == null) 5 else 4;
    const scratch = try a.alloc(Q, 2 * width * CHUNK);
    defer a.free(scratch);
    var sums: [5]Q = @splat(Q.zero());
    var start: usize = 0;
    while (start < n) : (start += CHUNK) {
        try chunk(.{ .source = source, .challenges = challenges, .range16 = range16, .range8 = range8, .rom_cache = rom_cache, .output = output }, start, denominators, scratch, &sums);
    }
    const prefixes = PREFIXES;
    for (prefixes, sums) |column, claim| {
        for (claim.toM31Array(), 0..) |coordinate, i| for (0..n) |row| {
            const index = (column + i) * n + row;
            output[index] = output[index].sub(coordinate);
        };
    }
    source.interaction = output;
    return .{ .register = sums[0], .function = sums[1], .rom = sums[2], .range16 = sums[3], .range8 = sums[4] };
}

const PREFIXES = [_]usize{ L.inter.register_sum, L.inter.function_sum, L.inter.rom_sum, L.inter.range16_sum, L.inter.range8_sum };
const Context = struct { source: *const Source, challenges: Lookup.Challenges, range16: []const Q, range8: []const Q, rom_cache: ?RomCache, output: []M };
fn chunk(ctx: Context, start: usize, denominators: []Q, scratch: []Q, sums: *[5]Q) !void {
    const source = ctx.source;
    const challenges = ctx.challenges;
    const range16 = ctx.range16;
    const range8 = ctx.range8;
    const rom_cache = ctx.rom_cache;
    const output = ctx.output;
    const n = source.size();
    const width: usize = if (rom_cache == null) 5 else 4;
    const count = @min(CHUNK, n - start);
    for (0..count) |j| {
        const logical = start + j;
        const main = if (rom_cache == null) source.rowValues(logical) else source.dataValues(logical);
        const fixed = [_]M{ M.fromCanonical(@intCast(logical)), M.fromCanonical(@intFromBool(logical == 0)), M.fromCanonical(@intFromBool(logical == n - 1)) };
        const row = denominators[8 * j ..][0..8];
        for (0..3) |slot| {
            const before = Eq.registerTuple(M, &fixed, &main, slot, false);
            const after = Eq.registerTuple(M, &fixed, &main, slot, true);
            row[2 * slot] = affine(challenges.register.offset, &challenges.register.coefficients, &before);
            row[2 * slot + 1] = affine(challenges.register.offset, &challenges.register.coefficients, &after);
            scratch[width * j + slot] = row[2 * slot].mul(row[2 * slot + 1]);
        }
        row[6] = affine(challenges.function.offset, &challenges.function.coefficients, &Eq.functionTuple(M, &main));
        if (rom_cache != null) {
            row[7] = Q.one(); // native inverse supplied by the sealed ROM provider
        } else {
            const rom_tuple = Eq.romTupleProfile(M, source.program.profile, &main);
            row[7] = affine(challenges.rom.offset, &challenges.rom.coefficients, rom_tuple[0..16]);
            if (source.program.profile == .alu_binary_v2) row[7] = affine(row[7], &challenges.rom.control_coefficients, rom_tuple[16..]);
        }
        scratch[width * j + 3] = row[6];
        if (rom_cache == null) scratch[width * j + 4] = row[7];
    }
    const inverse = scratch[width * CHUNK ..][0 .. width * count];
    try core.fields.batchInverseInPlace(Q, scratch[0 .. width * count], inverse);
    for (0..count) |j| {
        const logical = start + j;
        const pos = L.physical(logical, source.log_size);
        const main = if (rom_cache == null) source.rowValues(logical) else source.dataValues(logical);
        const row = denominators[8 * j ..][0..8];
        const inv = inverse[width * j ..][0..width];
        var registers = Q.zero();
        for (0..3) |slot| {
            store(output, n, pos, L.inter.register_inverses + 4 * slot, inv[slot]);
            registers = registers.add(row[2 * slot + 1].sub(row[2 * slot]).mul(inv[slot]).mulM31(main[L.main.enabled + slot]));
        }
        sums[0] = sums[0].add(registers);
        store(output, n, pos, L.inter.register_sum, sums[0]);
        store(output, n, pos, L.inter.function_inverse, inv[3]);
        sums[1] = sums[1].add(inv[3].mulM31(main[L.main.active]));
        store(output, n, pos, L.inter.function_sum, sums[1]);
        const rom_inverse = if (rom_cache) |cache| (if (logical < source.metadata.len) cache.inverses[source.metadata[logical].rom_row] else cache.padding_inverse) else inv[4];
        store(output, n, pos, L.inter.rom_inverse, rom_inverse);
        sums[2] = sums[2].add(rom_inverse.mulM31(main[L.main.active]));
        store(output, n, pos, L.inter.rom_sum, sums[2]);
        const low = [_]Q{ range16[main[L.main.gap16].v], range16[main[L.main.gap16 + 1].v], range16[main[L.main.gap16 + 2].v] };
        const high = [_]Q{ range8[main[L.main.gap8].v], range8[main[L.main.gap8 + 1].v], range8[main[L.main.gap8 + 2].v] };
        store(output, n, pos, L.inter.range16_inverses, low[0].mul(low[1]));
        store(output, n, pos, L.inter.range16_inverses + 4, low[2]);
        sums[3] = sums[3].add(low[0]).add(low[1]).add(low[2]);
        store(output, n, pos, L.inter.range16_sum, sums[3]);
        store(output, n, pos, L.inter.range8_inverses, high[0].mul(high[1]));
        store(output, n, pos, L.inter.range8_inverses + 4, high[2]);
        sums[4] = sums[4].add(high[0]).add(high[1]).add(high[2]);
        store(output, n, pos, L.inter.range8_sum, sums[4]);
    }
}
pub const MIN_STACK_BYTES = if (@import("builtin").mode == .Debug) 1024 * 1024 else 256 * 1024;
/// Both waves finish before publication. All worker scratch is coordinator-owned.
pub fn generateWithRomCacheParallel(source: *Source, challenges: Lookup.Challenges, range16: []const Q, range8: []const Q, rom_cache: ?RomCache, pool: ?*work.WorkPool) !P.Claims {
    return generateParallelImpl(source, challenges, range16, range8, rom_cache, pool, null, null);
}
fn generateParallelImpl(source: *Source, challenges: Lookup.Challenges, range16: []const Q, range8: []const Q, rom_cache: ?RomCache, pool: ?*work.WorkPool, fail_wave: ?usize, fail_after: ?usize) !P.Claims {
    try validate(source, range16, range8, rom_cache);
    if (pool) |active| if (active.stackSize() < MIN_STACK_BYTES) return error.InvalidWord16InteractionStack;
    const chunks = std.math.divCeil(usize, source.size(), CHUNK) catch unreachable;
    const workers = if (pool) |active| @min(active.workerCount(), chunks) else 1;
    if (workers <= 1) return generateWithRomCache(source, challenges, range16, range8, rom_cache);
    const a = source.allocator;
    const n = source.size();
    const width: usize = if (rom_cache == null) 5 else 4;
    const stride = (8 + 2 * width) * CHUNK;
    const output = try a.alloc(M, n * L.inter.COUNT);
    errdefer a.free(output);
    const scratch = try a.alloc(Q, workers * stride);
    defer a.free(scratch);
    const summaries = try a.alloc([5]Q, chunks);
    defer a.free(summaries);
    const ctx = Context{ .source = source, .challenges = challenges, .range16 = range16, .range8 = range8, .rom_cache = rom_cache, .output = output };
    var jobs: [work.MAX_WORKERS]Job = undefined;
    for (jobs[0..workers], 0..) |*job, i| job.* = .{ .ctx = ctx, .summaries = summaries, .scratch = scratch[i * stride ..][0..stride], .start = chunks * i / workers, .end = chunks * (i + 1) / workers };
    var lease = try pool.?.acquire(try work.WorkerBudget.init(workers));
    defer lease.deinit();
    try wave(&lease, jobs[0..workers], if (fail_wave == 0) fail_after else null);
    var sums: [5]Q = @splat(Q.zero());
    for (summaries) |*summary| {
        const local = summary.*;
        summary.* = sums;
        for (&sums, local) |*sum, value| sum.* = sum.add(value);
    }
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
    return .{ .register = sums[0], .function = sums[1], .rom = sums[2], .range16 = sums[3], .range8 = sums[4] };
}
fn wave(lease: *work.WorkLease, jobs: []Job, fail_after: ?usize) !void {
    var group = std.Thread.WaitGroup{};
    var joined = false;
    defer {
        if (!joined) group.wait();
        lease.completeWave();
    }
    for (jobs[1..], 0..) |*job, submitted| {
        if (fail_after == submitted) return error.InjectedInteractionSubmissionFailure;
        try lease.spawnWg(&group, Job.run, .{job});
    }
    jobs[0].run();
    group.wait();
    joined = true;
    for (jobs) |job| if (job.failure) |failure| return failure;
}
const Job = struct {
    ctx: Context,
    summaries: [][5]Q,
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
        if (!self.correct) {
            for (self.start..self.end) |index| {
                var sums: [5]Q = @splat(Q.zero());
                try chunk(self.ctx, index * CHUNK, self.scratch[0 .. 8 * CHUNK], self.scratch[8 * CHUNK ..], &sums);
                self.summaries[index] = sums;
            }
        } else {
            const n = self.ctx.source.size();
            const log = self.ctx.source.log_size;
            for (self.start..self.end) |position| {
                const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(position, log), log);
                const offsets = self.summaries[logical / CHUNK];
                for (PREFIXES, offsets) |column, offset| for (offset.toM31Array(), 0..) |coordinate, i| {
                    const at = (column + i) * n + position;
                    self.ctx.output[at] = self.ctx.output[at].add(coordinate);
                };
            }
        }
    }
};

pub const testing = if (@import("builtin").is_test) struct {
    pub fn failSubmission(source: *Source, challenges: Lookup.Challenges, range16: []const Q, range8: []const Q, cache: ?RomCache, pool: *work.WorkPool, which_wave: usize, after: usize) !P.Claims {
        return generateParallelImpl(source, challenges, range16, range8, cache, pool, which_wave, after);
    }
} else struct {};

fn validate(source: *const Source, range16: []const Q, range8: []const Q, cache: ?RomCache) !void {
    try source.public.validate(source.log_size);
    if (source.rows_projected != source.size() or source.interaction.len != 0 or source.metadata.len != source.public.steps or range16.len != 65536 or range8.len != 256) return error.InvalidWord16CpuPhase;
    if (cache) |dictionary| if (dictionary.inverses.len != source.program.size() or dictionary.padding_inverse.isZero()) return error.InvalidWord16RomCache;
}
