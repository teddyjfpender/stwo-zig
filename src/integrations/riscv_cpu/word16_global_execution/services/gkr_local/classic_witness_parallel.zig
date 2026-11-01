//! Immutable row providers: bounded physical-column generation followed by
//! two joined prefix waves. Existing prefix planes hold row contributions;
//! no row-by-term matrix or additional execution-sized plane is retained.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const C = @import("classic_witness.zig");
const N = @import("classic_witness_numeric.zig");
const Rows = engine.lookups.row_work;
// Relative128-byte output blocks; allocator base alignment is not assumed
// to establish a machine-wide false-sharing guarantee.
pub const BLOCK_ROWS: usize = 32;
pub const MAX_SCRATCH_BYTES: usize = 64 << 20;
pub const Plan = struct {
    rows: usize,
    terms: usize,
    width: usize,
    output_bytes: usize,
    jobs: usize,
    chunk_rows: usize,
    scratch_bytes: usize,
    pub fn init(log: u32, groups: []const C.Group, budget: usize, workers: usize) !Plan {
        if (log < 5 or log > 22 or groups.len == 0 or groups.len > C.MAX_GROUPS) return error.InvalidClassicWitnessShape;
        const rows = @as(usize, 1) << @intCast(log);
        var terms: usize = 0;
        var width: usize = 0;
        for (groups) |g| {
            if (g.inverses == 0) return error.InvalidClassicWitnessShape;
            terms = try std.math.add(usize, terms, g.inverses);
            width = try std.math.add(usize, width, 8 * (@as(usize, g.inverses) + 1));
        }
        if (terms > 640) return error.InvalidClassicWitnessShape;
        const output = try std.math.mul(usize, try std.math.mul(usize, rows, width), @sizeOf(M));
        if (output > budget or terms == 0) return error.ClassicWitnessBudgetExceeded;
        const capacity = @min(MAX_SCRATCH_BYTES, @min(try C.scratchByteUpperBound(log, terms), budget - output));
        const row_bytes = try std.math.mul(usize, terms, 2 * @sizeOf(O) + @sizeOf(C.Numerator));
        var jobs = @max(1, @min(Rows.MAX_SHARDS, @min(workers, rows / (2 * BLOCK_ROWS))));
        while (true) {
            const chunk = @min(C.ROW_CHUNK, capacity / (try std.math.mul(usize, jobs, row_bytes)));
            if (chunk >= core.fields.m31.PACK_WIDTH) {
                const aligned = chunk / core.fields.m31.PACK_WIDTH * core.fields.m31.PACK_WIDTH;
                return .{ .rows = rows, .terms = terms, .width = width, .output_bytes = output, .jobs = jobs, .chunk_rows = aligned, .scratch_bytes = try std.math.mul(usize, try std.math.mul(usize, jobs, aligned), row_bytes) };
            }
            if (jobs == 1) return error.ClassicWitnessBudgetExceeded;
            jobs -= 1;
        }
    }
};
const Scratch = struct {
    d: []O,
    inverses: []O,
    numerators: []C.Numerator,
    fn init(a: std.mem.Allocator, plan: Plan) !Scratch {
        const cells = try std.math.mul(usize, plan.chunk_rows, plan.terms);
        const d = try a.alloc(O, cells);
        errdefer a.free(d);
        const inv = try a.alloc(O, cells);
        errdefer a.free(inv);
        return .{ .d = d, .inverses = inv, .numerators = try a.alloc(C.Numerator, cells) };
    }
    fn deinit(s: *Scratch, a: std.mem.Allocator) void {
        a.free(s.d);
        a.free(s.inverses);
        a.free(s.numerators);
    }
};
pub const Result = struct { data: []M, claims: [C.MAX_GROUPS]O };
pub fn generate(a: std.mem.Allocator, log: u32, groups: []const C.Group, provider: anytype, budget: usize) !Result {
    const pool = engine.work_pool.currentScopedPool();
    const available = if (pool) |p| if (engine.work_pool.cooperative.current() == null) p.availableWorkers() else 1 else 1;
    const plan = try Plan.init(log, groups, budget, available);
    const data = try a.alloc(M, plan.output_bytes / @sizeOf(M));
    errdefer a.free(data);
    var scratch: [Rows.MAX_SHARDS]Scratch = undefined;
    var initialized: usize = 0;
    defer for (scratch[0..initialized]) |*s| s.deinit(a);
    for (scratch[0..plan.jobs]) |*s| {
        s.* = try Scratch.init(a, plan);
        initialized += 1;
    }
    const Generation = struct {
        plan: Plan,
        log: u32,
        groups: []const C.Group,
        provider: @TypeOf(provider),
        data: []M,
        scratch: []Scratch,
        errors: [Rows.MAX_SHARDS]?anyerror = @splat(null),
        pub fn runRange(ctx: *@This(), ordinal: usize, first: usize, end: usize) void {
            ctx.fill(ordinal, first * BLOCK_ROWS, end * BLOCK_ROWS) catch |err| {
                ctx.errors[ordinal] = err;
            };
        }
        fn fill(ctx: *@This(), ordinal: usize, first: usize, end: usize) !void {
            const s = &ctx.scratch[ordinal];
            const n = ctx.plan.rows;
            const terms = ctx.plan.terms;
            var start = first;
            while (start < end) : (start += ctx.plan.chunk_rows) {
                const count = @min(ctx.plan.chunk_rows, end - start);
                const cells = count * terms;
                @memset(s.d[0..cells], O.zero());
                @memset(s.numerators[0..cells], .{ .base = M.zero() });
                for (0..count) |r| {
                    const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(start + r, ctx.log), ctx.log);
                    try ctx.provider.fill(logical, s.d[r * terms ..][0..terms], s.numerators[r * terms ..][0..terms]);
                }
                try N.batchInverse(s.d[0..cells], s.inverses[0..cells]);
                N.contributions(s.numerators[0..cells], s.inverses[0..cells], s.d[0..cells]);
                var query: usize = 0;
                var column: usize = 0;
                for (ctx.groups) |g| {
                    // One query writes eight physically contiguous plane spans.
                    // This avoids the old logical-row wide column scatter.
                    for (0..g.inverses) |q| {
                        for (0..count) |r| {
                            for (s.inverses[r * terms + query + q].toM31Array(), 0..) |v, c| ctx.data[(column + c) * n + start + r] = v;
                        }
                        column += 8;
                    }
                    for (0..count) |r| {
                        const value = N.sum(s.d[r * terms + query ..][0..g.inverses]);
                        for (value.toM31Array(), 0..) |v, c| ctx.data[(column + c) * n + start + r] = v;
                    }
                    query += g.inverses;
                    column += 8;
                }
            }
        }
    };
    const blocks = plan.rows / BLOCK_ROWS;
    var generation = Generation{ .plan = plan, .log = log, .groups = groups, .provider = provider, .data = data, .scratch = scratch[0..plan.jobs] };
    const generated = Rows.forEachRange(blocks, &generation, .{ .max_shards = plan.jobs, .min_rows_per_shard = 2 });
    for (generation.errors[0..generated]) |failure| if (failure) |err| return err;
    // Release every inversion tile before prefix waves. No helper uses the
    // allocator, and no generation consumer remains after the joined call.
    for (scratch[0..initialized]) |*s| s.deinit(a);
    initialized = 0;
    const Prefix = struct {
        log: u32,
        rows: usize,
        groups: []const C.Group,
        data: []M,
        totals: [Rows.MAX_SHARDS][C.MAX_GROUPS]O = @splat(@splat(O.zero())),
        ends: [Rows.MAX_SHARDS]usize = @splat(0),
        pub fn runRange(ctx: *@This(), ordinal: usize, first: usize, end: usize) void {
            var totals: [C.MAX_GROUPS]O = @splat(O.zero());
            for (first * BLOCK_ROWS..end * BLOCK_ROWS) |logical| {
                const physical = A.witness.physical(logical, ctx.log);
                var col: usize = 0;
                for (ctx.groups, 0..) |g, gi| {
                    col += 8 * @as(usize, g.inverses);
                    var limbs: [8]M = undefined;
                    for (&limbs, 0..) |*v, c| v.* = ctx.data[(col + c) * ctx.rows + physical];
                    totals[gi] = totals[gi].add(O.fromM31Array(limbs));
                    for (totals[gi].toM31Array(), 0..) |v, c| ctx.data[(col + c) * ctx.rows + physical] = v;
                    col += 8;
                }
            }
            ctx.totals[ordinal] = totals;
            ctx.ends[ordinal] = end;
        }
    };
    var prefix = Prefix{ .log = log, .rows = plan.rows, .groups = groups, .data = data };
    const prefixed = Rows.forEachRange(blocks, &prefix, .{ .max_shards = plan.jobs, .min_rows_per_shard = 2 });
    var offsets: [Rows.MAX_SHARDS][C.MAX_GROUPS]O = undefined;
    var claim: [C.MAX_GROUPS]O = @splat(O.zero());
    for (0..prefixed) |i| {
        offsets[i] = claim;
        for (groups, 0..) |_, g| claim[g] = claim[g].add(prefix.totals[i][g]);
    }
    const Correction = struct {
        log: u32,
        rows: usize,
        jobs: usize,
        ends: *const [Rows.MAX_SHARDS]usize,
        groups: []const C.Group,
        data: []M,
        offsets: *const [Rows.MAX_SHARDS][C.MAX_GROUPS]O,
        claim: [C.MAX_GROUPS]O,
        pub fn runRange(ctx: *@This(), _: usize, first: usize, end: usize) void {
            var delta: [C.MAX_GROUPS][8][BLOCK_ROWS]M = undefined;
            for (first..end) |block| {
                const start = block * BLOCK_ROWS;
                for (0..BLOCK_ROWS) |r| {
                    const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(start + r, ctx.log), ctx.log);
                    // Use the actual joined scheduler cuts, including its
                    // uneven remainder distribution; no floor-division guess.
                    const logical_block = logical / BLOCK_ROWS;
                    var low: usize = 0;
                    var high = ctx.jobs;
                    while (low < high) {
                        const mid = low + (high - low) / 2;
                        if (logical_block < ctx.ends[mid]) high = mid else low = mid + 1;
                    }
                    const owner = low;
                    for (ctx.groups, 0..) |_, g| {
                        for (ctx.offsets[owner][g].sub(ctx.claim[g]).toM31Array(), 0..) |v, c| delta[g][c][r] = v;
                    }
                }
                var col: usize = 0;
                for (ctx.groups, 0..) |g, gi| {
                    col += 8 * @as(usize, g.inverses);
                    for (0..8) |c| {
                        const destination = ctx.data[(col + c) * ctx.rows + start ..][0..BLOCK_ROWS];
                        var r: usize = 0;
                        while (r < BLOCK_ROWS) : (r += core.fields.m31.PACK_WIDTH) core.fields.m31.storePacked(destination[r..].ptr, core.fields.m31.addPacked(core.fields.m31.loadPacked(destination[r..].ptr), core.fields.m31.loadPacked(delta[gi][c][r..].ptr)));
                    }
                    col += 8;
                }
            }
        }
    };
    var correction = Correction{ .log = log, .rows = plan.rows, .jobs = prefixed, .ends = &prefix.ends, .groups = groups, .data = data, .offsets = &offsets, .claim = claim };
    _ = Rows.forEachRange(blocks, &correction, .{ .max_shards = plan.jobs, .min_rows_per_shard = 2 });
    return .{ .data = data, .claims = claim };
}
