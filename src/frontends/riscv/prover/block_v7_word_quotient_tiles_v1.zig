//! Opt-in exact coset tiles for the existing packed RAM quotient equations.
//! Storage/evaluation only: masks, degree, denominators and random powers remain
//! the original adapter's authority. The output accumulator is caller-owned.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Packed = core.fields.packed_qm31.PackedQM31;
const Circle = engine.poly.circle;
const Blocks = Circle.coset_blocks;
const Poly = engine.air.component_prover.Poly;
const Accumulator = engine.air.accumulation.DomainEvaluationAccumulator;
const Profile = @import("block_v7_word_quotient_profile_v1.zig");
const BaseRows = @import("block_v7_ram_packed_base_v1.zig");
pub const Options = struct {
    tile_log: u32 = 16,
    /// Wider tiles are permitted only when every input already owns exact
    /// native-degree coefficients. Mixed/recovered inputs retain tile_log.
    retained_tile_log: ?u32 = null,
    parallel_rows: bool = true,
    factor_range_pairs: bool = false,
    base_field_rows: bool = false,
    group_bytes: usize = 128 << 20,
    /// Temporary coefficients, three block/group owners and metadata. Excludes
    /// borrowed input trees and the original caller-owned quotient accumulator.
    max_workspace_bytes: usize = 8 << 30,
};
pub const Stats = struct { base_field_rows: bool, factor_range_pairs: bool, charged_peak_bytes: usize, coefficient_bytes: usize, tile_log: u32, tiles: usize, requested_group_bytes: usize, group_bytes: usize, phases: ?Profile.Stats };
/// Reserve room for three prefold caches and metadata before selecting wider
/// tiles. This is a storage heuristic; the child allocator remains the hard
/// aggregate authority. No coefficient recovery is allocated by this planner.
pub fn selectTileLog(options: Options, eval_log: u32, columns: usize, all_retained: bool) !u32 {
    if (eval_log < 2 or eval_log >= core.circle.M31_CIRCLE_LOG_ORDER or options.tile_log < 1 or options.tile_log >= core.circle.M31_CIRCLE_LOG_ORDER or columns == 0 or options.max_workspace_bytes == 0) return error.InvalidWordQuotientTile;
    const base = @min(options.tile_log, eval_log - 1);
    const preferred = options.retained_tile_log orelse return base;
    if (preferred < options.tile_log or preferred >= core.circle.M31_CIRCLE_LOG_ORDER) return error.InvalidWordQuotientTile;
    if (!all_retained) return base;
    var selected = @min(preferred, eval_log - 1);
    while (selected > base) : (selected -= 1) {
        const column_bytes = try std.math.mul(usize, 4, columns);
        const payload = try std.math.mul(usize, column_bytes, @as(usize, 1) << @intCast(selected));
        if (payload <= options.max_workspace_bytes / 4) break;
    }
    return selected;
}

/// Cache space is derived after recovery, when its actual owned footprint is
/// known. Three independent cache owners share the remaining scratch budget.
/// The allocator still enforces the aggregate cap for every later transform.
pub fn affordableGroupBudget(requested: usize, cap: usize, live: usize, tile_bytes: usize) !usize {
    if (live > cap or tile_bytes > cap - live) return error.WordQuotientTileBudgetExceeded;
    const remaining = cap - live - tile_bytes;
    const metadata_reserve = @min(remaining / 8, 16 << 20);
    return @min(requested, (remaining - metadata_reserve) / 3);
}

/// The exact original circle predecessor can visit non-adjacent row tiles.
/// Keep the actual map instead of replacing it by tile-local subtraction.
pub fn priorBlocks(trace_log: u32, eval_log: u32, tile_log: u32, tile: usize) ![2]usize {
    if (trace_log == 0 or eval_log <= trace_log or eval_log >= core.circle.M31_CIRCLE_LOG_ORDER or tile_log == 0 or tile_log >= eval_log or tile >= (@as(usize, 1) << @intCast(eval_log - tile_log))) return error.InvalidWordQuotientTile;
    const rows = @as(usize, 1) << @intCast(tile_log);
    var result: [2]usize = @splat(std.math.maxInt(usize));
    for (0..rows) |local| {
        const prior = core.utils.previousBitReversedCircleDomainIndex(tile * rows + local, trace_log, eval_log) >> @intCast(tile_log);
        if (result[0] == prior or result[1] == prior) continue;
        if (result[0] == std.math.maxInt(usize)) result[0] = prior else if (result[1] == std.math.maxInt(usize)) result[1] = prior else return error.UnsupportedWordPreviousTileGeometry;
    }
    if (result[1] == std.math.maxInt(usize)) result[1] = result[0];
    return result;
}

pub fn evaluate(comptime Spec: type, backing: std.mem.Allocator, spec: Spec, trace_log: u32, source: *const engine.air.component_prover.Trace, accumulator: *Accumulator, options: Options) !Stats {
    // Keep terminal/window RAM explicit and finite. Window retains its two
    // additional state-delta equations; other word families are not admitted.
    const window = Spec == @import("block_v7_window_ram_component_v1.zig").Spec;
    if (comptime Spec != @import("block_v7_ram_component_v1.zig").Spec and !window) return error.UnsupportedWordQuotientTileSpec;
    const BaseKernel = if (window) @import("block_v7_window_ram_packed_base_v1.zig") else BaseRows;
    const F = Spec.FIXED_COUNT;
    const W = Spec.MAIN_COUNT;
    const I = Spec.INTERACTION_COUNT;
    const N = F + W + I;
    @setEvalBranchQuota(1000 + 128 * W);
    const eval_log = try std.math.add(u32, trace_log, Spec.EXPANSION_BITS);
    if (trace_log == 0 or eval_log >= core.circle.M31_CIRCLE_LOG_ORDER or options.tile_log == 0 or options.max_workspace_bytes == 0) return error.InvalidWordQuotientTile;
    if (source.polys.items.len != 3 or source.polys.items[0].len != F or source.polys.items[1].len != W or source.polys.items[2].len != I) return error.InvalidV5WordTrees;
    const native_rows = @as(usize, 1) << @intCast(trace_log);
    const previous_count = comptime blk: {
        var n: usize = I;
        for (Spec.PREVIOUS_MAIN_MASK) |needed| n += @intFromBool(needed);
        break :blk n;
    };
    var all_retained = true;
    for (source.polys.items) |tree| for (tree) |poly| {
        if (poly.coefficients == null) all_retained = false;
    };
    const tile_log = try selectTileLog(options, eval_log, N + 2 * previous_count, all_retained);
    const rows = @as(usize, 1) << @intCast(tile_log);
    if (rows < core.fields.m31.PACK_WIDTH) return error.InvalidWordQuotientTile;
    const minimum_tiles = try std.math.mul(usize, 4 * rows, N + 2 * previous_count);
    if (minimum_tiles > options.max_workspace_bytes) return error.WordQuotientTileBudgetExceeded;
    const budget = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(backing, options.max_workspace_bytes);
    defer budget.destroy();
    const a = budget.allocator();
    var profile: ?Profile.Stats = if (std.process.hasEnvVarConstant("STWO_WORD_QUOTIENT_TILE_PROFILE")) .{} else null;
    var phase_clock: ?std.time.Timer = if (profile != null) try std.time.Timer.start() else null;
    var polys: [N]Poly = undefined;
    @memcpy(polys[0..F], source.polys.items[0]);
    @memcpy(polys[F .. F + W], source.polys.items[1]);
    @memcpy(polys[F + W ..], source.polys.items[2]);
    var owners: [N][]M = @splat(&.{});
    defer for (owners) |owned| if (owned.len != 0) a.free(owned);
    var sources: [N]Blocks.Source = undefined;
    var coefficient_bytes: usize = 0;
    {
        // One exact interpolation domain suffices for all smaller canonical
        // source cosets. Release it before allocating row/group tile caches.
        var recovery_log: ?u32 = null;
        for (polys) |poly| if (poly.coefficients == null) {
            try poly.validate();
            if (poly.log_size < trace_log or poly.log_size > eval_log or poly.values.len == 0) return error.InvalidProofShape;
            recovery_log = @max(recovery_log orelse 0, poly.log_size);
        };
        var recovery_twiddles = if (recovery_log) |log| try engine.poly.twiddles.precomputeM31(a, Circle.CanonicCoset.new(log).circleDomain().half_coset) else null;
        defer if (recovery_twiddles) |*twiddles| engine.poly.twiddles.deinitM31(a, twiddles);
        for (polys, &owners, &sources) |poly, *owned, *out| {
            try poly.validate();
            const coefficients = if (poly.coefficients) |coefficient| blk: {
                if (coefficient.logSize() != trace_log) return error.InvalidProofShape;
                break :blk coefficient.coefficients();
            } else blk: {
                if (poly.log_size < trace_log or poly.log_size > eval_log or poly.values.len == 0) return error.InvalidProofShape;
                owned.* = try a.dupe(M, poly.values);
                const domain = Circle.CanonicCoset.new(poly.log_size).circleDomain();
                const twiddles = recovery_twiddles orelse return error.InvalidProofShape;
                _ = try Circle.poly.interpolateOwnedValuesWithTwiddles(domain, owned.*, .init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles));
                for (owned.*[native_rows..]) |value| if (!value.isZero()) return error.InvalidProofShape;
                owned.* = try a.realloc(owned.*, native_rows);
                coefficient_bytes = try std.math.add(usize, coefficient_bytes, 4 * native_rows);
                break :blk owned.*;
            };
            out.* = .{ .coefficients = coefficients, .coset_log = eval_log };
        }
    }
    if (phase_clock) |*clock| profile.?.recovery_ns = clock.lap();
    var previous_sources: [previous_count]Blocks.Source = undefined;
    var previous_index: [N]usize = @splat(std.math.maxInt(usize));
    var n_previous: usize = 0;
    for (sources, 0..) |s, index| {
        const needed = if (index >= F + W) true else if (index >= F) Spec.PREVIOUS_MAIN_MASK[index - F] else false;
        if (!needed) continue;
        previous_index[index] = n_previous;
        previous_sources[n_previous] = s;
        n_previous += 1;
    }
    std.debug.assert(n_previous == previous_count);
    const group_bytes = try affordableGroupBudget(options.group_bytes, options.max_workspace_bytes, budget.snapshot().live_bytes, minimum_tiles);
    var current = try Blocks.Tiles.init(a, &sources, eval_log, tile_log, group_bytes);
    defer current.deinit();
    var before0 = try Blocks.Tiles.init(a, &previous_sources, eval_log, tile_log, group_bytes);
    defer before0.deinit();
    var before1 = try Blocks.Tiles.init(a, &previous_sources, eval_log, tile_log, group_bytes);
    defer before1.deinit();
    const prior_owners = [2]*Blocks.Tiles{ &before0, &before1 };
    if (profile) |*stats| stats.group_logs = .{ current.group_log, before0.group_log, before1.group_log };
    const prepared = try spec.prepareDomain(@intCast(native_rows));
    const base_prepared = if (options.base_field_rows) try BaseKernel.Prepared.initWithRangeFactoring(prepared, options.factor_range_pairs) else null;
    var inverses: [1 << Spec.EXPANSION_BITS]M = undefined;
    const domain = Circle.CanonicCoset.new(eval_log).circleDomain();
    const coset = Circle.CanonicCoset.new(trace_log).coset();
    for (&inverses, 0..) |*inverse, i| inverse.* = try core.constraints.cosetVanishing(M, coset, domain.at(core.utils.bitReverseIndex(i, Spec.EXPANSION_BITS))).inv();
    const output = try accumulator.columns(backing, &.{.{ .log_size = eval_log, .n_cols = Spec.CONSTRAINT_COUNT }});
    defer backing.free(output);
    var result = output[0];
    var powers: [Spec.CONSTRAINT_COUNT]Packed = undefined;
    for (&powers, 0..) |*power, i| power.* = Packed.splat(result.random_coeff_powers[result.random_coeff_powers.len - 1 - i]);
    const RowJob = struct {
        current: *Blocks.Tiles,
        prior_owners: [2]*Blocks.Tiles,
        prior_tiles: [2]usize,
        previous_index: *const [N]usize,
        prepared: Spec.Domain,
        base_prepared: ?*const BaseKernel.Prepared,
        inverses: *const [1 << Spec.EXPANSION_BITS]M,
        powers: *const [Spec.CONSTRAINT_COUNT]Packed,
        trace_log: u32,
        eval_log: u32,
        tile_log: u32,
        tile: usize,
        rows: usize,
        begin: usize,
        end: usize,
        result: engine.air.accumulation.ColumnAccumulator,
        failure: ?anyerror = null,
        fn run(self: *@This()) !void {
            var row_result = self.result;
            defer self.result = row_result;
            var local: usize = self.begin;
            while (local < self.end) : (local += core.fields.m31.PACK_WIDTH) {
                const global = self.tile * self.rows + local;
                const packed_width = core.fields.m31.PACK_WIDTH;
                if (local + packed_width > self.rows) return error.InvalidWordQuotientTile;
                var prior_owner: [packed_width]usize = undefined;
                var prior_offset: [packed_width]usize = undefined;
                var inverse: core.fields.m31.PackedM31 = undefined;
                for (0..packed_width) |lane| {
                    const before = core.utils.previousBitReversedCircleDomainIndex(global + lane, self.trace_log, self.eval_log);
                    const block = before >> @intCast(self.tile_log);
                    prior_owner[lane] = if (block == self.prior_tiles[0]) 0 else if (block == self.prior_tiles[1]) 1 else return error.UnsupportedWordPreviousTileGeometry;
                    prior_offset[lane] = before & (self.rows - 1);
                    inverse[lane] = self.inverses[(global + lane) >> @intCast(self.trace_log)].v;
                }
                var fixed: [F]core.fields.m31.PackedM31 = undefined;
                var main: [W]core.fields.m31.PackedM31 = undefined;
                var prior_main: [W]core.fields.m31.PackedM31 = @splat(@splat(0));
                var interaction: [I]core.fields.m31.PackedM31 = undefined;
                var previous: [I]core.fields.m31.PackedM31 = undefined;
                for (&fixed, 0..) |*value, i| value.* = core.fields.m31.loadPacked(self.current.block(i).ptr + local);
                inline for (0..W) |i| {
                    main[i] = core.fields.m31.loadPacked(self.current.block(F + i).ptr + local);
                    if (Spec.PREVIOUS_MAIN_MASK[i]) prior_main[i] = gather(self.prior_owners, self.previous_index[F + i], prior_owner, prior_offset);
                }
                for (&interaction, &previous, 0..) |*value, *before, i| {
                    value.* = core.fields.m31.loadPacked(self.current.block(F + W + i).ptr + local);
                    before.* = gather(self.prior_owners, self.previous_index[F + W + i], prior_owner, prior_offset);
                }
                const folded = if (self.base_prepared) |base| base.fold(fixed, main, prior_main, interaction, previous, self.powers) else blk: {
                    const equations = self.prepared.evaluatePacked(BaseRows.lift(F, fixed), BaseRows.lift(W, main), BaseRows.lift(W, prior_main), BaseRows.lift(I, interaction), BaseRows.lift(I, previous));
                    var sum = Packed.zero();
                    for (equations, self.powers.*) |equation, power| sum = sum.add(equation.mul(power));
                    break :blk sum;
                };
                const scaled = folded.mulBase(inverse);
                for (0..packed_width) |lane| row_result.accumulate(global + lane, scaled.lane(lane));
            }
        }
        fn worker(self: *@This()) void {
            self.run() catch |err| {
                self.failure = err;
            };
        }
    };
    for (0..current.tileCount()) |tile| {
        if (phase_clock) |*clock| clock.reset();
        const prior_tiles = try priorBlocks(trace_log, eval_log, tile_log, tile);
        if (phase_clock) |*clock| profile.?.mapping_ns += clock.lap();
        if (profile) |*stats| {
            try Profile.load(&current, tile, &stats.current);
            for (prior_owners, prior_tiles) |previous, index| try Profile.load(previous, index, &stats.previous);
        } else {
            try current.load(tile);
            for (prior_owners, prior_tiles) |previous, index| try previous.load(index);
        }
        if (phase_clock) |*clock| clock.reset();
        defer if (phase_clock) |*clock| {
            profile.?.rows_ns += clock.read();
        };
        var first = RowJob{ .current = &current, .prior_owners = prior_owners, .prior_tiles = prior_tiles, .previous_index = &previous_index, .prepared = prepared, .base_prepared = if (base_prepared) |*base| base else null, .inverses = &inverses, .powers = &powers, .trace_log = trace_log, .eval_log = eval_log, .tile_log = tile_log, .tile = tile, .rows = rows, .begin = 0, .end = rows, .result = result };
        const pool_mod = engine.work_pool;
        const pool = if (options.parallel_rows and rows >= 16384) pool_mod.getGlobalPool() else null;
        const count = if (pool) |workers| @min(workers.availableWorkers(), rows / 8192) else 1;
        if (count > 1) {
            var lease = pool.?.acquire(try pool_mod.WorkerBudget.init(count)) catch |err| switch (err) {
                error.WorkerBudgetUnavailable => {
                    try first.run();
                    result = first.result;
                    continue;
                },
                else => return err,
            };
            var group: std.Thread.WaitGroup = .{};
            var joined = false;
            defer {
                if (!joined) group.wait();
                lease.completeWave();
                lease.deinit();
            }
            var jobs: [pool_mod.MAX_WORKERS]RowJob = undefined;
            for (jobs[0..count], 0..) |*job, index| {
                job.* = first;
                const packs = rows / core.fields.m31.PACK_WIDTH;
                job.begin = packs * index / count * core.fields.m31.PACK_WIDTH;
                job.end = packs * (index + 1) / count * core.fields.m31.PACK_WIDTH;
                job.result.next_fresh_index = if (result.next_fresh_index == tile * rows) tile * rows + job.begin else null;
            }
            for (jobs[1..count]) |*job| try lease.spawnWg(&group, RowJob.worker, .{job});
            jobs[0].worker();
            group.wait();
            joined = true;
            for (jobs[0..count]) |job| if (job.failure) |err| return err;
            result.next_fresh_index = if (result.next_fresh_index == tile * rows) (tile + 1) * rows else null;
        } else {
            try first.run();
            result = first.result;
        }
    }
    const stats = Stats{ .base_field_rows = options.base_field_rows, .factor_range_pairs = options.factor_range_pairs, .charged_peak_bytes = budget.snapshot().peak_live_bytes, .coefficient_bytes = coefficient_bytes, .tile_log = tile_log, .tiles = current.tileCount(), .requested_group_bytes = options.group_bytes, .group_bytes = group_bytes, .phases = profile };
    if (std.process.hasEnvVarConstant("STWO_WORD_QUOTIENT_TILE_PROFILE")) std.debug.print("WORD_QUOTIENT_TILED {f}\n", .{std.json.fmt(stats, .{})});
    return stats;
}
fn gather(owners: [2]*Blocks.Tiles, index: usize, owner: [core.fields.m31.PACK_WIDTH]usize, offset: [core.fields.m31.PACK_WIDTH]usize) core.fields.m31.PackedM31 {
    var values: core.fields.m31.PackedM31 = undefined;
    for (owner, offset, 0..) |slot, at, lane| values[lane] = owners[slot].block(index)[at].v;
    return values;
}

test "word quotient previous tiles preserve every original global predecessor" {
    for (2..9) |raw_trace| {
        const trace: u32 = @intCast(raw_trace);
        const eval = trace + 2;
        for (1..eval) |raw_tile| {
            const tile_log: u32 = @intCast(raw_tile);
            const rows = @as(usize, 1) << @intCast(tile_log);
            for (0..@as(usize, 1) << @intCast(eval - tile_log)) |tile| {
                const blocks = try priorBlocks(trace, eval, tile_log, tile);
                for (0..rows) |row| {
                    const expected = core.utils.previousBitReversedCircleDomainIndex(tile * rows + row, trace, eval);
                    try std.testing.expect(expected / rows == blocks[0] or expected / rows == blocks[1]);
                    try std.testing.expectEqual(expected, (expected / rows) * rows + (expected & (rows - 1)));
                }
            }
        }
    }
    try std.testing.expectError(error.InvalidWordQuotientTile, priorBlocks(4, 6, 6, 0));
    try std.testing.expectError(error.InvalidWordQuotientTile, priorBlocks(4, 6, 2, 16));
}

test "v7 RAM tiled quotient rejects recovered high-degree coefficients before folding" {
    const a = std.testing.allocator;
    const Spec = @import("block_v7_ram_component_v1.zig").Spec;
    // This column is a valid committed-domain polynomial but exceeds the
    // independently admitted native degree. No prefix-only interpolation or
    // silent high-tail truncation may turn it into an admissible trace.
    var evaluations: [32]M = @splat(M.zero());
    evaluations[8] = M.one();
    const domain = Circle.CanonicCoset.new(5).circleDomain();
    var twiddles = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
    defer engine.poly.twiddles.deinitM31(a, &twiddles);
    try Circle.poly.evaluateBuffersWithTwiddles(&.{&evaluations}, domain, .init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles));
    const poly = Poly{ .log_size = 5, .values = &evaluations };
    const fixed = [_]Poly{poly} ** Spec.FIXED_COUNT;
    const main = [_]Poly{poly} ** Spec.MAIN_COUNT;
    const interaction = [_]Poly{poly} ** Spec.INTERACTION_COUNT;
    var trees = [_][]const Poly{ &fixed, &main, &interaction };
    const source = engine.air.component_prover.Trace{ .polys = .{ .items = &trees } };
    var accumulator = try Accumulator.init(a, Q.one(), 5, Spec.CONSTRAINT_COUNT);
    defer accumulator.deinit();
    try std.testing.expectError(error.InvalidProofShape, evaluate(Spec, a, std.mem.zeroes(Spec), 3, &source, &accumulator, .{ .tile_log = 3, .group_bytes = 4096, .max_workspace_bytes = 1 << 20 }));
    try std.testing.expectEqual(@as(usize, Spec.CONSTRAINT_COUNT), accumulator.next_power_index);
    for (accumulator.sub_accumulations) |bucket| try std.testing.expect(bucket == null);
}

test "v7 RAM tiled cache admission accounts recovered coefficients and three cache owners" {
    const cap: usize = 4 << 30;
    try std.testing.expectEqual(@as(usize, 1 << 30), try affordableGroupBudget(1 << 30, cap, 0, 64 << 20));
    const recovered: usize = 228 * (1 << 22) * 4;
    const chosen = try affordableGroupBudget(1 << 30, cap, recovered, 64 << 20);
    try std.testing.expect(chosen < 128 << 20);
    try std.testing.expect(recovered + (64 << 20) + 3 * chosen <= cap);
    try std.testing.expectError(error.WordQuotientTileBudgetExceeded, affordableGroupBudget(1, 10, 11, 0));
    try std.testing.expectError(error.WordQuotientTileBudgetExceeded, affordableGroupBudget(1, 10, 9, 2));
}

test "v7 RAM tiled wider retained layout clamps before scratch allocation" {
    const options = Options{ .tile_log = 15, .retained_tile_log = 18, .max_workspace_bytes = 4 << 30 };
    try std.testing.expectEqual(@as(u32, 18), try selectTileLog(options, 24, 478, true));
    try std.testing.expectEqual(@as(u32, 15), try selectTileLog(options, 24, 478, false));
    var small = options;
    small.max_workspace_bytes = 1 << 30;
    try std.testing.expectEqual(@as(u32, 17), try selectTileLog(small, 24, 478, true));
    small.max_workspace_bytes = 256 << 20;
    try std.testing.expectEqual(@as(u32, 15), try selectTileLog(small, 24, 478, true));
    try std.testing.expectEqual(@as(u32, 7), try selectTileLog(options, 8, 478, true));
    small.retained_tile_log = 14;
    try std.testing.expectError(error.InvalidWordQuotientTile, selectTileLog(small, 24, 478, false));
    try std.testing.expectError(error.InvalidWordQuotientTile, selectTileLog(options, 31, 478, true));
    try std.testing.expectError(error.Overflow, selectTileLog(options, 24, std.math.maxInt(usize), true));
}
