//! Contiguous bit-reversed blocks of a polynomial's coset evaluation, from its
//! coefficients, without evaluating the whole coset (design §9.3, recompute
//! per tile).
//!
//! A block of `2^j` bit-reversed positions of `CanonicCoset(L)`'s evaluation
//! is the evaluation on a smaller conjugate coset (`coset_partition`). On a
//! circle domain of log size `j` every circle-basis factor from `j` up is a
//! constant, so a polynomial of `2^c > 2^j` coefficients is folded to `2^j`
//! coefficients (`foldWeights`, `foldToDomain`) and evaluated with one `2^j`
//! FFT. The values are the polynomial's exact evaluations: equal, value for
//! value, to the whole-coset FFT's.
//!
//! `Tiles` walks aligned row tiles of an evaluation domain over many
//! polynomials at once, the shape both a composition lease and a row-tiled
//! Merkle commitment need. Consecutive tiles form groups that share every
//! basis constant above `block_log + group_log`, so each polynomial is folded
//! once per group into a group buffer and each tile folds only from there.

const std = @import("std");
const core = @import("stwo_core");
const poly = @import("poly.zig");
const coset_partition = @import("coset_partition.zig");
const twiddles = @import("../twiddles.zig");
const work_pool = @import("../../work_pool.zig");

const M31 = core.fields.m31.M31;
const CanonicCoset = core.poly.circle.canonic.CanonicCoset;
const CircleDomain = core.poly.circle.domain.CircleDomain;

/// The weights `foldToDomain` applies to the `coefficient_count / domain.size()`
/// chunks of a polynomial (one weight, 1, when the polynomial is no larger than
/// the domain). Coefficient bit `i` carries basis factor `i` (`y`, then `x`
/// doubled `i - 1` times). On a circle domain of log size `j` every factor
/// `i >= j` is the constant `x(2^(i-1) * p)` for any domain point `p`, so
/// chunk `h` is weighted by the product of the constants of `h`'s set bits.
pub fn foldWeights(a: std.mem.Allocator, domain: CircleDomain, coefficient_count: usize) ![]M31 {
    const n = domain.size();
    if (!std.math.isPowerOfTwo(coefficient_count) or n < 2) return error.InvalidBlockShape;
    if (coefficient_count <= n) {
        const weights = try a.alloc(M31, 1);
        weights[0] = M31.one();
        return weights;
    }
    const j: u32 = @intCast(std.math.log2_int(usize, n));
    const c: u32 = @intCast(std.math.log2_int(usize, coefficient_count));
    const weights = try a.alloc(M31, @as(usize, 1) << @intCast(c - j));
    weights[0] = M31.one();
    var filled: usize = 1;
    var x = domain.half_coset.initial.x;
    var factor: u32 = 1;
    while (factor < c) : (factor += 1) {
        if (factor >= j) {
            for (0..filled) |h| weights[filled + h] = weights[h].mul(x);
            filled *= 2;
        }
        x = core.circle.CirclePointM31.doubleX(x);
    }
    std.debug.assert(filled == weights.len);
    return weights;
}

/// Writes into `out` circle-basis coefficients whose FFT on the domain
/// `weights` was built for (`foldWeights`) equals `coefficients`' evaluation
/// there: the weighted sum of `coefficients`' `out.len`-sized chunks, or
/// `coefficients` zero-padded when it is no larger than `out`.
pub fn foldToDomain(coefficients: []const M31, weights: []const M31, out: []M31) void {
    const n = out.len;
    if (coefficients.len <= n) {
        @memcpy(out[0..coefficients.len], coefficients);
        @memset(out[coefficients.len..], M31.zero());
        return;
    }
    std.debug.assert(weights.len * n == coefficients.len);
    const m31 = core.fields.m31;
    const width = m31.PACK_WIDTH;
    const block: usize = @min(n, 2048);
    var start: usize = 0;
    while (start < n) : (start += block) {
        const dst = out[start..][0..block];
        @memcpy(dst, coefficients[start..][0..block]);
        for (weights[1..], 1..) |weight, h| {
            const src = coefficients[h * n + start ..][0..block];
            if (block % width == 0) {
                const w: m31.PackedM31 = m31.splatPacked(weight);
                var k: usize = 0;
                while (k < block) : (k += width) {
                    const sum = m31.addPacked(m31.loadPacked(dst[k..].ptr), m31.mulPacked(m31.loadPacked(src[k..].ptr), w));
                    m31.storePacked(dst[k..].ptr, sum);
                }
            } else for (dst, src) |*d, value| {
                d.* = d.add(value.mul(weight));
            }
        }
    }
}

/// A block's domain, fold weights and (for blocks that are evaluated, not
/// only folded) twiddle tree, cached per load: every polynomial of one shape
/// shares them.
pub const Shape = struct {
    coset_log: u32,
    block_log: u32,
    part: usize,
    coefficient_count: usize,
    domain: CircleDomain,
    transform: ?twiddles.TwiddleTree([]M31),
    weights: []M31,
};

pub const Shapes = struct {
    allocator: std.mem.Allocator,
    items: std.ArrayList(Shape) = .empty,

    pub fn init(allocator: std.mem.Allocator) Shapes {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Shapes) void {
        for (self.items.items) |*shape| {
            if (shape.transform) |*transform| twiddles.deinitM31(self.allocator, transform);
            self.allocator.free(shape.weights);
        }
        self.items.deinit(self.allocator);
        self.* = undefined;
    }

    /// Block `part` of log size `block_log` of `CanonicCoset(coset_log)`, for
    /// a polynomial of `coefficient_count` coefficients. The pointer is valid
    /// until the next call.
    pub fn get(self: *Shapes, coset_log: u32, block_log: u32, part: usize, coefficient_count: usize, with_transform: bool) !*Shape {
        const a = self.allocator;
        for (self.items.items) |*shape| {
            if (shape.coset_log == coset_log and shape.block_log == block_log and shape.part == part and shape.coefficient_count == coefficient_count) {
                if (with_transform and shape.transform == null) shape.transform = try twiddles.precomputeM31(a, shape.domain.half_coset);
                return shape;
            }
        }
        if (block_log > coset_log) return error.InvalidBlockShape;
        const full = CanonicCoset.new(coset_log).circleDomain();
        const domain = try coset_partition.domain(full, coset_log - block_log, part);
        var transform: ?twiddles.TwiddleTree([]M31) = if (with_transform) try twiddles.precomputeM31(a, domain.half_coset) else null;
        errdefer if (transform) |*owned| twiddles.deinitM31(a, owned);
        const weights = try foldWeights(a, domain, coefficient_count);
        errdefer a.free(weights);
        try self.items.append(a, .{
            .coset_log = coset_log,
            .block_log = block_log,
            .part = part,
            .coefficient_count = coefficient_count,
            .domain = domain,
            .transform = transform,
            .weights = weights,
        });
        return &self.items.items[self.items.items.len - 1];
    }

    /// A job writing block `part` (`out.len` values) of `coefficients`'
    /// evaluation on `CanonicCoset(coset_log)`.
    pub fn blockJob(self: *Shapes, coefficients: []const M31, coset_log: u32, part: usize, out: []M31) !BlockJob {
        const block_log: u32 = @intCast(std.math.log2_int(usize, out.len));
        const shape = try self.get(coset_log, block_log, part, coefficients.len, true);
        const transform = shape.transform.?;
        return .{
            .coefficients = coefficients,
            .weights = shape.weights,
            .values = out,
            .domain = shape.domain,
            .transform = .{ .root_coset = transform.root_coset, .twiddles = transform.twiddles, .itwiddles = transform.itwiddles },
        };
    }
};

pub const BlockJob = struct {
    coefficients: []const M31,
    weights: []const M31,
    values: []M31,
    domain: CircleDomain,
    transform: twiddles.TwiddleTree([]const M31),
    failure: ?anyerror = null,

    pub fn run(self: *BlockJob) void {
        foldToDomain(self.coefficients, self.weights, self.values);
        poly.evaluateBuffersWithTwiddles(&.{self.values}, self.domain, self.transform) catch |err| {
            self.failure = err;
        };
    }
};

pub const FoldJob = struct {
    coefficients: []const M31,
    weights: []const M31,
    values: []M31,

    pub fn run(self: *FoldJob) void {
        foldToDomain(self.coefficients, self.weights, self.values);
    }
};

/// Runs `jobs` (each with `run(*Job)`) on the global work pool, or serially.
pub fn runJobs(comptime Job: type, jobs: []Job) void {
    if (jobs.len == 0) return;
    if (work_pool.getGlobalPool()) |pool| {
        var group: std.Thread.WaitGroup = .{};
        for (jobs[1..]) |*job| pool.spawnWg(&group, Job.run, .{job});
        jobs[0].run();
        group.wait();
    } else for (jobs) |*job| job.run();
}

/// A polynomial and the coset it is read on.
pub const Source = struct {
    coefficients: []const M31,
    coset_log: u32,
};

/// The largest tile log in `[min_tile_log, evaluation_log)` whose blocks
/// (`4 << (tile_log - lift)` bytes per source) plus `extra_bytes(tile_log)`
/// fit `budget`, or `min_tile_log` when none does.
pub fn chooseTileLog(
    coset_logs: []const u32,
    evaluation_log: u32,
    min_tile_log: u32,
    budget: usize,
    extra: anytype,
) u32 {
    var tile_log = evaluation_log;
    while (tile_log > min_tile_log) {
        tile_log -= 1;
        var bytes: usize = extra.bytes(tile_log);
        for (coset_logs) |log| bytes +|= @as(usize, 4) << @intCast(tile_log - (evaluation_log - log));
        if (bytes <= budget) break;
    }
    return tile_log;
}

/// Row tiles of `CanonicCoset(evaluation_log)`'s bit-reversed positions over
/// many sources. Tile `t` of source `i` is block `t` of log
/// `tile_log - (evaluation_log - coset_log)` of its coset evaluation: the
/// positions a lifted read of the tile's rows touches.
pub const Tiles = struct {
    allocator: std.mem.Allocator,
    sources: []const Source,
    evaluation_log: u32,
    tile_log: u32,
    block_logs: []u32,
    offsets: []usize,
    arena: []M31,
    /// Tiles per group is `2^group_log`; `group_offsets[i]` is source `i`'s
    /// group buffer in `group_arena`, or `ungrouped`.
    group_log: u32 = 0,
    group_offsets: []usize,
    group_arena: []M31,
    loaded_group: ?usize = null,

    pub const ungrouped = std.math.maxInt(usize);

    /// `sources` must outlive the tiles, and every source's block must hold
    /// at least two positions.
    pub fn init(a: std.mem.Allocator, sources: []const Source, evaluation_log: u32, tile_log: u32, group_budget: usize) !Tiles {
        var result = Tiles{
            .allocator = a,
            .sources = sources,
            .evaluation_log = evaluation_log,
            .tile_log = tile_log,
            .block_logs = &.{},
            .offsets = &.{},
            .arena = &.{},
            .group_offsets = &.{},
            .group_arena = &.{},
        };
        errdefer result.deinit();
        result.block_logs = try a.alloc(u32, sources.len);
        result.offsets = try a.alloc(usize, sources.len);
        var offset: usize = 0;
        for (sources, result.block_logs, result.offsets) |source, *block_log, *slot| {
            if (source.coset_log > evaluation_log or tile_log + source.coset_log < evaluation_log + 1)
                return error.InvalidBlockShape;
            block_log.* = tile_log - (evaluation_log - source.coset_log);
            slot.* = offset;
            offset += @as(usize, 1) << @intCast(block_log.*);
        }
        result.arena = try a.alloc(M31, offset);

        // Group size: the fewest coefficient reads (a prefold per group plus
        // a small fold per tile) whose group buffers fit `group_budget`.
        const tile_count_log = evaluation_log - tile_log;
        var best_reads: u128 = std.math.maxInt(u128);
        var group_log: u32 = 0;
        while (group_log <= tile_count_log) : (group_log += 1) {
            var reads: u128 = 0;
            var bytes: usize = 0;
            for (sources, result.block_logs) |source, block_log| {
                const count = source.coefficients.len;
                const grouped_len = @as(usize, 1) << @intCast(block_log + group_log);
                if (group_log != 0 and count > grouped_len) {
                    reads += (@as(u128, count) << @intCast(tile_count_log - group_log)) + (@as(u128, grouped_len) << @intCast(tile_count_log));
                    bytes +|= 4 * grouped_len;
                } else reads += @as(u128, count) << @intCast(tile_count_log);
            }
            if (bytes > group_budget) break;
            if (reads < best_reads) {
                best_reads = reads;
                result.group_log = group_log;
            }
        }
        result.group_offsets = try a.alloc(usize, sources.len);
        var group_len: usize = 0;
        for (sources, result.block_logs, result.group_offsets) |source, block_log, *group_offset| {
            const grouped_len = @as(usize, 1) << @intCast(block_log + result.group_log);
            if (result.group_log != 0 and source.coefficients.len > grouped_len) {
                group_offset.* = group_len;
                group_len += grouped_len;
            } else group_offset.* = ungrouped;
        }
        result.group_arena = try a.alloc(M31, group_len);
        return result;
    }

    pub fn deinit(self: *Tiles) void {
        const a = self.allocator;
        a.free(self.group_arena);
        a.free(self.group_offsets);
        a.free(self.arena);
        a.free(self.offsets);
        a.free(self.block_logs);
        self.* = undefined;
    }

    pub fn tileCount(self: *const Tiles) usize {
        return @as(usize, 1) << @intCast(self.evaluation_log - self.tile_log);
    }

    pub fn tileRows(self: *const Tiles) usize {
        return @as(usize, 1) << @intCast(self.tile_log);
    }

    /// Source `index`'s block of the loaded tile.
    pub fn block(self: *const Tiles, index: usize) []M31 {
        return self.arena[self.offsets[index]..][0 .. @as(usize, 1) << @intCast(self.block_logs[index])];
    }

    /// Prefolds the tile's group if it is new, then appends one job per
    /// source writing its block of `tile` to `jobs`, which the caller runs
    /// (alongside any jobs of its own) with `runJobs`.
    pub fn prepare(self: *Tiles, shapes: *Shapes, tile: usize, jobs: *std.ArrayList(BlockJob)) !void {
        const a = self.allocator;
        const group = tile >> @intCast(self.group_log);
        if (self.group_log != 0 and self.loaded_group != group) {
            self.loaded_group = null;
            var prefolds = std.ArrayList(FoldJob).empty;
            defer prefolds.deinit(a);
            for (self.sources, self.block_logs, self.group_offsets) |source, block_log, group_offset| {
                if (group_offset == ungrouped) continue;
                const group_block_log = block_log + self.group_log;
                const shape = try shapes.get(source.coset_log, group_block_log, group, source.coefficients.len, false);
                try prefolds.append(a, .{
                    .coefficients = source.coefficients,
                    .weights = shape.weights,
                    .values = self.group_arena[group_offset..][0 .. @as(usize, 1) << @intCast(group_block_log)],
                });
            }
            runJobs(FoldJob, prefolds.items);
            self.loaded_group = group;
        }
        try jobs.ensureUnusedCapacity(a, self.sources.len);
        for (self.sources, self.block_logs, self.group_offsets, 0..) |source, block_log, group_offset, index| {
            const coefficients = if (group_offset == ungrouped)
                source.coefficients
            else
                self.group_arena[group_offset..][0 .. @as(usize, 1) << @intCast(block_log + self.group_log)];
            jobs.appendAssumeCapacity(try shapes.blockJob(coefficients, source.coset_log, tile, self.block(index)));
        }
    }

    /// `prepare` and run the jobs: every source's block of `tile`.
    pub fn load(self: *Tiles, tile: usize) !void {
        var shapes = Shapes.init(self.allocator);
        defer shapes.deinit();
        var jobs = std.ArrayList(BlockJob).empty;
        defer jobs.deinit(self.allocator);
        try self.prepare(&shapes, tile, &jobs);
        runJobs(BlockJob, jobs.items);
        for (jobs.items) |job| if (job.failure) |err| return err;
    }
};

test "coset blocks: folded sub-coset FFTs reproduce contiguous slices of the full evaluation" {
    const a = std.testing.allocator;
    for (2..9) |coefficient_log| {
        const coefficients = try a.alloc(M31, @as(usize, 1) << @intCast(coefficient_log));
        defer a.free(coefficients);
        for (coefficients, 0..) |*value, i| value.* = M31.fromU64(1_000_003 * i * i + 7919 * i + 17);
        const polynomial = try poly.CircleCoefficients.initBorrowed(coefficients);
        for (1..3) |extra| {
            const coset_log: u32 = @intCast(coefficient_log + extra);
            const full = try polynomial.evaluate(a, CanonicCoset.new(coset_log).circleDomain());
            defer a.free(full.values);
            for (1..coset_log + 1) |block_log| {
                const size = @as(usize, 1) << @intCast(block_log);
                const out = try a.alloc(M31, size);
                defer a.free(out);
                var shapes = Shapes.init(a);
                defer shapes.deinit();
                for (0..@as(usize, 1) << @intCast(coset_log - block_log)) |part| {
                    var job = try shapes.blockJob(coefficients, coset_log, part, out);
                    job.run();
                    try std.testing.expect(job.failure == null);
                    try std.testing.expectEqualSlices(M31, full.values[part * size ..][0..size], out);
                }
            }
        }
    }
}

test "coset blocks: grouped tiles reproduce every source's lifted blocks" {
    const a = std.testing.allocator;
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3 });
    defer pool.deinit();
    var binding = try work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();

    // Evaluation log 11: two full-height polynomials (2^10 coefficients) and
    // a lifted one (2^7 coefficients on coset 8).
    const logs = [_]u32{ 10, 10, 7 };
    var owned: [logs.len][]M31 = undefined;
    var sources: [logs.len]Source = undefined;
    var fulls: [logs.len][]const M31 = undefined;
    for (logs, &owned, &sources, &fulls, 0..) |log, *buffer, *source, *full, seed| {
        buffer.* = try a.alloc(M31, @as(usize, 1) << @intCast(log));
        for (buffer.*, 0..) |*value, i| value.* = M31.fromU64(seed * 99_991 + i * i * 7919 + i * 13 + 1);
        source.* = .{ .coefficients = buffer.*, .coset_log = log + 1 };
        const evaluation = try (try poly.CircleCoefficients.initBorrowed(buffer.*)).evaluate(a, CanonicCoset.new(log + 1).circleDomain());
        full.* = evaluation.values;
    }
    defer for (owned, fulls) |buffer, full| {
        a.free(buffer);
        a.free(full);
    };
    var tiles = try Tiles.init(a, &sources, 11, 6, 1 << 20);
    defer tiles.deinit();
    try std.testing.expect(tiles.group_log != 0);
    for (0..tiles.tileCount()) |tile| {
        try tiles.load(tile);
        for (fulls, 0..) |full, index| {
            const size = @as(usize, 1) << @intCast(tiles.block_logs[index]);
            try std.testing.expectEqualSlices(M31, full[tile * size ..][0..size], tiles.block(index));
        }
    }
}
