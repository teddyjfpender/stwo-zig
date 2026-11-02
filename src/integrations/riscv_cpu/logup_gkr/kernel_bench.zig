//! rv64-logup-kernel-bench: reproducible CPU micro/meso benchmarks for the
//! LogUp interaction and LogUp-GKR prover kernels. Measurement only; nothing
//! here is a protocol or a receiver. Every input is a deterministic function
//! of (kernel, log, seed), and every run prints a SHA-256 of its outputs (proof
//! bytes, final channel digest, artifact claims, or committed columns) so a
//! kernel change can be checked byte-for-byte against the previous binary.
//!
//!   gkr <log> <singles|generic|mixed> <fast|reference> <threads> [reps]
//!   om31 <log> [reference|fast] [threads] [reps]  OM31 LogUpMultiplicities (services shape)
//!   logup <log> <n_sums> <threads> [reps]  frontend generateParallelColumns
//!   columns <log> <width> <threads> [reps] engine logup_columns.build
//!   inverse <log> <threads> [reps]         chunked QM31 batch inversion (4096)
//!   eq <log> [reps]                        eq-table generation
//!
//! Output: one JSON object per line (`stdout`), with min/median wall ns over
//! the repetitions and ns per element at the median.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const OM31 = core.fields.om31.OM31;
const P = @import("protocol.zig");
const F = @import("fast_gkr.zig");
const MP = @import("mle_point.zig");
const lookups = engine.lookups;
const work = engine.work_pool;
const logup = @import("stwo_riscv_frontend").air.logup;
const logup_columns = engine.air.logup_columns;

const Rng = std.Random.DefaultPrng;

fn randM31(r: std.Random) M31 {
    return M31.fromCanonical(r.intRangeLessThan(u32, 0, core.fields.m31.Modulus));
}

fn randQ(r: std.Random) QM31 {
    while (true) {
        const v = QM31.fromU32Unchecked(
            r.intRangeLessThan(u32, 0, core.fields.m31.Modulus),
            r.intRangeLessThan(u32, 0, core.fields.m31.Modulus),
            r.intRangeLessThan(u32, 0, core.fields.m31.Modulus),
            r.intRangeLessThan(u32, 0, core.fields.m31.Modulus),
        );
        if (!v.isZero()) return v;
    }
}

const Sample = struct {
    min: u64,
    median: u64,
    fn of(ns: []u64) Sample {
        std.mem.sort(u64, ns, {}, std.sort.asc(u64));
        return .{ .min = ns[0], .median = ns[ns.len / 2] };
    }
};

fn emit(a: std.mem.Allocator, value: anytype) !void {
    const json = try std.json.Stringify.valueAlloc(a, value, .{});
    defer a.free(json);
    var out = std.fs.File.stdout();
    try out.writeAll(json);
    try out.writeAll("\n");
}

fn hexDigest(h: *std.crypto.hash.sha2.Sha256) [64]u8 {
    var d: [32]u8 = undefined;
    h.final(&d);
    return std.fmt.bytesToHex(d, .lower);
}

fn parse(args: []const []const u8, i: usize, default: usize) !usize {
    if (args.len <= i) return default;
    return std.fmt.parseUnsigned(usize, args[i], 10);
}

pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len < 3) return error.ExpectedKernelAndLog;
    const kernel = args[1];
    const log: u32 = @intCast(try std.fmt.parseUnsigned(u32, args[2], 10));
    if (log < 2 or log > 26) return error.InvalidLog;
    if (std.mem.eql(u8, kernel, "gkr")) {
        if (args.len < 6) return error.ExpectedGkrKindImplThreads;
        return benchGkr(a, log, args[3], args[4], try parse(args, 5, 1), try parse(args, 6, 3));
    }
    if (std.mem.eql(u8, kernel, "om31")) {
        const impl = if (args.len > 3) args[3] else "reference";
        return benchOm31(a, log, impl, try parse(args, 4, 1), try parse(args, 5, 3));
    }
    if (std.mem.eql(u8, kernel, "logup")) return benchLogup(a, log, try parse(args, 3, 4), try parse(args, 4, 1), try parse(args, 5, 3));
    if (std.mem.eql(u8, kernel, "columns")) return benchColumns(a, log, try parse(args, 3, 4), try parse(args, 4, 1), try parse(args, 5, 3));
    if (std.mem.eql(u8, kernel, "inverse")) return benchInverse(a, log, try parse(args, 3, 1), try parse(args, 4, 5));
    if (std.mem.eql(u8, kernel, "eq")) return benchEq(a, log, try parse(args, 3, 5));
    return error.UnknownKernel;
}

// ---------------------------------------------------------------- GKR (QM31)

const GkrKind = enum { singles, generic, mixed };

/// Instances by kind: singles = one singles instance at `log`; generic = one
/// generic instance (sparse non-unit numerators) at `log`; mixed = singles at
/// `log`, a singles instance at `log-2` and a generic instance at `log`.
const Shape = struct { shift: u32, generic: bool };
const singles_shapes = [_]Shape{.{ .shift = 0, .generic = false }};
const generic_shapes = [_]Shape{.{ .shift = 0, .generic = true }};
const mixed_shapes = [_]Shape{ .{ .shift = 0, .generic = false }, .{ .shift = 2, .generic = false }, .{ .shift = 0, .generic = true } };
fn gkrShapes(kind: GkrKind) []const Shape {
    return switch (kind) {
        .singles => &singles_shapes,
        .generic => &generic_shapes,
        .mixed => &mixed_shapes,
    };
}

const GkrInstance = struct { num: ?[]QM31, den: []QM31 };

fn gkrInputs(a: std.mem.Allocator, kind: GkrKind, log: u32) ![]GkrInstance {
    const shapes = gkrShapes(kind);
    const out = try a.alloc(GkrInstance, shapes.len);
    var prng = Rng.init(0x474b52 ^ @as(u64, log));
    const r = prng.random();
    for (shapes, out) |shape, *inst| {
        const n = @as(usize, 1) << @intCast(log - shape.shift);
        const den = try a.alloc(QM31, n);
        for (den) |*d| d.* = randQ(r);
        inst.den = den;
        inst.num = null;
        if (shape.generic) {
            const num = try a.alloc(QM31, n);
            for (num, 0..) |*v, i| v.* = if (i % 7 == 0) QM31.fromBase(randM31(r)) else QM31.one();
            inst.num = num;
        }
    }
    return out;
}

fn benchGkr(a: std.mem.Allocator, log: u32, kind_text: []const u8, impl: []const u8, threads: usize, reps: usize) !void {
    const kind = std.meta.stringToEnum(GkrKind, kind_text) orelse return error.InvalidGkrKind;
    const fast = std.mem.eql(u8, impl, "fast");
    if (!fast and !std.mem.eql(u8, impl, "reference")) return error.InvalidGkrImpl;
    const base = try gkrInputs(a, kind, log);
    defer {
        for (base) |inst| {
            if (inst.num) |n| a.free(n);
            a.free(inst.den);
        }
        a.free(base);
    }
    var leaves: usize = 0;
    for (base) |inst| leaves += inst.den.len;
    const ns = try a.alloc(u64, reps);
    defer a.free(ns);
    var build_ns: u64 = 0;
    var sumcheck_ns: u64 = 0;
    var digest: [64]u8 = undefined;
    for (0..reps) |rep| {
        var channel = P.Channel{};
        channel.mixU32s(&.{ 0x42454e43, log });
        var timer = try std.time.Timer.start();
        var result = if (fast) blk: {
            var inputs: [4]F.Input = undefined;
            for (base, 0..) |inst, i| inputs[i] = .{
                .num = if (inst.num) |n| try a.dupe(QM31, n) else null,
                .den = try a.dupe(QM31, inst.den),
            };
            timer.reset();
            var stats = F.Stats{};
            const res = try F.proveBatch(a, &channel, inputs[0..base.len], .{ .threads = threads }, &stats);
            build_ns = stats.build_ns;
            sumcheck_ns = stats.sumcheck_ns;
            break :blk res;
        } else blk: {
            const Mle = lookups.mle.Mle(QM31);
            var layers: [4]lookups.gkr_prover.Layer = undefined;
            for (base, 0..) |inst, i| layers[i] = if (inst.num) |n|
                .{ .LogUpGeneric = .{ .numerators = try Mle.initOwned(try a.dupe(QM31, n)), .denominators = try Mle.initOwned(try a.dupe(QM31, inst.den)) } }
            else
                .{ .LogUpSingles = .{ .denominators = try Mle.initOwned(try a.dupe(QM31, inst.den)) } };
            defer for (layers[0..base.len]) |*l| l.deinit(a);
            timer.reset();
            break :blk try lookups.gkr_prover.proveBatch(a, &channel, layers[0..base.len]);
        };
        ns[rep] = timer.read();
        defer result.deinit(a);
        const bytes = try P.encodeGkr(a, &result.proof);
        defer a.free(bytes);
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update(bytes);
        h.update(&channel.digestBytes());
        h.update(std.mem.sliceAsBytes(result.artifact.ood_point));
        for (result.artifact.claims_to_verify_by_instance) |c| h.update(std.mem.sliceAsBytes(c));
        digest = hexDigest(&h);
    }
    const s = Sample.of(ns);
    try emit(a, .{ .kernel = "gkr", .kind = kind_text, .impl = impl, .log = log, .threads = threads, .reps = reps, .leaves = leaves, .min_ns = s.min, .median_ns = s.median, .ns_per_leaf = @as(f64, @floatFromInt(s.median)) / @as(f64, @floatFromInt(leaves)), .last_build_ns = build_ns, .last_sumcheck_ns = sumcheck_ns, .sha256 = digest });
}

// ------------------------------------------------------- GKR generic (OM31)

fn benchOm31(a: std.mem.Allocator, log: u32, impl: []const u8, threads: usize, reps: usize) !void {
    // `reference` is the production `gkr_prover.proveBatch` (PR #309 packed
    // numerical kernels); with threads > 1 it runs on a scoped work pool of
    // that many workers, which is how its row kernels parallelise.
    if (!std.mem.eql(u8, impl, "fast") and threads > 1) return withPool(threads, om31PoolBody, .{ a, log, impl, threads, reps });
    return benchOm31Run(a, log, impl, threads, reps);
}

fn om31PoolBody(_: *work.WorkPool, a: std.mem.Allocator, log: u32, impl: []const u8, threads: usize, reps: usize) !void {
    return benchOm31Run(a, log, impl, threads, reps);
}

fn benchOm31Run(a: std.mem.Allocator, log: u32, impl: []const u8, threads: usize, reps: usize) !void {
    const fast = std.mem.eql(u8, impl, "fast");
    if (!fast and !std.mem.eql(u8, impl, "reference")) return error.InvalidGkrImpl;
    const Fast = lookups.gkr_prover_fast.ForField(OM31);
    const GP = lookups.gkr_prover.ForField(OM31);
    const Channel = core.channel.raw_mod_m31.Om31Channel;
    const Mle = lookups.mle.MleFor;
    const n = @as(usize, 1) << @intCast(log);
    var prng = Rng.init(0x4f4d33 ^ @as(u64, log));
    const r = prng.random();
    const num = try a.alloc(M31, n);
    defer a.free(num);
    const den = try a.alloc(OM31, n);
    defer a.free(den);
    for (num, 0..) |*v, i| v.* = if (i % 5 == 0) randM31(r) else M31.one();
    for (den) |*d| d.* = .{ .c0 = randQ(r), .c1 = randQ(r) };
    const ns = try a.alloc(u64, reps);
    defer a.free(ns);
    var digest: [64]u8 = undefined;
    for (0..reps) |rep| {
        var layers = [_]GP.Layer{.{ .LogUpMultiplicities = .{ .numerators = try Mle(OM31, M31).initOwned(try a.dupe(M31, num)), .denominators = try Mle(OM31, OM31).initOwned(try a.dupe(OM31, den)) } }};
        defer for (&layers) |*l| l.deinit(a);
        var channel = Channel.init();
        channel.mixU32s(&.{ 0x42454e43, log });
        var timer = try std.time.Timer.start();
        // Fast inputs are borrowed, exactly as the services child passes them.
        var result = if (fast) try Fast.proveBatch(a, &channel, &.{.{ .num = .{ .base = num }, .den = den, .owned = false }}, .{ .threads = threads }, null) else try GP.proveBatch(a, &channel, &layers);
        ns[rep] = timer.read();
        defer result.deinit(a);
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update(&channel.digestBytes());
        h.update(std.mem.sliceAsBytes(result.artifact.ood_point));
        for (result.artifact.claims_to_verify_by_instance) |c| h.update(std.mem.sliceAsBytes(c));
        for (result.proof.sumcheck_proofs) |p| for (p.round_polys) |poly| h.update(std.mem.sliceAsBytes(poly.coeffsSlice()));
        digest = hexDigest(&h);
    }
    const s = Sample.of(ns);
    try emit(a, .{ .kernel = "om31", .impl = impl, .log = log, .threads = threads, .reps = reps, .leaves = n, .min_ns = s.min, .median_ns = s.median, .ns_per_leaf = @as(f64, @floatFromInt(s.median)) / @as(f64, @floatFromInt(n)), .sha256 = digest });
}

// ------------------------------------------------------ LogUp interaction

/// Synthetic RV64-shaped row: every relation of the row looks up a tuple of
/// `TUPLE` committed M31 values, `d = z - sum alpha^i v_i`, and the frontend
/// pairs two relations per cumulative sum (`n_sums` sums = 2*n_sums fractions,
/// the shape of a Word16 provider with paired inverse columns).
const TUPLE = 6;
const LogupContext = struct {
    values: []const M31,
    rows: usize,
    z: [16]QM31,
    alpha: [TUPLE]QM31,
    n_sums: usize,

    fn denominator(self: LogupContext, relation: usize, row: usize) QM31 {
        var d = self.z[relation % 16];
        const base = (relation * self.rows + row) * TUPLE;
        for (self.alpha, self.values[base..][0..TUPLE]) |alpha, v| d = d.sub(alpha.mulM31(v));
        return d;
    }
};

fn LogupRowContext(comptime n_sums: usize) type {
    return struct {
        inner: LogupContext,
        pub fn rowPairsAt(self: @This(), row: usize) [n_sums]logup.RowPair {
            var out: [n_sums]logup.RowPair = undefined;
            for (&out, 0..) |*pair, s| pair.* = .{
                .n1 = QM31.one(),
                .d1 = self.inner.denominator(2 * s, row),
                .n2 = QM31.one().neg(),
                .d2 = self.inner.denominator(2 * s + 1, row),
            };
            return out;
        }
    };
}

fn logupContext(a: std.mem.Allocator, log: u32, relations: usize) !LogupContext {
    const rows = @as(usize, 1) << @intCast(log);
    const values = try a.alloc(M31, relations * rows * TUPLE);
    var prng = Rng.init(0x4c4f47 ^ @as(u64, log));
    const r = prng.random();
    for (values) |*v| v.* = M31.fromCanonical(r.int(u16));
    var ctx = LogupContext{ .values = values, .rows = rows, .z = undefined, .alpha = undefined, .n_sums = relations / 2 };
    for (&ctx.z) |*z| z.* = randQ(r);
    for (&ctx.alpha) |*x| x.* = randQ(r);
    return ctx;
}

fn withPool(threads: usize, comptime body: anytype, args: anytype) !void {
    var pool: work.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = threads, .stack_size = 1024 * 1024 });
    defer pool.deinit();
    var binding = try work.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    try @call(.auto, body, .{&pool} ++ args);
}

fn benchLogup(a: std.mem.Allocator, log: u32, n_sums: usize, threads: usize, reps: usize) !void {
    const ctx = try logupContext(a, log, 2 * n_sums);
    defer a.free(ctx.values);
    try withPool(threads, logupBody, .{ a, ctx, log, n_sums, threads, reps });
}

fn logupBody(pool: *work.WorkPool, a: std.mem.Allocator, ctx: LogupContext, log: u32, n_sums: usize, threads: usize, reps: usize) !void {
    inline for (.{ 1, 2, 4, 8 }) |K| if (K == n_sums) return logupRun(K, pool, a, ctx, log, threads, reps);
    return error.UnsupportedSumCount;
}

fn logupRun(comptime K: usize, pool: *work.WorkPool, a: std.mem.Allocator, ctx: LogupContext, log: u32, threads: usize, reps: usize) !void {
    const ns = try a.alloc(u64, reps);
    defer a.free(ns);
    var digest: [64]u8 = undefined;
    for (0..reps) |rep| {
        var timer = try std.time.Timer.start();
        var out = try logup.generateParallelColumns(K, a, LogupRowContext(K){ .inner = ctx }, log, pool);
        ns[rep] = timer.read();
        defer out.deinit(a);
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        for (out.columns) |c| h.update(std.mem.sliceAsBytes(c));
        h.update(std.mem.sliceAsBytes(&out.claims));
        digest = hexDigest(&h);
    }
    const rows = @as(usize, 1) << @intCast(log);
    const s = Sample.of(ns);
    try emit(a, .{ .kernel = "logup", .log = log, .n_sums = K, .fractions_per_row = 2 * K, .threads = threads, .reps = reps, .min_ns = s.min, .median_ns = s.median, .ns_per_row = @as(f64, @floatFromInt(s.median)) / @as(f64, @floatFromInt(rows)), .ns_per_fraction = @as(f64, @floatFromInt(s.median)) / @as(f64, @floatFromInt(rows * 2 * K)), .sha256 = digest });
}

const ColumnsContext = struct {
    inner: LogupContext,
    fn fill(self: ColumnsContext, row: usize, out: []logup_columns.Fraction) anyerror!void {
        for (out, 0..) |*f, i| f.* = .{ .numerator = if (i % 2 == 0) QM31.one() else QM31.one().neg(), .denominator = self.inner.denominator(i, row) };
    }
};

fn benchColumns(a: std.mem.Allocator, log: u32, width: usize, threads: usize, reps: usize) !void {
    const ctx = try logupContext(a, log, width);
    defer a.free(ctx.values);
    try withPool(threads, columnsBody, .{ a, ctx, log, width, threads, reps });
}

fn columnsBody(_: *work.WorkPool, a: std.mem.Allocator, ctx: LogupContext, log: u32, width: usize, threads: usize, reps: usize) !void {
    const ns = try a.alloc(u64, reps);
    defer a.free(ns);
    var digest: [64]u8 = undefined;
    for (0..reps) |rep| {
        var timer = try std.time.Timer.start();
        const out = try logup_columns.build(a, log, width, ColumnsContext{ .inner = ctx }, ColumnsContext.fill);
        ns[rep] = timer.read();
        defer {
            for (out.columns) |c| a.free(c.values);
            a.free(out.columns);
        }
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        for (out.columns) |c| h.update(std.mem.sliceAsBytes(c.values));
        h.update(std.mem.asBytes(&out.claimed_sum));
        digest = hexDigest(&h);
    }
    const rows = @as(usize, 1) << @intCast(log);
    const s = Sample.of(ns);
    try emit(a, .{ .kernel = "columns", .log = log, .width = width, .threads = threads, .reps = reps, .min_ns = s.min, .median_ns = s.median, .ns_per_row = @as(f64, @floatFromInt(s.median)) / @as(f64, @floatFromInt(rows)), .ns_per_fraction = @as(f64, @floatFromInt(s.median)) / @as(f64, @floatFromInt(rows * width)), .sha256 = digest });
}

// ------------------------------------------------------- batch inversion

const InverseJob = struct {
    src: []const QM31,
    dst: []QM31,
    failure: ?anyerror = null,
    fn run(self: *InverseJob) void {
        core.fields.batchInverseChunked(QM31, self.src, self.dst, INVERSE_CHUNK) catch |err| {
            self.failure = err;
        };
    }
};
const INVERSE_CHUNK = 4096;

fn benchInverse(a: std.mem.Allocator, log: u32, threads: usize, reps: usize) !void {
    const n = @as(usize, 1) << @intCast(log);
    const src = try a.alloc(QM31, n);
    defer a.free(src);
    const dst = try a.alloc(QM31, n);
    defer a.free(dst);
    var prng = Rng.init(0x494e56 ^ @as(u64, log));
    for (src) |*v| v.* = randQ(prng.random());
    @memset(dst, QM31.zero());
    try withPool(threads, inverseBody, .{ a, src, dst, log, threads, reps });
}

fn inverseBody(pool: *work.WorkPool, a: std.mem.Allocator, src: []const QM31, dst: []QM31, log: u32, threads: usize, reps: usize) !void {
    const ns = try a.alloc(u64, reps);
    defer a.free(ns);
    var jobs: [work.MAX_WORKERS]InverseJob = undefined;
    const k = @min(threads, work.MAX_WORKERS);
    const n = src.len;
    for (0..reps) |rep| {
        var timer = try std.time.Timer.start();
        for (jobs[0..k], 0..) |*job, i| {
            const lo = std.mem.alignBackward(usize, n * i / k, INVERSE_CHUNK);
            const hi = if (i + 1 == k) n else std.mem.alignBackward(usize, n * (i + 1) / k, INVERSE_CHUNK);
            job.* = .{ .src = src[lo..hi], .dst = dst[lo..hi] };
        }
        var wg = std.Thread.WaitGroup{};
        for (jobs[1..k]) |*job| pool.spawnWg(&wg, InverseJob.run, .{job});
        jobs[0].run();
        wg.wait();
        ns[rep] = timer.read();
        for (jobs[0..k]) |job| if (job.failure) |err| return err;
    }
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(std.mem.sliceAsBytes(dst));
    const s = Sample.of(ns);
    try emit(a, .{ .kernel = "inverse", .log = log, .threads = threads, .reps = reps, .chunk = INVERSE_CHUNK, .min_ns = s.min, .median_ns = s.median, .ns_per_element = @as(f64, @floatFromInt(s.median)) / @as(f64, @floatFromInt(n)), .sha256 = hexDigest(&h) });
}

// ------------------------------------------------------------- eq table

fn benchEq(a: std.mem.Allocator, log: u32, reps: usize) !void {
    var prng = Rng.init(0x4551 ^ @as(u64, log));
    var point: [32]QM31 = undefined;
    for (point[0..log]) |*p| p.* = randQ(prng.random());
    const ns = try a.alloc(u64, reps);
    defer a.free(ns);
    var digest: [64]u8 = undefined;
    for (0..reps) |rep| {
        var timer = try std.time.Timer.start();
        const t = try MP.genEqEvals(a, point[0..log]);
        ns[rep] = timer.read();
        defer a.free(t);
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update(std.mem.sliceAsBytes(t));
        digest = hexDigest(&h);
    }
    const n = @as(usize, 1) << @intCast(log);
    const s = Sample.of(ns);
    try emit(a, .{ .kernel = "eq", .log = log, .threads = 1, .reps = reps, .min_ns = s.min, .median_ns = s.median, .ns_per_element = @as(f64, @floatFromInt(s.median)) / @as(f64, @floatFromInt(n)), .sha256 = digest });
}
