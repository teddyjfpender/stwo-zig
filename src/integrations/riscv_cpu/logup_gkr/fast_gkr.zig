//! Parallel, clone-free LogUp batch GKR prover for WGKR-LS-RANGE-v0.
//!
//! It emits exactly the transcript and proof of the reference
//! `lookups/gkr_prover.zig:proveBatch` for LogUp inputs (field arithmetic is
//! exact, so chunked summation order cannot change any transcript value); the
//! test below compares encoded proofs byte for byte. Differences from the
//! reference are engineering only:
//!   - layers are built once and folded IN PLACE during their own sumcheck
//!     (the reference clones each layer into the oracle and again in sumcheck);
//!   - singles keep an implicit all-ones numerator through every fold;
//!   - layer construction, round sums and folds are chunked over a thread pool;
//!   - each layer's storage is released right after its sumcheck.
//! Memory is still "materialise every layer" (design note section 8, v0):
//! sum_k 2^k * 32 B over generic layers plus the 16 B/leaf input layer.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const lookups = @import("stwo_prover_engine").lookups;
const gkr_prover = lookups.gkr_prover;
const gkr_verifier = lookups.gkr_verifier;
const gkr_circuit = @import("stwo_prover_engine").lookups.gkr_prover;
const sumcheck = lookups.sumcheck;
const lookup_utils = lookups.utils;
const MP = @import("mle_point.zig");

const Poly = lookup_utils.UnivariatePoly(QM31);

/// Owned input layer. `num == null` means LogUp singles (all numerators 1).
pub const Input = struct {
    num: ?[]QM31,
    den: []QM31,
    pub fn nVariables(self: Input) usize {
        return std.math.log2_int(usize, self.den.len);
    }
};

/// `num`/`den` are views that shrink as the layer is folded in place;
/// `num_buf`/`den_buf` keep the original allocations for `free`.
const Layer = struct {
    num: ?[]QM31,
    den: []QM31,
    num_buf: ?[]QM31,
    den_buf: []QM31,
    fn init(num: ?[]QM31, den: []QM31) Layer {
        return .{ .num = num, .den = den, .num_buf = num, .den_buf = den };
    }
    fn free(self: *Layer, a: std.mem.Allocator) void {
        if (self.num_buf) |n| a.free(n);
        a.free(self.den_buf);
        self.* = init(null, &.{});
    }
};

pub const Stats = struct {
    build_ns: u64 = 0,
    sumcheck_ns: u64 = 0,
    peak_layer_bytes: u64 = 0,
};

pub const Options = struct {
    /// Dedicated prototype pool, never borrowed from a production coordinator.
    /// The caller must include it in its own scheduling/resource admission.
    threads: usize = 1,
    /// Smallest loop that is split across the pool (tests lower it).
    min_parallel: usize = 1 << 13,
};

pub const MAX_THREADS: usize = 64;

const Ctx = struct {
    pool: *std.Thread.Pool,
    threads: usize,
    min_parallel: usize,

    fn chunks(self: Ctx, n: usize) usize {
        if (n < self.min_parallel or self.threads == 1) return 1;
        return @max(1, @min(self.threads * 4, n / @max(1, self.min_parallel / 4)));
    }

    /// Splits `n` coarse units over at most `n` tasks (no grain threshold).
    fn runExact(self: Ctx, n: usize, comptime func: anytype, args: anytype) void {
        if (n <= 1 or self.threads == 1) {
            @call(.auto, func, args ++ .{ 0, n, 0 });
            return;
        }
        var wg = std.Thread.WaitGroup{};
        for (0..n) |c| self.pool.spawnWg(&wg, func, args ++ .{ c, c + 1, c });
        self.pool.waitAndWork(&wg);
    }

    fn run(self: Ctx, n: usize, comptime func: anytype, args: anytype) void {
        const k = self.chunks(n);
        if (k <= 1) {
            @call(.auto, func, args ++ .{ 0, n, 0 });
            return;
        }
        var wg = std.Thread.WaitGroup{};
        for (0..k) |c| {
            const start = n * c / k;
            const end = n * (c + 1) / k;
            self.pool.spawnWg(&wg, func, args ++ .{ start, end, c });
        }
        self.pool.waitAndWork(&wg);
    }
};

// Packed kernels: four consecutive terms per AdvSIMD operation (AoS loads are
// transposed into coordinate vectors). Field arithmetic is exact and every
// lane computes the same scalar formula, so values are bit-identical to the
// scalar loops, which still handle unaligned heads and tails.
const PE = core.fields.packed_extensions;
const PQ = PE.PackedQM31x4;
const padd = PE.addPackedQM31x4;
const psub = PE.subPackedQM31x4;
const pmul = PE.mulPackedQM31x4;
const pload = PE.loadPackedQM31x4;
const pstore = PE.storePackedQM31x4;
const LANES = 4;

fn nextLayerScalar(src: *const Layer, dst: *Layer, i: usize) void {
    const d0 = src.den[2 * i];
    const d1 = src.den[2 * i + 1];
    if (src.num) |n| {
        dst.num.?[i] = n[2 * i].mul(d1).add(d0.mul(n[2 * i + 1]));
    } else {
        dst.num.?[i] = d0.add(d1);
    }
    dst.den[i] = d0.mul(d1);
}

fn nextLayerChunk(src: *const Layer, dst: *Layer, start: usize, end: usize, _: usize) void {
    var i = start;
    while (i < end and i % LANES != 0) : (i += 1) nextLayerScalar(src, dst, i);
    const out_num = dst.num.?.ptr;
    const out_den = dst.den.ptr;
    while (i + LANES <= end) : (i += LANES) {
        const d = PE.loadEvenOddPackedQM31x4(src.den.ptr + 2 * i);
        if (src.num) |n| {
            const x = PE.loadEvenOddPackedQM31x4(n.ptr + 2 * i);
            pstore(out_num + i, padd(pmul(x[0], d[1]), pmul(d[0], x[1])));
        } else {
            pstore(out_num + i, padd(d[0], d[1]));
        }
        pstore(out_den + i, pmul(d[0], d[1]));
    }
    while (i < end) : (i += 1) nextLayerScalar(src, dst, i);
}

fn sumScalar(layer: *const Layer, eq: []const QM31, n_terms: usize, lambda: QM31, i: usize, e0: *QM31, e2: *QM31) void {
    const den = layer.den;
    const d00 = den[2 * i];
    const d01 = den[2 * i + 1];
    const d10 = den[2 * (n_terms + i)];
    const d11 = den[2 * (n_terms + i) + 1];
    const d20 = d10.add(d10).sub(d00);
    const d21 = d11.add(d11).sub(d01);
    var n0: QM31 = undefined;
    var n2: QM31 = undefined;
    if (layer.num) |num| {
        const n00 = num[2 * i];
        const n01 = num[2 * i + 1];
        const n10 = num[2 * (n_terms + i)];
        const n11 = num[2 * (n_terms + i) + 1];
        const n20 = n10.add(n10).sub(n00);
        const n21 = n11.add(n11).sub(n01);
        n0 = n00.mul(d01).add(d00.mul(n01));
        n2 = n20.mul(d21).add(d20.mul(n21));
    } else {
        n0 = d00.add(d01);
        n2 = d20.add(d21);
    }
    const w = eq[i];
    e0.* = e0.add(w.mul(n0.add(lambda.mul(d00.mul(d01)))));
    e2.* = e2.add(w.mul(n2.add(lambda.mul(d20.mul(d21)))));
}

fn sumChunk(layer: *const Layer, eq: []const QM31, n_terms: usize, lambda: QM31, partial: [][2]QM31, start: usize, end: usize, chunk: usize) void {
    @setEvalBranchQuota(20_000);
    var e0 = QM31.zero();
    var e2 = QM31.zero();
    var i = start;
    while (i < end and i % LANES != 0) : (i += 1) sumScalar(layer, eq, n_terms, lambda, i, &e0, &e2);
    if (i + LANES <= end) {
        const den = layer.den.ptr;
        const plambda = PE.splatPackedQM31x4(lambda);
        var p0 = PE.zeroPackedQM31x4();
        var p2 = PE.zeroPackedQM31x4();
        while (i + LANES <= end) : (i += LANES) {
            const lo = PE.loadEvenOddPackedQM31x4(den + 2 * i);
            const hi = PE.loadEvenOddPackedQM31x4(den + 2 * (n_terms + i));
            const d20 = psub(padd(hi[0], hi[0]), lo[0]);
            const d21 = psub(padd(hi[1], hi[1]), lo[1]);
            var n0: PQ = undefined;
            var n2: PQ = undefined;
            if (layer.num) |num| {
                const nlo = PE.loadEvenOddPackedQM31x4(num.ptr + 2 * i);
                const nhi = PE.loadEvenOddPackedQM31x4(num.ptr + 2 * (n_terms + i));
                const n20 = psub(padd(nhi[0], nhi[0]), nlo[0]);
                const n21 = psub(padd(nhi[1], nhi[1]), nlo[1]);
                n0 = padd(pmul(nlo[0], lo[1]), pmul(lo[0], nlo[1]));
                n2 = padd(pmul(n20, d21), pmul(d20, n21));
            } else {
                n0 = padd(lo[0], lo[1]);
                n2 = padd(d20, d21);
            }
            const w = pload(eq.ptr + i);
            p0 = padd(p0, pmul(w, padd(n0, pmul(plambda, pmul(lo[0], lo[1])))));
            p2 = padd(p2, pmul(w, padd(n2, pmul(plambda, pmul(d20, d21)))));
        }
        e0 = e0.add(PE.sumLanesPackedQM31x4(p0));
        e2 = e2.add(PE.sumLanesPackedQM31x4(p2));
    }
    while (i < end) : (i += 1) sumScalar(layer, eq, n_terms, lambda, i, &e0, &e2);
    partial[chunk] = .{ e0, e2 };
}

/// Inverse of `evenOdd`: lanes `(e0, o0, e1, o1)` and `(e2, o2, e3, o3)`.
inline fn interleave(even: PQ, odd: PQ) [2]PQ {
    const lo = @Vector(4, i32){ 0, -1, 1, -2 };
    const hi = @Vector(4, i32){ 2, -3, 3, -4 };
    return .{
        .{ .c0a = @shuffle(u32, even.c0a, odd.c0a, lo), .c0b = @shuffle(u32, even.c0b, odd.c0b, lo), .c1a = @shuffle(u32, even.c1a, odd.c1a, lo), .c1b = @shuffle(u32, even.c1b, odd.c1b, lo) },
        .{ .c0a = @shuffle(u32, even.c0a, odd.c0a, hi), .c0b = @shuffle(u32, even.c0b, odd.c0b, hi), .c1a = @shuffle(u32, even.c1a, odd.c1a, hi), .c1b = @shuffle(u32, even.c1b, odd.c1b, hi) },
    };
}

inline fn evenOdd(lo: PQ, hi: PQ) [2]PQ {
    const even = @Vector(4, i32){ 0, 2, -1, -3 };
    const odd = @Vector(4, i32){ 1, 3, -2, -4 };
    return .{
        .{ .c0a = @shuffle(u32, lo.c0a, hi.c0a, even), .c0b = @shuffle(u32, lo.c0b, hi.c0b, even), .c1a = @shuffle(u32, lo.c1a, hi.c1a, even), .c1b = @shuffle(u32, lo.c1b, hi.c1b, even) },
        .{ .c0a = @shuffle(u32, lo.c0a, hi.c0a, odd), .c0b = @shuffle(u32, lo.c0b, hi.c0b, odd), .c1a = @shuffle(u32, lo.c1a, hi.c1a, odd), .c1b = @shuffle(u32, lo.c1b, hi.c1b, odd) },
    };
}

/// Folds `v[j..j+8]` in place by `r` (`v[j] += r * (v[j + half] - v[j])`)
/// and returns the folded values split into even and odd positions.
inline fn foldEight(v: [*]QM31, half: usize, pr: PQ, j: usize) [2]PQ {
    const x0 = pload(v + j);
    const x1 = pload(v + j + 4);
    const f0 = padd(pmul(pr, psub(pload(v + j + half), x0)), x0);
    const f1 = padd(pmul(pr, psub(pload(v + j + 4 + half), x1)), x1);
    pstore(v + j, f0);
    pstore(v + j + 4, f1);
    return evenOdd(f0, f1);
}

inline fn foldOne(v: []QM31, half: usize, r: QM31, j: usize) void {
    v[j] = r.mul(v[j + half].sub(v[j])).add(v[j]);
}

/// One pass that folds a layer by `r` (exactly `foldChunk` on den and num)
/// and accumulates the NEXT round's sums over the folded layer (exactly
/// `sumChunk` with `n_terms = half / 4`). Term `i` owns folded positions
/// `2i, 2i+1, 2(n+i), 2(n+i)+1`, so the term ranges partition `[0, half)`
/// and every position is folded once, before it is read, by its owner.
fn foldSumChunk(layer: *const Layer, half: usize, r: QM31, eq: []const QM31, lambda: QM31, partial: [][2]QM31, start: usize, end: usize, chunk: usize) void {
    @setEvalBranchQuota(20_000);
    const n_terms = half / 4;
    const folded = Layer{ .num = if (layer.num) |n| n[0..half] else null, .den = layer.den[0..half], .num_buf = null, .den_buf = &.{} };
    var e0 = QM31.zero();
    var e2 = QM31.zero();
    var i = start;
    const scalar = struct {
        fn term(l: *const Layer, f: *const Layer, h: usize, rr: QM31, w: []const QM31, nt: usize, lam: QM31, t: usize, a0: *QM31, a2: *QM31) void {
            for ([_]usize{ 2 * t, 2 * t + 1, 2 * (nt + t), 2 * (nt + t) + 1 }) |j| {
                foldOne(l.den, h, rr, j);
                if (l.num) |n| foldOne(n, h, rr, j);
            }
            sumScalar(f, w, nt, lam, t, a0, a2);
        }
    }.term;
    while (i < end and i % LANES != 0) : (i += 1) scalar(layer, &folded, half, r, eq, n_terms, lambda, i, &e0, &e2);
    if (i + LANES <= end) {
        const den = layer.den.ptr;
        const pr = PE.splatPackedQM31x4(r);
        const plambda = PE.splatPackedQM31x4(lambda);
        var p0 = PE.zeroPackedQM31x4();
        var p2 = PE.zeroPackedQM31x4();
        while (i + LANES <= end) : (i += LANES) {
            const lo = foldEight(den, half, pr, 2 * i);
            const hi = foldEight(den, half, pr, 2 * (n_terms + i));
            const d20 = psub(padd(hi[0], hi[0]), lo[0]);
            const d21 = psub(padd(hi[1], hi[1]), lo[1]);
            var n0: PQ = undefined;
            var n2: PQ = undefined;
            if (layer.num) |num| {
                const nlo = foldEight(num.ptr, half, pr, 2 * i);
                const nhi = foldEight(num.ptr, half, pr, 2 * (n_terms + i));
                const n20 = psub(padd(nhi[0], nhi[0]), nlo[0]);
                const n21 = psub(padd(nhi[1], nhi[1]), nlo[1]);
                n0 = padd(pmul(nlo[0], lo[1]), pmul(lo[0], nlo[1]));
                n2 = padd(pmul(n20, d21), pmul(d20, n21));
            } else {
                n0 = padd(lo[0], lo[1]);
                n2 = padd(d20, d21);
            }
            const w = pload(eq.ptr + i);
            p0 = padd(p0, pmul(w, padd(n0, pmul(plambda, pmul(lo[0], lo[1])))));
            p2 = padd(p2, pmul(w, padd(n2, pmul(plambda, pmul(d20, d21)))));
        }
        e0 = e0.add(PE.sumLanesPackedQM31x4(p0));
        e2 = e2.add(PE.sumLanesPackedQM31x4(p2));
    }
    while (i < end) : (i += 1) scalar(layer, &folded, half, r, eq, n_terms, lambda, i, &e0, &e2);
    partial[chunk] = .{ e0, e2 };
}

fn foldChunk(values: []QM31, half: usize, r: QM31, start: usize, end: usize, _: usize) void {
    var i = start;
    while (i < end and i % LANES != 0) : (i += 1) values[i] = r.mul(values[i + half].sub(values[i])).add(values[i]);
    const pr = PE.splatPackedQM31x4(r);
    const v = values.ptr;
    while (i + LANES <= end) : (i += LANES) {
        const x = pload(v + i);
        pstore(v + i, padd(pmul(pr, psub(pload(v + i + half), x)), x));
    }
    while (i < end) : (i += 1) values[i] = r.mul(values[i + half].sub(values[i])).add(values[i]);
}

/// `eq((y0, x), y)` table, scaled by `1 - y[0]`, in the bit order of
/// `mle_point.genEqEvals(y[1..])` (y[1] is the most significant index bit).
/// Chunks of the table expand independently from their prefix products.
fn eqTable(a: std.mem.Allocator, ctx: Ctx, y: []const QM31) ![]QM31 {
    if (y.len == 0) return a.dupe(QM31, &.{QM31.one()});
    const r = y[1..];
    const n = @as(usize, 1) << @intCast(r.len);
    const out = try a.alloc(QM31, n);
    const k = ctx.chunks(n);
    const top: usize = if (k <= 1) 0 else @min(r.len, std.math.log2_int_ceil(usize, k));
    ctx.runExact(@as(usize, 1) << @intCast(top), eqChunk, .{ out, r, top, QM31.one().sub(y[0]) });
    return out;
}

fn eqChunk(out: []QM31, r: []const QM31, top: usize, scale: QM31, start: usize, end: usize, _: usize) void {
    @setEvalBranchQuota(20_000);
    const block = @as(usize, 1) << @intCast(r.len - top);
    for (start..end) |c| {
        // Prefix product of the top `top` coordinates (MSB first).
        var prefix = scale;
        for (0..top) |j| {
            const bit = (c >> @intCast(top - 1 - j)) & 1;
            prefix = prefix.mul(if (bit == 1) r[j] else QM31.one().sub(r[j]));
        }
        const dst = out[c * block ..][0..block];
        dst[0] = prefix;
        var len: usize = 1;
        for (r[top..]) |ri| {
            const one_minus = QM31.one().sub(ri);
            if (len >= LANES) {
                // In-place doubling, four entries at a time from the top: block
                // `i` writes `[2i, 2i + 8)`, which is above every unread entry.
                const pri = PE.splatPackedQM31x4(ri);
                const pom = PE.splatPackedQM31x4(one_minus);
                var i = len;
                while (i > 0) {
                    i -= LANES;
                    const x = pload(dst.ptr + i);
                    const hi = interleave(pmul(x, pom), pmul(x, pri));
                    pstore(dst.ptr + 2 * i, hi[0]);
                    pstore(dst.ptr + 2 * i + LANES, hi[1]);
                }
            } else {
                var i = len;
                while (i > 0) {
                    i -= 1;
                    const v = dst[i];
                    dst[2 * i + 1] = v.mul(ri);
                    dst[2 * i] = v.mul(one_minus);
                }
            }
            len *= 2;
        }
    }
}

fn reduce(partial: []const [2]QM31) [2]QM31 {
    var f0 = QM31.zero();
    var f2 = QM31.zero();
    for (partial) |p| {
        f0 = f0.add(p[0]);
        f2 = f2.add(p[1]);
    }
    return .{ f0, f2 };
}

fn eqOne(x: QM31, y: QM31) QM31 {
    return x.mul(y).add(QM31.one().sub(x).mul(QM31.one().sub(y)));
}

fn pow2(n: usize) M31 {
    return M31.fromU64(@as(u64, 1) << @intCast(n));
}

/// Consumes `inputs` (frees their buffers). Returns the same result type as
/// the reference prover.
pub fn proveBatch(a: std.mem.Allocator, channel: anytype, inputs: []Input, options: Options, stats: ?*Stats) !gkr_prover.ProveBatchResult {
    // Inputs are consumed on every exit, including validation/pool-init OOM.
    var adopted: usize = 0;
    defer for (inputs[adopted..]) |input| {
        if (input.num) |num| a.free(num);
        a.free(input.den);
    };
    if (options.threads == 0 or options.threads > MAX_THREADS) return error.InvalidGkrThreads;
    const threads = options.threads;
    var timer = try std.time.Timer.start();
    const n_inst = inputs.len;
    if (n_inst == 0 or n_inst > 4) return error.InvalidBatch;
    for (inputs) |input| {
        if (input.den.len < 2 or !std.math.isPowerOfTwo(input.den.len)) return error.InvalidInputShape;
        if (input.num) |num| if (num.len != input.den.len) return error.InvalidInputShape;
    }
    var pool: std.Thread.Pool = undefined;
    try pool.init(.{ .allocator = a, .n_jobs = threads });
    defer pool.deinit();
    const ctx = Ctx{ .pool = &pool, .threads = threads, .min_parallel = options.min_parallel };

    // layers[i][k] has k variables; layers[i][n_vars] is the input.
    var layers: [4][]Layer = undefined;
    var n_vars: [4]usize = undefined;
    var built: usize = 0;
    defer for (layers[0..built]) |ls| {
        for (ls) |*l| l.free(a);
        a.free(ls);
    };
    var n_layers: usize = 0;
    var layer_bytes: u64 = 0;
    for (inputs, 0..) |input, i| {
        n_vars[i] = input.nVariables();
        n_layers = @max(n_layers, n_vars[i]);
        layers[i] = try a.alloc(Layer, n_vars[i] + 1);
        for (layers[i]) |*l| l.* = Layer.init(null, &.{});
        built += 1;
        layers[i][n_vars[i]] = Layer.init(input.num, input.den);
        adopted = i + 1;
        layer_bytes += input.den.len * @sizeOf(QM31) * @as(u64, if (input.num != null) 2 else 1);
        var k = n_vars[i];
        while (k > 0) : (k -= 1) {
            const size = @as(usize, 1) << @intCast(k - 1);
            const num = try a.alloc(QM31, size);
            const den = a.alloc(QM31, size) catch |err| {
                a.free(num);
                return err;
            };
            layers[i][k - 1] = Layer.init(num, den);
            layer_bytes += 2 * size * @sizeOf(QM31);
            ctx.run(size, nextLayerChunk, .{ &layers[i][k], &layers[i][k - 1] });
        }
    }
    if (stats) |s| {
        s.build_ns = timer.read();
        s.peak_layer_bytes = layer_bytes;
    }

    var output_claims: [4][2]QM31 = undefined;
    var claims: [4]?[2]QM31 = .{ null, null, null, null };
    var masks: [4]std.ArrayList(gkr_verifier.GkrMask) = .{ .empty, .empty, .empty, .empty };
    defer for (&masks) |*m| {
        for (m.items) |*x| x.deinit(a);
        m.deinit(a);
    };
    var sumcheck_proofs = std.ArrayList(sumcheck.SumcheckProof).empty;
    defer {
        for (sumcheck_proofs.items) |*p| p.deinit(a);
        sumcheck_proofs.deinit(a);
    }
    var ood = std.ArrayList(QM31).empty;
    defer ood.deinit(a);
    const partial = try a.alloc([2]QM31, ctx.threads * 4 + 1);
    defer a.free(partial);

    for (0..n_layers) |layer_idx| {
        const n_remaining = n_layers - layer_idx;
        for (0..n_inst) |i| if (n_vars[i] == n_remaining) {
            const top = &layers[i][0];
            const out = [2]QM31{ if (top.num) |n| n[0] else QM31.one(), top.den[0] };
            output_claims[i] = out;
            claims[i] = out;
        };
        for (claims[0..n_inst]) |c| if (c) |v| channel.mixFelts(&v);
        const eq = try eqTable(a, ctx, ood.items);
        defer a.free(eq);
        const alpha = channel.drawSecureFelt();
        const lambda = channel.drawSecureFelt();

        // Active instances, their layer (local vars m), sumcheck claims.
        var active: [4]usize = undefined;
        var n_active: usize = 0;
        var sc_claim: [4]QM31 = undefined;
        var nv: [4]usize = undefined; // remaining sumcheck variables per active instance
        var correction: [4]QM31 = undefined;
        for (0..n_inst) |i| if (claims[i]) |c| {
            const local = layer_idx - (n_layers - n_vars[i]);
            active[n_active] = i;
            nv[n_active] = local; // oracle nVariables = (local + 1) - 1
            sc_claim[n_active] = lookup_utils.randomLinearCombination(&c, lambda);
            correction[n_active] = QM31.one();
            n_active += 1;
        };
        const n_sc_vars = layer_idx;
        for (0..n_active) |s| sc_claim[s] = sc_claim[s].mulM31(pow2(n_sc_vars - nv[s]));
        var round_polys = std.ArrayList(Poly).empty;
        errdefer {
            for (round_polys.items) |*p| p.deinit(a);
            round_polys.deinit(a);
        }
        var assignment = std.ArrayList(QM31).empty;
        defer assignment.deinit(a);
        // Next-round sums already accumulated by the fused fold (per active s).
        var pending: [4]?[2]QM31 = .{ null, null, null, null };
        for (0..n_sc_vars) |round| {
            const n_remaining_rounds = n_sc_vars - round;
            var polys: [4]Poly = undefined;
            var made: usize = 0;
            defer for (polys[0..made]) |*p| p.deinit(a);
            for (0..n_active) |s| {
                if (nv[s] == n_remaining_rounds) {
                    const layer = &layers[active[s]][layer_idx - (n_layers - n_vars[active[s]]) + 1];
                    const n_terms = @as(usize, 1) << @intCast(nv[s] - 1);
                    const sums = pending[s] orelse blk: {
                        ctx.run(n_terms, sumChunk, .{ layer, @as([]const QM31, eq), n_terms, lambda, partial });
                        break :blk reduce(partial[0..ctx.chunks(n_terms)]);
                    };
                    pending[s] = null;
                    const f0 = sums[0];
                    const f2 = sums[1];
                    polys[s] = try gkr_circuit.correctSumAsPolyInFirstVariable(a, f0.mul(correction[s]), f2.mul(correction[s]), sc_claim[s], ood.items, nv[s]);
                } else {
                    const half = try sc_claim[s].divM31(M31.fromCanonical(2));
                    polys[s] = Poly.initOwned(try a.dupe(QM31, &.{half}));
                }
                made += 1;
            }
            // Random linear combination with alpha (Horner from the last poly).
            var acc = Poly.initOwned(try a.alloc(QM31, 0));
            var s_idx = n_active;
            while (s_idx > 0) {
                s_idx -= 1;
                var scaled = try acc.mulScalar(a, alpha);
                acc.deinit(a);
                acc = try scaled.add(a, polys[s_idx]);
                scaled.deinit(a);
            }
            channel.mixFelts(acc.coeffsSlice());
            const r = channel.drawSecureFelt();
            try round_polys.append(a, acc);
            try assignment.append(a, r);
            for (0..n_active) |s| {
                sc_claim[s] = polys[s].evalAtPoint(r);
                if (nv[s] != n_remaining_rounds) continue;
                const layer = &layers[active[s]][layer_idx - (n_layers - n_vars[active[s]]) + 1];
                const z0 = ood.items[ood.items.len - nv[s]];
                correction[s] = correction[s].mul(eqOne(r, z0));
                const half = layer.den.len / 2;
                if (nv[s] >= 2) {
                    // The folded layer has a next round: fold and sum in one pass.
                    const next_terms = half / 4;
                    ctx.run(next_terms, foldSumChunk, .{ layer, half, r, @as([]const QM31, eq), lambda, partial });
                    pending[s] = reduce(partial[0..ctx.chunks(next_terms)]);
                } else {
                    ctx.run(half, foldChunk, .{ layer.den, half, r });
                    if (layer.num) |n| ctx.run(half, foldChunk, .{ n, half, r });
                }
                layer.den = layer.den[0..half];
                if (layer.num) |n| layer.num = n[0..half];
                nv[s] -= 1;
            }
        }
        try sumcheck_proofs.append(a, .{ .round_polys = try round_polys.toOwnedSlice(a) });

        var flat: [4][4]QM31 = undefined;
        for (0..n_active) |s| {
            const i = active[s];
            const layer = &layers[i][layer_idx - (n_layers - n_vars[i]) + 1];
            if (layer.den.len != 2) return error.InvalidLayerStructure;
            const nums = if (layer.num) |n| [2]QM31{ n[0], n[1] } else [2]QM31{ QM31.one(), QM31.one() };
            flat[s] = .{ nums[0], nums[1], layer.den[0], layer.den[1] };
            try masks[i].append(a, gkr_verifier.GkrMask.initOwned(try a.dupe([2]QM31, &.{ nums, .{ layer.den[0], layer.den[1] } })));
            channel.mixFelts(&flat[s]);
        }
        const challenge = channel.drawSecureFelt();
        ood.clearRetainingCapacity();
        try ood.appendSlice(a, assignment.items);
        try ood.append(a, challenge);
        for (0..n_active) |s| {
            const i = active[s];
            const f = flat[s];
            claims[i] = .{ lookup_utils.foldMleEvals(QM31, challenge, f[0], f[1]), lookup_utils.foldMleEvals(QM31, challenge, f[2], f[3]) };
            layers[i][layer_idx - (n_layers - n_vars[i]) + 1].free(a);
        }
    }
    if (stats) |s| s.sumcheck_ns = timer.read() - s.build_ns;

    // Assemble owned results.
    var proof = gkr_verifier.GkrBatchProof{
        .sumcheck_proofs = try sumcheck_proofs.toOwnedSlice(a),
        .layer_masks_by_instance = try a.alloc([]gkr_verifier.GkrMask, n_inst),
        .output_claims_by_instance = try a.alloc([]QM31, n_inst),
    };
    for (0..n_inst) |i| {
        proof.layer_masks_by_instance[i] = try masks[i].toOwnedSlice(a);
        proof.output_claims_by_instance[i] = try a.dupe(QM31, &output_claims[i]);
    }
    const artifact_claims = try a.alloc([]QM31, n_inst);
    for (0..n_inst) |i| artifact_claims[i] = try a.dupe(QM31, &(claims[i].?));
    const artifact = gkr_verifier.GkrArtifact{
        .ood_point = try a.dupe(QM31, ood.items),
        .claims_to_verify_by_instance = artifact_claims,
        .n_variables_by_instance = try a.dupe(usize, n_vars[0..n_inst]),
    };
    return .{ .proof = proof, .artifact = artifact };
}

/// Test-only access to the parallel eq table (reference: `mle_point.genEqEvals`).
pub const testing = if (@import("builtin").is_test) struct {
    pub fn eqTableWith(a: std.mem.Allocator, threads: usize, min_parallel: usize, y: []const QM31) ![]QM31 {
        var pool: std.Thread.Pool = undefined;
        try pool.init(.{ .allocator = a, .n_jobs = threads });
        defer pool.deinit();
        return eqTable(a, .{ .pool = &pool, .threads = threads, .min_parallel = min_parallel }, y);
    }
} else struct {};
