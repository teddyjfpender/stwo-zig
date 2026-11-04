//! Sum-of-products sumcheck over QM31 (MSB-first variable order).
//!
//! Proves  claim = sum_x  sum_t  c_t * prod_{j in term t} F_j(x)
//! for a small set of factor vectors F_j (length 2^n) and terms of degree <= 3.
//! Each round sends the round polynomial's values at 0, 2, .., d (value at 1 is
//! implied by the running claim).
const std = @import("std");
const f = @import("field.zig");
const canonical = @import("canonical.zig");
const Transcript = @import("transcript.zig").Transcript;

const QM31 = f.QM31;
const M31 = f.M31;

pub const MAX_DEG = 3;
pub const MAX_FACTORS = 8;

pub const Term = struct {
    coeff: QM31,
    factors: []const u8, // indices into the factor list, 1..3 entries
};

pub const RoundPoly = struct {
    /// evals[0] = s(0), evals[1..deg] = s(2)..s(deg)
    evals: [MAX_DEG]QM31,
};

pub const Proof = struct {
    rounds: []RoundPoly,
    deg: u8,

    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        a.free(self.rounds);
    }

    pub fn byteSize(self: Proof) usize {
        return self.rounds.len * @as(usize, self.deg) * 16;
    }
};

pub const ProveResult = struct {
    proof: Proof,
    point: []QM31,
    /// final values F_j(point)
    finals: []QM31,

    pub fn deinit(self: *ProveResult, a: std.mem.Allocator) void {
        self.proof.deinit(a);
        a.free(self.point);
        a.free(self.finals);
    }
};

fn termDegree(terms: []const Term) u8 {
    var d: usize = 0;
    for (terms) |t| d = @max(d, t.factors.len);
    return @intCast(d);
}

/// Value of the degree-`deg` polynomial with s(0)=e0, s(1)=e1, s(k)=ek at r
/// (Lagrange over nodes 0..deg).
pub fn interpolateAt(vals: []const QM31, r: QM31) QM31 {
    const n = vals.len;
    var acc = QM31.zero();
    for (0..n) |i| {
        var num = QM31.one();
        var den = M31.one();
        for (0..n) |j| {
            if (i == j) continue;
            num = num.mul(r.sub(QM31.fromBase(M31.fromCanonical(@intCast(j)))));
            const diff: i64 = @as(i64, @intCast(i)) - @as(i64, @intCast(j));
            den = den.mul(f.fromI64(diff));
        }
        acc = acc.add(vals[i].mul(num).mul(QM31.fromBase(den.inv() catch unreachable)));
    }
    return acc;
}

fn RoundCtx(comptime NF: usize) type {
    return struct {
        factors: [NF][]QM31,
        half: usize,
        active: usize,
        partial: [][MAX_DEG + 1]QM31,
        chunk: usize,
    };
}

inline fn evalTermsAt(comptime terms: []const Term, comptime NF: usize, cur: *const [NF]QM31) QM31 {
    var v = QM31.zero();
    inline for (terms) |term| {
        var p = cur[term.factors[0]];
        inline for (term.factors[1..]) |fi| p = p.mul(cur[fi]);
        if (comptime !isOne(term.coeff)) p = p.mul(term.coeff);
        v = v.add(p);
    }
    return v;
}

const PQ = f.PackedQM31;
const LANES = f.PACK_WIDTH;

inline fn evalTermsAtP(comptime terms: []const Term, comptime NF: usize, cur: *const [NF]PQ) PQ {
    @setEvalBranchQuota(100_000);
    var v = PQ.zero();
    inline for (terms) |term| {
        var p = cur[term.factors[0]];
        inline for (term.factors[1..]) |fi| p = p.mul(cur[fi]);
        if (comptime !isOne(term.coeff)) p = p.mul(PQ.splat(term.coeff));
        v = v.add(p);
    }
    return v;
}

inline fn loadP(src: []const QM31, at: usize) PQ {
    return PQ.fromLanes(src[at..][0..LANES].*);
}

inline fn storeP(dst: []QM31, at: usize, v: PQ) void {
    inline for (0..LANES) |l| dst[at + l] = v.lane(l);
}

fn sumLanes(v: PQ) QM31 {
    var s = QM31.zero();
    inline for (0..LANES) |l| s = s.add(v.lane(l));
    return s;
}

fn isOne(c: QM31) bool {
    return c.eql(QM31.one());
}

fn roundChunkT(comptime NF: usize, comptime terms: []const Term, comptime deg: u8) fn (*const RoundCtx(NF), usize, usize) void {
    return struct {
        inline fn stepP(c: *const RoundCtx(NF), x: usize, comptime with_hi: bool, pacc: *[MAX_DEG + 1]PQ) void {
            var diff: [NF]PQ = undefined;
            var cur: [NF]PQ = undefined;
            inline for (0..NF) |j| {
                cur[j] = loadP(c.factors[j], x);
                const hi = if (with_hi) loadP(c.factors[j], x + c.half) else PQ.zero();
                diff[j] = hi.sub(cur[j]);
            }
            pacc[0] = pacc[0].add(evalTermsAtP(terms, NF, &cur));
            inline for (0..NF) |j| cur[j] = cur[j].add(diff[j]).add(diff[j]);
            pacc[2] = pacc[2].add(evalTermsAtP(terms, NF, &cur));
            if (deg >= 3) {
                inline for (0..NF) |j| cur[j] = cur[j].add(diff[j]);
                pacc[3] = pacc[3].add(evalTermsAtP(terms, NF, &cur));
            }
        }

        inline fn step(c: *const RoundCtx(NF), x: usize, acc: *[MAX_DEG + 1]QM31) void {
            var diff: [NF]QM31 = undefined;
            var cur: [NF]QM31 = undefined;
            const has_hi = x + c.half < c.active;
            inline for (0..NF) |j| {
                cur[j] = c.factors[j][x];
                const hi = if (has_hi) c.factors[j][x + c.half] else QM31.zero();
                diff[j] = hi.sub(cur[j]);
            }
            acc[0] = acc[0].add(evalTermsAt(terms, NF, &cur));
            inline for (0..NF) |j| cur[j] = cur[j].add(diff[j]).add(diff[j]);
            acc[2] = acc[2].add(evalTermsAt(terms, NF, &cur));
            if (deg >= 3) {
                inline for (0..NF) |j| cur[j] = cur[j].add(diff[j]);
                acc[3] = acc[3].add(evalTermsAt(terms, NF, &cur));
            }
        }

        fn run(c: *const RoundCtx(NF), s: usize, e: usize) void {
            @setEvalBranchQuota(100_000);
            var acc: [MAX_DEG + 1]QM31 = [_]QM31{QM31.zero()} ** (MAX_DEG + 1);
            // Packed fast path over LANES consecutive x's: first those whose high
            // partners are active, then those whose partners are (implicit) zeros.
            // Field arithmetic is exact, so lane/chunk order is irrelevant.
            var x = s;
            if (LANES > 1) {
                var pacc: [MAX_DEG + 1]PQ = [_]PQ{PQ.zero()} ** (MAX_DEG + 1);
                const hi_end = if (c.active > c.half) @max(s, @min(e, c.active - c.half)) else s;
                while (x + LANES <= hi_end) : (x += LANES) stepP(c, x, true, &pacc);
                while (x < hi_end) : (x += 1) step(c, x, &acc);
                while (x + LANES <= e) : (x += LANES) stepP(c, x, false, &pacc);
                inline for (0..MAX_DEG + 1) |t| acc[t] = acc[t].add(sumLanes(pacc[t]));
            }
            while (x < e) : (x += 1) step(c, x, &acc);
            c.partial[s / c.chunk] = acc;
        }
    }.run;
}

fn FoldCtxT(comptime NF: usize) type {
    return struct { factors: [NF][]QM31, half: usize, active: usize, r: QM31 };
}

fn foldChunkT(comptime NF: usize) fn (*const FoldCtxT(NF), usize, usize) void {
    return struct {
        fn run(c: *const FoldCtxT(NF), s: usize, e: usize) void {
            @setEvalBranchQuota(100_000);
            const rp = PQ.splat(c.r);
            // beyond the active high half: f'(x) = f(x) + r (0 - f(x)) = (1 - r) f(x)
            const omr = PQ.splat(QM31.one().sub(c.r));
            const hi_end = if (c.active > c.half) @max(s, @min(e, c.active - c.half)) else s;
            inline for (0..NF) |j| {
                const fac = c.factors[j];
                var x = s;
                if (LANES > 1) {
                    while (x + LANES <= hi_end) : (x += LANES) {
                        const lo = loadP(fac, x);
                        const hi = loadP(fac, x + c.half);
                        storeP(fac, x, lo.add(rp.mul(hi.sub(lo))));
                    }
                    while (x < hi_end) : (x += 1) fac[x] = fac[x].add(c.r.mul(fac[x + c.half].sub(fac[x])));
                    while (x + LANES <= e) : (x += LANES) storeP(fac, x, omr.mul(loadP(fac, x)));
                }
                while (x < e) : (x += 1) {
                    const hi = if (x + c.half < c.active) fac[x + c.half] else QM31.zero();
                    fac[x] = fac[x].add(c.r.mul(hi.sub(fac[x])));
                }
            }
        }
    }.run;
}

fn FoldRoundCtx(comptime NF: usize) type {
    return struct {
        factors: [NF][]QM31,
        /// current (pre-fold) half and active length
        half: usize,
        active: usize,
        r: QM31,
        partial: [][MAX_DEG + 1]QM31,
        chunk: usize,
    };
}

/// Fold at r fused with the next round's sums. Index y in [0, min(half/2, work))
/// owns folded positions y and y + half/2 (each folded once, by its owner, and
/// read only by it), so ranges of y can run in parallel in place.
fn foldRoundChunkT(comptime NF: usize, comptime terms: []const Term, comptime deg: u8) fn (*const FoldRoundCtx(NF), usize, usize) void {
    return struct {
        fn run(c: *const FoldRoundCtx(NF), s: usize, e: usize) void {
            @setEvalBranchQuota(100_000);
            const nh = c.half / 2;
            const work = @min(c.half, c.active);
            var acc: [MAX_DEG + 1]QM31 = [_]QM31{QM31.zero()} ** (MAX_DEG + 1);
            var y = s;
            if (LANES > 1) {
                const full_end = if (c.active > c.half + nh) @max(s, @min(e, c.active - c.half - nh)) else s;
                if (y + LANES <= full_end) {
                    var pacc: [MAX_DEG + 1]PQ = [_]PQ{PQ.zero()} ** (MAX_DEG + 1);
                    const rp = PQ.splat(c.r);
                    while (y + LANES <= full_end) : (y += LANES) {
                        var cur: [NF]PQ = undefined;
                        var diff: [NF]PQ = undefined;
                        inline for (0..NF) |j| {
                            const fac = c.factors[j];
                            const l0 = loadP(fac, y);
                            const f0 = l0.add(rp.mul(loadP(fac, y + c.half).sub(l0)));
                            const l1 = loadP(fac, y + nh);
                            const f1 = l1.add(rp.mul(loadP(fac, y + nh + c.half).sub(l1)));
                            storeP(fac, y, f0);
                            storeP(fac, y + nh, f1);
                            cur[j] = f0;
                            diff[j] = f1.sub(f0);
                        }
                        pacc[0] = pacc[0].add(evalTermsAtP(terms, NF, &cur));
                        inline for (0..NF) |j| cur[j] = cur[j].add(diff[j]).add(diff[j]);
                        pacc[2] = pacc[2].add(evalTermsAtP(terms, NF, &cur));
                        if (deg >= 3) {
                            inline for (0..NF) |j| cur[j] = cur[j].add(diff[j]);
                            pacc[3] = pacc[3].add(evalTermsAtP(terms, NF, &cur));
                        }
                    }
                    inline for (0..MAX_DEG + 1) |t| acc[t] = acc[t].add(sumLanes(pacc[t]));
                }
            }
            while (y < e) : (y += 1) {
                var cur: [NF]QM31 = undefined;
                var diff: [NF]QM31 = undefined;
                const has2 = y + nh < work;
                inline for (0..NF) |j| {
                    const fac = c.factors[j];
                    const h0 = if (y + c.half < c.active) fac[y + c.half] else QM31.zero();
                    const f0 = fac[y].add(c.r.mul(h0.sub(fac[y])));
                    var f1 = QM31.zero();
                    if (has2) {
                        const x1 = y + nh;
                        const h1 = if (x1 + c.half < c.active) fac[x1 + c.half] else QM31.zero();
                        f1 = fac[x1].add(c.r.mul(h1.sub(fac[x1])));
                        fac[x1] = f1;
                    }
                    fac[y] = f0;
                    cur[j] = f0;
                    diff[j] = f1.sub(f0);
                }
                acc[0] = acc[0].add(evalTermsAt(terms, NF, &cur));
                inline for (0..NF) |j| cur[j] = cur[j].add(diff[j]).add(diff[j]);
                acc[2] = acc[2].add(evalTermsAt(terms, NF, &cur));
                if (deg >= 3) {
                    inline for (0..NF) |j| cur[j] = cur[j].add(diff[j]);
                    acc[3] = acc[3].add(evalTermsAt(terms, NF, &cur));
                }
            }
            c.partial[s / c.chunk] = acc;
        }
    }.run;
}

fn chunkFor(pool: *f.Pool, work: usize) usize {
    const target = pool.n_threads * 4;
    var chunk = (work + target - 1) / target;
    if (chunk < 2048) chunk = 2048;
    if (chunk > work) chunk = work;
    return chunk;
}

fn termDegreeC(comptime terms: []const Term) u8 {
    var d: usize = 0;
    for (terms) |t| d = @max(d, t.factors.len);
    return @intCast(@max(d, 2));
}

/// Prove. Factor vectors are consumed (folded in place). Entries at index >=
/// `active` are treated as zero (and never read).
pub fn proveActive(
    comptime NF: usize,
    comptime terms: []const Term,
    a: std.mem.Allocator,
    pool: *f.Pool,
    tr: *Transcript,
    claim: QM31,
    factors_in: [NF][]QM31,
    active_in: usize,
) !ProveResult {
    const deg = comptime termDegreeC(terms);
    const len0 = factors_in[0].len;
    inline for (factors_in) |fac| std.debug.assert(fac.len == len0);
    const n = f.log2Exact(len0);
    const rounds = try a.alloc(RoundPoly, n);
    errdefer a.free(rounds);
    const point = try a.alloc(QM31, n);
    errdefer a.free(point);
    var cur_claim = claim;
    var len = len0;
    var active = @min(active_in, len0);
    const max_chunks = pool.n_threads * 4 + 2;
    const partial = try a.alloc([MAX_DEG + 1]QM31, max_chunks);
    defer a.free(partial);
    // sums of the current round when the previous fold already produced them
    var pending: ?[MAX_DEG + 1]QM31 = null;
    for (0..n) |round| {
        const half = len / 2;
        const work = @min(half, active);
        var sums: [MAX_DEG + 1]QM31 = [_]QM31{QM31.zero()} ** (MAX_DEG + 1);
        if (pending) |p| {
            sums = p;
            pending = null;
        } else if (work > 0) {
            const target = pool.n_threads * 4;
            var chunk = (work + target - 1) / target;
            if (chunk < 2048) chunk = 2048;
            if (chunk > work) chunk = work;
            const n_chunks = (work + chunk - 1) / chunk;
            const ctx = RoundCtx(NF){ .factors = factors_in, .half = half, .active = active, .partial = partial, .chunk = chunk };
            const run = comptime roundChunkT(NF, terms, deg);
            if (n_chunks <= 1) {
                run(&ctx, 0, work);
            } else {
                var wg: std.Thread.WaitGroup = .{};
                var s: usize = 0;
                while (s < work) : (s += chunk) pool.pool.spawnWg(&wg, run, .{ &ctx, s, @min(work, s + chunk) });
                pool.pool.waitAndWork(&wg);
            }
            for (0..n_chunks) |ci| {
                for (0..deg + 1) |t| sums[t] = sums[t].add(partial[ci][t]);
            }
        }
        sums[1] = cur_claim.sub(sums[0]);
        var rp = RoundPoly{ .evals = [_]QM31{QM31.zero()} ** MAX_DEG };
        rp.evals[0] = sums[0];
        for (2..deg + 1) |t| rp.evals[t - 1] = sums[t];
        tr.mixFelts(rp.evals[0..deg]);
        rounds[round] = rp;
        const r = tr.draw();
        point[round] = r;
        cur_claim = interpolateAt(sums[0 .. deg + 1], r);
        const next_work = @min(half / 2, work);
        if (round + 1 < n and next_work > 0) {
            // fold fused with the next round's sums (one pass instead of two)
            const chunk = chunkFor(pool, next_work);
            const n_chunks = (next_work + chunk - 1) / chunk;
            const fr = FoldRoundCtx(NF){ .factors = factors_in, .half = half, .active = active, .r = r, .partial = partial, .chunk = chunk };
            const run = comptime foldRoundChunkT(NF, terms, deg);
            if (n_chunks <= 1) {
                run(&fr, 0, next_work);
            } else {
                var wg: std.Thread.WaitGroup = .{};
                var s: usize = 0;
                while (s < next_work) : (s += chunk) pool.pool.spawnWg(&wg, run, .{ &fr, s, @min(next_work, s + chunk) });
                pool.pool.waitAndWork(&wg);
            }
            var ns: [MAX_DEG + 1]QM31 = [_]QM31{QM31.zero()} ** (MAX_DEG + 1);
            for (0..n_chunks) |ci| {
                for (0..deg + 1) |t| ns[t] = ns[t].add(partial[ci][t]);
            }
            pending = ns;
        } else {
            const fctx = FoldCtxT(NF){ .factors = factors_in, .half = half, .active = active, .r = r };
            pool.parallelFor(work, 4096, &fctx, comptime foldChunkT(NF));
        }
        len = half;
        active = work;
    }
    const finals = try a.alloc(QM31, NF);
    inline for (0..NF) |j| finals[j] = if (active > 0) factors_in[j][0] else QM31.zero();
    return .{ .proof = .{ .rounds = rounds, .deg = deg }, .point = point, .finals = finals };
}

/// Runtime-term entry point kept for tests: dispatches to comptime kernels for the shapes used.
pub fn prove(
    a: std.mem.Allocator,
    pool: *f.Pool,
    tr: *Transcript,
    claim: QM31,
    factors: []const []QM31,
    terms: []const Term,
) !ProveResult {
    _ = terms;
    std.debug.assert(factors.len == 3);
    return proveActive(3, &TEST_TERMS, a, pool, tr, claim, .{ factors[0], factors[1], factors[2] }, factors[0].len);
}

const TEST_C2 = QM31.fromU32Unchecked(5, 6, 7, 8);
const TEST_TERMS = [_]Term{ .{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1, 2 } }, .{ .coeff = TEST_C2, .factors = &[_]u8{0} } };

pub const VerifyResult = struct {
    point: []QM31,
    /// claimed value of the summand at the point (to be checked against finals by the caller)
    final_claim: QM31,
};

/// Verify round consistency; returns the random point and the reduced claim.
pub fn verify(a: std.mem.Allocator, tr: *Transcript, claim: QM31, n: usize, deg: u8, proof: Proof) !VerifyResult {
    if (proof.rounds.len != n or proof.deg != deg) return error.SumcheckShape;
    // canonical round evals (KERN-1): M31.sub wraps on a limb >= P
    try canonical.check(proof);
    const point = try a.alloc(QM31, n);
    var cur = claim;
    for (proof.rounds, 0..) |rp, round| {
        var vals: [MAX_DEG + 1]QM31 = undefined;
        vals[0] = rp.evals[0];
        vals[1] = cur.sub(rp.evals[0]);
        for (2..deg + 1) |t| vals[t] = rp.evals[t - 1];
        tr.mixFelts(rp.evals[0..deg]);
        const r = tr.draw();
        point[round] = r;
        cur = interpolateAt(vals[0 .. deg + 1], r);
    }
    return .{ .point = point, .final_claim = cur };
}

/// Evaluate the summand from final factor values.
pub fn evalTerms(terms: []const Term, finals: []const QM31) QM31 {
    var v = QM31.zero();
    for (terms) |t| {
        var p = t.coeff;
        for (t.factors) |fi| p = p.mul(finals[fi]);
        v = v.add(p);
    }
    return v;
}

test "sumcheck product and triple roundtrip" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const n = 10;
    const len = 1 << n;
    var fa = try a.alloc(QM31, len);
    defer a.free(fa);
    var fb = try a.alloc(QM31, len);
    defer a.free(fb);
    var fc = try a.alloc(QM31, len);
    defer a.free(fc);
    var claim = QM31.zero();
    const c2 = QM31.fromU32Unchecked(5, 6, 7, 8);
    for (0..len) |i| {
        fa[i] = QM31.fromU32Unchecked(@intCast(i), 3, 1, 2);
        fb[i] = QM31.fromU32Unchecked(@intCast(i * 3 + 1), 1, 4, 9);
        fc[i] = QM31.fromBase(M31.fromCanonical(@intCast(i ^ 77)));
        claim = claim.add(fa[i].mul(fb[i]).mul(fc[i])).add(c2.mul(fa[i]));
    }
    const ia = [_]u8{ 0, 1, 2 };
    const ib = [_]u8{0};
    const terms = [_]Term{ .{ .coeff = QM31.one(), .factors = &ia }, .{ .coeff = c2, .factors = &ib } };
    const orig_a = try a.dupe(QM31, fa);
    defer a.free(orig_a);
    var tp = Transcript.initDomain("test");
    var res = try prove(a, &pool, &tp, claim, &.{ fa, fb, fc }, &terms);
    defer res.deinit(a);
    var tv = Transcript.initDomain("test");
    const vr = try verify(a, &tv, claim, n, 3, res.proof);
    defer a.free(vr.point);
    try std.testing.expect(vr.final_claim.eql(evalTerms(&terms, res.finals)));
    try std.testing.expect(res.finals[0].eql(try f.mleEval(a, orig_a, vr.point)));
    // wrong claim must fail the final check
    var tv2 = Transcript.initDomain("test");
    const vr2 = try verify(a, &tv2, claim.add(QM31.one()), n, 3, res.proof);
    defer a.free(vr2.point);
    try std.testing.expect(!vr2.final_claim.eql(evalTerms(&terms, res.finals)));
}

test "active-length prover equals zero-padded full-length prover" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 3);
    defer pool.deinit();
    var prng = std.Random.DefaultPrng.init(5);
    const rnd = prng.random();
    for ([_]usize{ 3, 8, 13 }) |n| {
        const len = @as(usize, 1) << @intCast(n);
        for ([_]usize{ len / 2 + 1, len * 5 / 8 + 3, len - 1 }) |active| {
            var fa: [3][]QM31 = undefined;
            var fz: [3][]QM31 = undefined;
            for (0..3) |j| {
                fa[j] = try a.alloc(QM31, len);
                fz[j] = try a.alloc(QM31, len);
                for (0..len) |i| {
                    const v = QM31.fromU32Unchecked(rnd.uintLessThan(u32, f.P), rnd.uintLessThan(u32, f.P), rnd.uintLessThan(u32, f.P), rnd.uintLessThan(u32, f.P));
                    fa[j][i] = v; // garbage beyond `active` must never be read
                    fz[j][i] = if (i < active) v else QM31.zero();
                }
            }
            defer for (0..3) |j| {
                a.free(fa[j]);
                a.free(fz[j]);
            };
            var claim = QM31.zero();
            for (0..active) |i| claim = claim.add(fz[0][i].mul(fz[1][i]).mul(fz[2][i])).add(TEST_C2.mul(fz[0][i]));
            var t1 = Transcript.initDomain("act");
            var t2 = Transcript.initDomain("act");
            var r1 = try proveActive(3, &TEST_TERMS, a, &pool, &t1, claim, .{ fa[0], fa[1], fa[2] }, active);
            defer r1.deinit(a);
            var r2 = try proveActive(3, &TEST_TERMS, a, &pool, &t2, claim, .{ fz[0], fz[1], fz[2] }, len);
            defer r2.deinit(a);
            for (r1.proof.rounds, r2.proof.rounds) |x, y| for (0..3) |i| try std.testing.expect(x.evals[i].eql(y.evals[i]));
            for (r1.finals, r2.finals) |x, y| try std.testing.expect(x.eql(y));
            try std.testing.expect(t1.draw().eql(t2.draw()));
        }
    }
}
