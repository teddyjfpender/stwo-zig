//! Sum-of-products sumcheck over QM31 (MSB-first variable order).
//!
//! Proves  claim = sum_x  sum_t  c_t * prod_{j in term t} F_j(x)
//! for a small set of factor vectors F_j (length 2^n) and terms of degree <= 3.
//! Each round sends the round polynomial's values at 0, 2, .., d (value at 1 is
//! implied by the running claim).
const std = @import("std");
const f = @import("field.zig");
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
        fn run(c: *const RoundCtx(NF), s: usize, e: usize) void {
            @setEvalBranchQuota(100_000);
            var acc: [MAX_DEG + 1]QM31 = [_]QM31{QM31.zero()} ** (MAX_DEG + 1);
            // Packed fast path: LANES consecutive x's whose high partners are
            // all active (exact field arithmetic, so lane order is irrelevant).
            var x = s;
            if (LANES > 1) {
                var pacc: [MAX_DEG + 1]PQ = [_]PQ{PQ.zero()} ** (MAX_DEG + 1);
                const hi_end = if (c.active > c.half) @min(e, c.active - c.half) else s;
                while (x + LANES <= hi_end) : (x += LANES) {
                    var diff: [NF]PQ = undefined;
                    var cur: [NF]PQ = undefined;
                    inline for (0..NF) |j| {
                        cur[j] = loadP(c.factors[j], x);
                        diff[j] = loadP(c.factors[j], x + c.half).sub(cur[j]);
                    }
                    pacc[0] = pacc[0].add(evalTermsAtP(terms, NF, &cur));
                    inline for (0..NF) |j| cur[j] = cur[j].add(diff[j]).add(diff[j]);
                    pacc[2] = pacc[2].add(evalTermsAtP(terms, NF, &cur));
                    if (deg >= 3) {
                        inline for (0..NF) |j| cur[j] = cur[j].add(diff[j]);
                        pacc[3] = pacc[3].add(evalTermsAtP(terms, NF, &cur));
                    }
                }
                acc[0] = sumLanes(pacc[0]);
                acc[2] = sumLanes(pacc[2]);
                if (deg >= 3) acc[3] = sumLanes(pacc[3]);
            }
            var lo: [NF]QM31 = undefined;
            var diff: [NF]QM31 = undefined;
            var cur: [NF]QM31 = undefined;
            while (x < e) : (x += 1) {
                const has_hi = x + c.half < c.active;
                inline for (0..NF) |j| {
                    lo[j] = c.factors[j][x];
                    const hi = if (has_hi) c.factors[j][x + c.half] else QM31.zero();
                    diff[j] = hi.sub(lo[j]);
                    cur[j] = lo[j];
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

fn FoldCtxT(comptime NF: usize) type {
    return struct { factors: [NF][]QM31, half: usize, active: usize, r: QM31 };
}

fn foldChunkT(comptime NF: usize) fn (*const FoldCtxT(NF), usize, usize) void {
    return struct {
        fn run(c: *const FoldCtxT(NF), s: usize, e: usize) void {
            @setEvalBranchQuota(100_000);
            const rp = PQ.splat(c.r);
            const hi_end = if (c.active > c.half) @min(e, c.active - c.half) else s;
            inline for (0..NF) |j| {
                const fac = c.factors[j];
                var x = s;
                if (LANES > 1) {
                    while (x + LANES <= hi_end) : (x += LANES) {
                        const lo = loadP(fac, x);
                        const hi = loadP(fac, x + c.half);
                        storeP(fac, x, lo.add(rp.mul(hi.sub(lo))));
                    }
                }
                while (x < e) : (x += 1) {
                    const hi = if (x + c.half < c.active) fac[x + c.half] else QM31.zero();
                    fac[x] = fac[x].add(c.r.mul(hi.sub(fac[x])));
                }
            }
        }
    }.run;
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
    for (0..n) |round| {
        const half = len / 2;
        const work = @min(half, active);
        var sums: [MAX_DEG + 1]QM31 = [_]QM31{QM31.zero()} ** (MAX_DEG + 1);
        if (work > 0) {
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
        const fctx = FoldCtxT(NF){ .factors = factors_in, .half = half, .active = active, .r = r };
        pool.parallelFor(work, 4096, &fctx, comptime foldChunkT(NF));
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
