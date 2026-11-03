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

const RoundCtx = struct {
    factors: []const []QM31,
    terms: []const Term,
    half: usize,
    deg: u8,
    partial: [][MAX_DEG + 1]QM31,
    chunk: usize,
};

fn roundChunk(c: *const RoundCtx, s: usize, e: usize) void {
    var acc: [MAX_DEG + 1]QM31 = [_]QM31{QM31.zero()} ** (MAX_DEG + 1);
    var lo: [MAX_FACTORS]QM31 = undefined;
    var diff: [MAX_FACTORS]QM31 = undefined;
    var cur: [MAX_FACTORS]QM31 = undefined;
    for (s..e) |x| {
        for (c.factors, 0..) |fac, j| {
            lo[j] = fac[x];
            diff[j] = fac[x + c.half].sub(fac[x]);
        }
        // t = 0
        for (c.factors, 0..) |_, j| cur[j] = lo[j];
        var t: usize = 0;
        while (t <= c.deg) : (t += 1) {
            if (t != 1) {
                var v = QM31.zero();
                for (c.terms) |term| {
                    var p = term.coeff;
                    for (term.factors) |fi| p = p.mul(cur[fi]);
                    v = v.add(p);
                }
                acc[t] = acc[t].add(v);
            }
            for (c.factors, 0..) |_, j| cur[j] = cur[j].add(diff[j]);
        }
    }
    c.partial[s / c.chunk] = acc;
}

fn foldChunk(c: *const FoldCtx, s: usize, e: usize) void {
    for (c.factors) |fac| {
        for (s..e) |x| fac[x] = fac[x].add(c.r.mul(fac[x + c.half].sub(fac[x])));
    }
}

const FoldCtx = struct { factors: []const []QM31, half: usize, r: QM31 };

/// Prove. Factor vectors are consumed (folded in place).
pub fn prove(
    a: std.mem.Allocator,
    pool: *f.Pool,
    tr: *Transcript,
    claim: QM31,
    factors: []const []QM31,
    terms: []const Term,
) !ProveResult {
    std.debug.assert(factors.len > 0 and factors.len <= MAX_FACTORS);
    const len0 = factors[0].len;
    for (factors) |fac| std.debug.assert(fac.len == len0);
    const n = f.log2Exact(len0);
    const deg = termDegree(terms);
    const rounds = try a.alloc(RoundPoly, n);
    errdefer a.free(rounds);
    const point = try a.alloc(QM31, n);
    errdefer a.free(point);
    var cur_claim = claim;
    var len = len0;
    const max_chunks = pool.n_threads * 4 + 1;
    const partial = try a.alloc([MAX_DEG + 1]QM31, max_chunks + 1);
    defer a.free(partial);
    for (0..n) |round| {
        const half = len / 2;
        const target = pool.n_threads * 4;
        var chunk = (half + target - 1) / target;
        if (chunk < 1024) chunk = 1024;
        if (chunk > half) chunk = half;
        const n_chunks = (half + chunk - 1) / chunk;
        const ctx = RoundCtx{ .factors = factors, .terms = terms, .half = half, .deg = deg, .partial = partial, .chunk = chunk };
        if (n_chunks <= 1) {
            roundChunk(&ctx, 0, half);
        } else {
            var wg: std.Thread.WaitGroup = .{};
            var s: usize = 0;
            while (s < half) : (s += chunk) pool.pool.spawnWg(&wg, roundChunk, .{ &ctx, s, @min(half, s + chunk) });
            pool.pool.waitAndWork(&wg);
        }
        var sums: [MAX_DEG + 1]QM31 = [_]QM31{QM31.zero()} ** (MAX_DEG + 1);
        for (0..n_chunks) |ci| {
            for (0..deg + 1) |t| sums[t] = sums[t].add(partial[ci][t]);
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
        const fctx = FoldCtx{ .factors = factors, .half = half, .r = r };
        pool.parallelFor(half, 4096, &fctx, foldChunk);
        len = half;
    }
    const finals = try a.alloc(QM31, factors.len);
    for (factors, 0..) |fac, j| finals[j] = fac[0];
    return .{ .proof = .{ .rounds = rounds, .deg = deg }, .point = point, .finals = finals };
}

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
