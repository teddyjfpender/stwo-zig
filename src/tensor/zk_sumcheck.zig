//! Zero-knowledge ("masked") sumcheck.
//!
//! Proves  sum_{x in {0,1}^n} G(x) = c  for G = sum_t coeff_t prod_j F_j(x)
//! (comptime terms, degree d <= 3) without revealing anything beyond c and
//! masked ("hat") final values:
//!
//!  1. Hiding polynomial (the universal hiding polynomial of FlashProve's
//!     blocks/iop/hp.h, after Libra/[CFW26]):
//!       U(X_0..X_{n-1}, Y) = sum_l w_l(X_l) prod_{j>l} psi_j(X_j)
//!     with psi_j(X) = X for the n plain variables (phi(g) = g(0)+g(1)) and
//!     psi_Y = 1 for one extra variable Y summed by phi_Y(g) = g(0). Each w_l
//!     has degree <= d with uniform coefficients (constant term fixed to 0
//!     except for the last variable). The coefficients live in the committed
//!     witness table. The prover sends sigma = sum U, the verifier draws eps,
//!     and the sumcheck is run on U + eps * G'. The map from U's coefficients
//!     to (sigma, round polynomials) is a bijection onto the accepting tuples,
//!     so the messages are uniform given the claim.
//!  2. Hat round. G'(x, Y) evaluates each non-public factor at
//!       F^_j(x, Y) = (1 - Y) F_j(x) + Y p_j
//!     where, at the end, p_j is the value of a committed pad tensor at a point
//!     derived from x. Since phi_Y only looks at Y = 0 the claimed sum is
//!     unchanged; after the extra round at challenge gamma_Y the revealed final
//!     values are F^_j = (1 - gamma_Y) F_j(r) + gamma_Y p_j, masked by the pad.
//!     The caller turns each F^_j into a linear claim on the committed tables.
//!
//! The verifier checks q(r_last) = U(r, gamma_Y) + eps * G(F^), with U(r,
//! gamma_Y) (`u_val`) and sigma proved by linear claims on the U coefficients
//! (`sumForm`, `evalForm`).
const std = @import("std");
const f = @import("field.zig");
const sc = @import("sumcheck.zig");
const Transcript = @import("transcript.zig").Transcript;

const QM31 = f.QM31;
const M31 = f.M31;
pub const Term = sc.Term;
pub const MAX_DEG = 3;

fn smallQ(v: u32) QM31 {
    return QM31.fromBase(M31.fromCanonical(v));
}

// ---------------------------------------------------------------------------
// Hiding polynomial.

pub const Hp = struct {
    n: usize,
    d: usize,
    /// entries(n, d) coefficients: for l < n, t = 1..d at l*d + t - 1;
    /// for the Y variable (l = n), t = 0..d at n*d + t.
    c: []const QM31,

    pub fn entries(n: usize, d: usize) usize {
        return (n + 1) * d + 1;
    }

    fn idx(n: usize, d: usize, l: usize, t: usize) ?usize {
        if (l < n) return if (t == 0) null else l * d + t - 1;
        return n * d + t;
    }

    pub fn w(self: Hp, l: usize, t: usize) QM31 {
        return if (idx(self.n, self.d, l, t)) |i| self.c[i] else QM31.zero();
    }

    pub fn wEval(self: Hp, l: usize, x: QM31) QM31 {
        var acc = QM31.zero();
        var t: usize = self.d + 1;
        while (t > 0) {
            t -= 1;
            acc = acc.mul(x).add(self.w(l, t));
        }
        return acc;
    }

    /// phi_l(w_l): plain = w(0) + w(1), Y = w(0).
    fn phiW(self: Hp, l: usize) QM31 {
        if (l == self.n) return self.w(l, 0);
        return self.wEval(l, QM31.zero()).add(self.wEval(l, QM31.one()));
    }

    /// after[i] = sum_{l>i} phi_l(w_l) prod_{i<j<l} phi_j(1); index n is 0.
    fn afters(self: Hp, out: []QM31) void {
        out[self.n] = QM31.zero();
        var i: usize = self.n;
        while (i > 0) {
            i -= 1;
            const phi1: QM31 = if (i + 1 == self.n) QM31.one() else smallQ(2);
            out[i] = self.phiW(i + 1).add(phi1.mul(out[i + 1]));
        }
    }

    pub fn sum(self: Hp) QM31 {
        var buf: [64]QM31 = undefined;
        std.debug.assert(self.n < 64);
        self.afters(buf[0 .. self.n + 1]);
        if (self.n == 0) return self.phiW(0);
        return self.phiW(0).add(smallQ(2).mul(buf[0]));
    }

    /// Linear form of sum(): out[e] such that sum = sum_e out[e] c[e].
    pub fn sumForm(n: usize, d: usize, out: []QM31) void {
        @memset(out, QM31.zero());
        var scale = QM31.one(); // prod_{j<l} phi_j(1) = 2^l
        for (0..n + 1) |l| {
            for (0..d + 1) |t| {
                const i = idx(n, d, l, t) orelse continue;
                const moment: QM31 = if (l == n) (if (t == 0) QM31.one() else QM31.zero()) else (if (t == 0) smallQ(2) else QM31.one());
                out[i] = moment.mul(scale);
            }
            scale = scale.mul(smallQ(2));
        }
    }

    /// Linear form of U(gamma) (gamma has n+1 coordinates, the last is Y).
    pub fn evalForm(n: usize, d: usize, gamma: []const QM31, out: []QM31) void {
        std.debug.assert(gamma.len == n + 1);
        @memset(out, QM31.zero());
        var tail = QM31.one(); // prod_{j>l} psi_j(gamma_j); psi_Y = 1
        var l: usize = n + 1;
        while (l > 0) {
            l -= 1;
            var pw = QM31.one();
            for (0..d + 1) |t| {
                if (idx(n, d, l, t)) |i| out[i] = pw.mul(tail);
                pw = pw.mul(gamma[l]);
            }
            if (l < n) tail = tail.mul(gamma[l]);
        }
    }
};

// ---------------------------------------------------------------------------
// Proof objects.

pub const MaskedProof = struct {
    sigma: QM31,
    /// x-rounds: q(0), q(2..d); Y-round: q(1..d)
    rounds: [][MAX_DEG]QM31,
    /// hat values of the non-public factors (in factor order)
    hats: []QM31,
    u_val: QM31,
    deg: u8,

    pub fn deinit(self: *MaskedProof, a: std.mem.Allocator) void {
        a.free(self.rounds);
        a.free(self.hats);
    }
    pub fn byteSize(self: MaskedProof) usize {
        return 16 * (2 + self.rounds.len * @as(usize, self.deg) + self.hats.len);
    }
};

pub const ProveOut = struct {
    proof: MaskedProof,
    /// n x-challenges followed by gamma_Y
    point: []QM31,
    eps: QM31,

    pub fn deinitPoint(self: *ProveOut, a: std.mem.Allocator) void {
        a.free(self.point);
    }
};

fn termDegree(comptime terms: []const Term) usize {
    var d: usize = 0;
    for (terms) |t| d = @max(d, t.factors.len);
    return @max(d, 2);
}

inline fn evalTerms(comptime terms: []const Term, comptime NF: usize, cur: *const [NF]QM31) QM31 {
    var v = QM31.zero();
    inline for (terms) |term| {
        var p = cur[term.factors[0]];
        inline for (term.factors[1..]) |fi| p = p.mul(cur[fi]);
        if (comptime !term.coeff.eql(QM31.one())) p = p.mul(term.coeff);
        v = v.add(p);
    }
    return v;
}

pub fn evalTermsRt(comptime terms: []const Term, comptime NF: usize, vals: [NF]QM31) QM31 {
    return evalTerms(terms, NF, &vals);
}

fn Ctx(comptime NF: usize) type {
    return struct { fac: [NF][]QM31, half: usize, active: usize, partial: [][MAX_DEG + 1]QM31, chunk: usize };
}

fn roundKernel(comptime NF: usize, comptime terms: []const Term, comptime deg: usize) fn (*const Ctx(NF), usize, usize) void {
    return struct {
        fn run(c: *const Ctx(NF), s: usize, e: usize) void {
            var acc: [MAX_DEG + 1]QM31 = [_]QM31{QM31.zero()} ** (MAX_DEG + 1);
            var diff: [NF]QM31 = undefined;
            var cur: [NF]QM31 = undefined;
            for (s..e) |x| {
                const has_hi = x + c.half < c.active;
                inline for (0..NF) |j| {
                    const lo = c.fac[j][x];
                    const hi = if (has_hi) c.fac[j][x + c.half] else QM31.zero();
                    diff[j] = hi.sub(lo);
                    cur[j] = lo;
                }
                acc[0] = acc[0].add(evalTerms(terms, NF, &cur));
                inline for (0..NF) |j| cur[j] = cur[j].add(diff[j]).add(diff[j]);
                acc[2] = acc[2].add(evalTerms(terms, NF, &cur));
                if (deg >= 3) {
                    inline for (0..NF) |j| cur[j] = cur[j].add(diff[j]);
                    acc[3] = acc[3].add(evalTerms(terms, NF, &cur));
                }
            }
            c.partial[s / c.chunk] = acc;
        }
    }.run;
}

fn FoldCtx(comptime NF: usize) type {
    return struct { fac: [NF][]QM31, half: usize, active: usize, r: QM31 };
}

fn foldKernel(comptime NF: usize) fn (*const FoldCtx(NF), usize, usize) void {
    return struct {
        fn run(c: *const FoldCtx(NF), s: usize, e: usize) void {
            inline for (0..NF) |j| {
                const fac = c.fac[j];
                for (s..e) |x| {
                    const hi = if (x + c.half < c.active) fac[x + c.half] else QM31.zero();
                    fac[x] = fac[x].add(c.r.mul(hi.sub(fac[x])));
                }
            }
        }
    }.run;
}

/// Prove the masked sumcheck over hp.n variables. Factors are folded in place
/// and need only `min(active, 2^n)` entries (entries at or beyond `active` are
/// zero and never read). `pads` is called
/// once with the x-point r and the plain finals F_j(r) and returns the pad
/// values p_j (ignored for public factors, whose hat is their plain value).
pub fn prove(
    comptime NF: usize,
    comptime terms: []const Term,
    a: std.mem.Allocator,
    pool: *f.Pool,
    tr: *Transcript,
    claim: QM31,
    factors: [NF][]QM31,
    active_in: usize,
    public: [NF]bool,
    hp: Hp,
    pad_ctx: anytype,
) !ProveOut {
    const deg = comptime termDegree(terms);
    const n = hp.n;
    const len0 = @as(usize, 1) << @intCast(n);
    std.debug.assert(hp.d == deg);
    inline for (factors) |fac| std.debug.assert(fac.len >= @min(active_in, len0));
    const sigma = hp.sum();
    tr.mixFelt(sigma);
    const eps = tr.draw();
    var after: [64]QM31 = undefined;
    hp.afters(after[0 .. n + 1]);

    const rounds = try a.alloc([MAX_DEG]QM31, n + 1);
    errdefer a.free(rounds);
    const point = try a.alloc(QM31, n + 1);
    errdefer a.free(point);
    var g_claim = claim;
    var before = QM31.zero();
    var len = len0;
    var active = @min(active_in, len0);
    const max_chunks = pool.n_threads * 4 + 2;
    const partial = try a.alloc([MAX_DEG + 1]QM31, max_chunks);
    defer a.free(partial);
    for (0..n) |round| {
        const half = len / 2;
        const work = @min(half, active);
        var g: [MAX_DEG + 1]QM31 = [_]QM31{QM31.zero()} ** (MAX_DEG + 1);
        if (work > 0) {
            const target = pool.n_threads * 4;
            var chunk = (work + target - 1) / target;
            if (chunk < 2048) chunk = 2048;
            if (chunk > work) chunk = work;
            const n_chunks = (work + chunk - 1) / chunk;
            const ctx = Ctx(NF){ .fac = factors, .half = half, .active = active, .partial = partial, .chunk = chunk };
            const run = comptime roundKernel(NF, terms, deg);
            if (n_chunks <= 1) {
                run(&ctx, 0, work);
            } else {
                var wg: std.Thread.WaitGroup = .{};
                var s: usize = 0;
                while (s < work) : (s += chunk) pool.pool.spawnWg(&wg, run, .{ &ctx, s, @min(work, s + chunk) });
                pool.pool.waitAndWork(&wg);
            }
            for (0..n_chunks) |ci| for (0..deg + 1) |t| {
                g[t] = g[t].add(partial[ci][t]);
            };
        }
        g[1] = g_claim.sub(g[0]);
        var q: [MAX_DEG + 1]QM31 = undefined;
        for (0..deg + 1) |t| {
            const X = smallQ(@intCast(t));
            const uq = before.mul(X).add(hp.wEval(round, X)).add(after[round]);
            q[t] = uq.add(eps.mul(g[t]));
        }
        var msg = [_]QM31{QM31.zero()} ** MAX_DEG;
        msg[0] = q[0];
        for (2..deg + 1) |t| msg[t - 1] = q[t];
        tr.mixFelts(msg[0..deg]);
        rounds[round] = msg;
        const r = tr.draw();
        point[round] = r;
        g_claim = sc.interpolateAt(g[0 .. deg + 1], r);
        before = before.mul(r).add(hp.wEval(round, r));
        const fctx = FoldCtx(NF){ .fac = factors, .half = half, .active = active, .r = r };
        pool.parallelFor(work, 4096, &fctx, comptime foldKernel(NF));
        len = half;
        active = work;
    }
    var fin: [NF]QM31 = undefined;
    inline for (0..NF) |j| fin[j] = if (active > 0) factors[j][0] else QM31.zero();
    var pads: [NF]QM31 = pad_ctx.pads(point[0..n], fin);
    inline for (0..NF) |j| {
        if (public[j]) pads[j] = fin[j];
    }
    // Y round: G_y(Y) = G((1-Y) F + Y p)
    var gy: [MAX_DEG + 1]QM31 = undefined;
    var qy: [MAX_DEG + 1]QM31 = undefined;
    for (0..deg + 1) |t| {
        const Y = smallQ(@intCast(t));
        var vals: [NF]QM31 = undefined;
        inline for (0..NF) |j| vals[j] = fin[j].add(Y.mul(pads[j].sub(fin[j])));
        gy[t] = evalTerms(terms, NF, &vals);
        qy[t] = before.add(hp.wEval(n, Y)).add(eps.mul(gy[t]));
    }
    std.debug.assert(gy[0].eql(g_claim));
    var msg = [_]QM31{QM31.zero()} ** MAX_DEG;
    for (1..deg + 1) |t| msg[t - 1] = qy[t];
    tr.mixFelts(msg[0..deg]);
    rounds[n] = msg;
    const gam = tr.draw();
    point[n] = gam;
    var n_hats: usize = 0;
    inline for (0..NF) |j| n_hats += @intFromBool(!public[j]);
    const hats = try a.alloc(QM31, n_hats);
    var k: usize = 0;
    inline for (0..NF) |j| {
        if (!public[j]) {
            hats[k] = fin[j].add(gam.mul(pads[j].sub(fin[j])));
            k += 1;
        }
    }
    tr.mixFelts(hats);
    const u_val = before.add(hp.wEval(n, gam));
    tr.mixFelt(u_val);
    return .{ .proof = .{ .sigma = sigma, .rounds = rounds, .hats = hats, .u_val = u_val, .deg = @intCast(deg) }, .point = point, .eps = eps };
}

pub const VerifyOut = struct {
    point: []QM31,
    eps: QM31,
    /// value of the last round polynomial at gamma_Y; must equal u_val + eps * G(hats)
    final_claim: QM31,
};

pub fn verify(a: std.mem.Allocator, tr: *Transcript, claim: QM31, n: usize, deg: u8, n_hats: usize, proof: MaskedProof) !VerifyOut {
    if (proof.rounds.len != n + 1 or proof.deg != deg or proof.hats.len != n_hats or deg > MAX_DEG or deg < 2) return error.SumcheckShape;
    tr.mixFelt(proof.sigma);
    const eps = tr.draw();
    var cur = proof.sigma.add(eps.mul(claim));
    const point = try a.alloc(QM31, n + 1);
    errdefer a.free(point);
    for (0..n) |round| {
        const msg = proof.rounds[round];
        var vals: [MAX_DEG + 1]QM31 = undefined;
        vals[0] = msg[0];
        vals[1] = cur.sub(msg[0]);
        for (2..deg + 1) |t| vals[t] = msg[t - 1];
        tr.mixFelts(msg[0..deg]);
        const r = tr.draw();
        point[round] = r;
        cur = sc.interpolateAt(vals[0 .. deg + 1], r);
    }
    {
        const msg = proof.rounds[n];
        var vals: [MAX_DEG + 1]QM31 = undefined;
        vals[0] = cur; // phi_Y(q) = q(0) = running claim
        for (1..deg + 1) |t| vals[t] = msg[t - 1];
        tr.mixFelts(msg[0..deg]);
        const g = tr.draw();
        point[n] = g;
        cur = sc.interpolateAt(vals[0 .. deg + 1], g);
    }
    tr.mixFelts(proof.hats);
    tr.mixFelt(proof.u_val);
    return .{ .point = point, .eps = eps, .final_claim = cur };
}

// ---------------------------------------------------------------------------
// Tests.

const TT = [_]Term{ .{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1, 2 } }, .{ .coeff = QM31.fromU32Unchecked(f.P - 1, 0, 0, 0), .factors = &[_]u8{ 0, 3 } } };

test "hiding polynomial: sum and eval forms match brute force" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5);
    const r = prng.random();
    inline for (.{ 2, 3 }) |d| {
        const n = 4;
        const ne = Hp.entries(n, d);
        const c = try a.alloc(QM31, ne);
        defer a.free(c);
        for (c) |*x| x.* = QM31.fromU32Unchecked(r.uintLessThan(u32, f.P), r.uintLessThan(u32, f.P), 3, 1);
        const hp = Hp{ .n = n, .d = d, .c = c };
        // U(x, y) direct
        const U = struct {
            fn at(h: Hp, x: []const QM31) QM31 {
                var acc = QM31.zero();
                for (0..h.n + 1) |l| {
                    var t = h.wEval(l, x[l]);
                    if (l < h.n) for (l + 1..h.n) |j| {
                        t = t.mul(x[j]);
                    };
                    acc = acc.add(t);
                }
                return acc;
            }
        };
        var brute = QM31.zero();
        for (0..(1 << n)) |m| {
            var x: [n + 1]QM31 = undefined;
            for (0..n) |k| x[k] = if ((m >> @intCast(k)) & 1 == 1) QM31.one() else QM31.zero();
            x[n] = QM31.zero();
            brute = brute.add(U.at(hp, &x));
        }
        try std.testing.expect(brute.eql(hp.sum()));
        const form = try a.alloc(QM31, ne);
        defer a.free(form);
        Hp.sumForm(n, d, form);
        var s2 = QM31.zero();
        for (form, c) |x, y| s2 = s2.add(x.mul(y));
        try std.testing.expect(s2.eql(brute));
        var g: [n + 1]QM31 = undefined;
        for (&g, 0..) |*x, i| x.* = QM31.fromU32Unchecked(@intCast(17 + i), 5, @intCast(i), 2);
        Hp.evalForm(n, d, &g, form);
        var e2 = QM31.zero();
        for (form, c) |x, y| e2 = e2.add(x.mul(y));
        try std.testing.expect(e2.eql(U.at(hp, &g)));
    }
}

const NoPad = struct {
    p: [4]QM31,
    pub fn pads(self: @This(), _: []const QM31, _: [4]QM31) [4]QM31 {
        return self.p;
    }
};

test "masked sumcheck: completeness, final check, rejection" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const n = 6;
    const len = 1 << n;
    var prng = std.Random.DefaultPrng.init(9);
    const r = prng.random();
    var fac: [4][]QM31 = undefined;
    var orig: [4][]QM31 = undefined;
    for (&fac, &orig) |*x, *o| {
        x.* = try a.alloc(QM31, len);
        for (x.*) |*v| v.* = QM31.fromU32Unchecked(r.uintLessThan(u32, f.P), r.uintLessThan(u32, f.P), r.uintLessThan(u32, f.P), 0);
        o.* = try a.dupe(QM31, x.*);
    }
    defer for (fac, orig) |x, o| {
        a.free(x);
        a.free(o);
    };
    var claim = QM31.zero();
    for (0..len) |i| claim = claim.add(fac[0][i].mul(fac[1][i]).mul(fac[2][i]).sub(fac[0][i].mul(fac[3][i])));
    const c = try a.alloc(QM31, Hp.entries(n, 3));
    defer a.free(c);
    for (c) |*x| x.* = QM31.fromU32Unchecked(r.uintLessThan(u32, f.P), 1, 2, r.uintLessThan(u32, f.P));
    const hp = Hp{ .n = n, .d = 3, .c = c };
    const pads = NoPad{ .p = .{ QM31.zero(), QM31.fromU32Unchecked(5, 0, 0, 0), QM31.fromU32Unchecked(6, 1, 0, 0), QM31.fromU32Unchecked(7, 0, 2, 0) } };
    const public = [4]bool{ true, false, false, false };
    var tp = Transcript.initDomain("msc");
    var out = try prove(4, &TT, a, &pool, &tp, claim, fac, len, public, hp, pads);
    defer out.proof.deinit(a);
    defer a.free(out.point);
    var tv = Transcript.initDomain("msc");
    const vo = try verify(a, &tv, claim, n, 3, 3, out.proof);
    defer a.free(vo.point);
    // public factor 0 evaluated by the verifier
    const f0 = try f.mleEval(a, orig[0], vo.point[0..n]);
    const hats = [4]QM31{ f0, out.proof.hats[0], out.proof.hats[1], out.proof.hats[2] };
    try std.testing.expect(vo.final_claim.eql(out.proof.u_val.add(vo.eps.mul(evalTermsRt(&TT, 4, hats)))));
    // the hats are the claimed masked values
    const gy = vo.point[n];
    for (1..4) |j| {
        const fj = try f.mleEval(a, orig[j], vo.point[0..n]);
        try std.testing.expect(hats[j].eql(fj.add(gy.mul(pads.p[j].sub(fj)))));
    }
    // u_val equals U(point)
    const form = try a.alloc(QM31, c.len);
    defer a.free(form);
    Hp.evalForm(n, 3, vo.point, form);
    var uv = QM31.zero();
    for (form, c) |x, y| uv = uv.add(x.mul(y));
    try std.testing.expect(uv.eql(out.proof.u_val));
    // wrong claim breaks the final check
    var tv2 = Transcript.initDomain("msc");
    const vo2 = try verify(a, &tv2, claim.add(QM31.one()), n, 3, 3, out.proof);
    defer a.free(vo2.point);
    const f0b = try f.mleEval(a, orig[0], vo2.point[0..n]);
    const hats2 = [4]QM31{ f0b, out.proof.hats[0], out.proof.hats[1], out.proof.hats[2] };
    try std.testing.expect(!vo2.final_claim.eql(out.proof.u_val.add(vo2.eps.mul(evalTermsRt(&TT, 4, hats2)))));
    // tampered hat breaks it as well
    out.proof.hats[1] = out.proof.hats[1].add(QM31.one());
    var tv3 = Transcript.initDomain("msc");
    const vo3 = try verify(a, &tv3, claim, n, 3, 3, out.proof);
    defer a.free(vo3.point);
    const hats3 = [4]QM31{ f0, out.proof.hats[0], out.proof.hats[1], out.proof.hats[2] };
    try std.testing.expect(!vo3.final_claim.eql(out.proof.u_val.add(vo3.eps.mul(evalTermsRt(&TT, 4, hats3)))));
}
