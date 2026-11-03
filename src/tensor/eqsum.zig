//! Fast prover for eq-weighted sumchecks  sum_x eq(rho, x) * g(A_1(x), .., A_K(x))
//! with integer (base-field) inputs A_j and g one of
//!   g = A_1 * A_2           (hadamard)
//!   g = A_1 * A_2 - A_3     (product)
//!
//! The produced proof/transcript is identical to
//!   sumcheck.proveActive(K + 1, {eq * g}, claim, {eqTable(rho), A_1.., A_K}, 2^n)
//! (same round values s(0), s(2), s(3), same challenges, same finals), but the
//! prover never materialises or folds the eq table ("split eq", Gruen 2024):
//!
//!   eq(rho, (t, x')) = e_k(t) * eq(rho_{k+1..}, x'),  e_k(t) = (1-rho_k)(1-t) + rho_k t
//!
//! so in round k, s_k(t) = C_k e_k(t) q_k(t) with C_k = prod_{j<k} e_j(r_j) and
//! q_k(t) = sum_{x'} T_k(x') g(t, x'), T_k = eq(rho_{k+1..}, .). T_{k+1} is the
//! sum of T_k's two halves (e(0)+e(1)=1), so all suffix tables cost additions
//! only. q_k has degree 2; q_k(1) follows from the running claim
//! (s(0) + s(1) = claim) when C_k rho_k != 0, otherwise it is summed directly.
//! Round 0 runs in the base field straight from the i32 inputs.
const std = @import("std");
const f = @import("field.zig");
const sc = @import("sumcheck.zig");
const Transcript = @import("transcript.zig").Transcript;

const QM31 = f.QM31;
const M31 = f.M31;
const PQ = f.PackedQM31;
const PM = f.PackedM31;
const LANES = f.PACK_WIDTH;

pub const Kind = enum { hadamard, product };

fn nIn(comptime kind: Kind) usize {
    return switch (kind) {
        .hadamard => 2,
        .product => 3,
    };
}

inline fn gBase(comptime kind: Kind, v: *const [nIn(kind)]M31) M31 {
    return switch (kind) {
        .hadamard => v[0].mul(v[1]),
        .product => v[0].mul(v[1]).sub(v[2]),
    };
}

inline fn gBaseP(comptime kind: Kind, v: *const [nIn(kind)]PM) PM {
    return switch (kind) {
        .hadamard => f.mulPackedM31(v[0], v[1]),
        .product => f.subPackedM31(f.mulPackedM31(v[0], v[1]), v[2]),
    };
}

inline fn gExt(comptime kind: Kind, v: *const [nIn(kind)]QM31) QM31 {
    return switch (kind) {
        .hadamard => v[0].mul(v[1]),
        .product => v[0].mul(v[1]).sub(v[2]),
    };
}

inline fn gExtP(comptime kind: Kind, v: *const [nIn(kind)]PQ) PQ {
    return switch (kind) {
        .hadamard => v[0].mul(v[1]),
        .product => v[0].mul(v[1]).sub(v[2]),
    };
}

inline fn packedFromI32(src: []const i32, at: usize) PM {
    const v: @Vector(LANES, i32) = src[at..][0..LANES].*;
    const u: PM = @bitCast(v);
    const p: PM = @splat(f.P);
    return @select(u32, v < @as(@Vector(LANES, i32), @splat(0)), u +% p, u);
}

inline fn loadP(src: []const QM31, at: usize) PQ {
    return PQ.fromLanes(src[at..][0..LANES].*);
}

inline fn storeP(dst: []QM31, at: usize, v: PQ) void {
    inline for (0..LANES) |l| dst[at + l] = v.lane(l);
}

inline fn sumLanes(v: PQ) QM31 {
    var s = QM31.zero();
    inline for (0..LANES) |l| s = s.add(v.lane(l));
    return s;
}

/// q sums: [0] = q(0), [1] = q(1) (only if with_q1), [2] = q(2)
const Sums = [3]QM31;

fn Round0Ctx(comptime kind: Kind) type {
    return struct { ins: [nIn(kind)][]const i32, T: []const QM31, half: usize, partial: []Sums, chunk: usize, with_q1: bool };
}

fn round0(comptime kind: Kind) fn (*const Round0Ctx(kind), usize, usize) void {
    const K = nIn(kind);
    return struct {
        fn run(c: *const Round0Ctx(kind), s: usize, e: usize) void {
            @setEvalBranchQuota(100_000);
            var out: Sums = .{ QM31.zero(), QM31.zero(), QM31.zero() };
            var x = s;
            if (LANES > 1) {
                var p0 = PQ.zero();
                var p1 = PQ.zero();
                var p2 = PQ.zero();
                while (x + LANES <= e) : (x += LANES) {
                    var lo: [K]PM = undefined;
                    var hi: [K]PM = undefined;
                    var two: [K]PM = undefined;
                    inline for (0..K) |j| {
                        lo[j] = packedFromI32(c.ins[j], x);
                        hi[j] = packedFromI32(c.ins[j], x + c.half);
                        two[j] = f.subPackedM31(f.addPackedM31(hi[j], hi[j]), lo[j]);
                    }
                    const t = loadP(c.T, x);
                    p0 = p0.add(t.mulBase(gBaseP(kind, &lo)));
                    p2 = p2.add(t.mulBase(gBaseP(kind, &two)));
                    if (c.with_q1) p1 = p1.add(t.mulBase(gBaseP(kind, &hi)));
                }
                out = .{ sumLanes(p0), sumLanes(p1), sumLanes(p2) };
            }
            while (x < e) : (x += 1) {
                var lo: [K]M31 = undefined;
                var hi: [K]M31 = undefined;
                var two: [K]M31 = undefined;
                inline for (0..K) |j| {
                    lo[j] = f.fromI32(c.ins[j][x]);
                    hi[j] = f.fromI32(c.ins[j][x + c.half]);
                    two[j] = hi[j].add(hi[j]).sub(lo[j]);
                }
                const t = c.T[x];
                out[0] = out[0].add(t.mulM31(gBase(kind, &lo)));
                out[2] = out[2].add(t.mulM31(gBase(kind, &two)));
                if (c.with_q1) out[1] = out[1].add(t.mulM31(gBase(kind, &hi)));
            }
            c.partial[s / c.chunk] = out;
        }
    }.run;
}

fn Fold0Ctx(comptime kind: Kind) type {
    return struct { ins: [nIn(kind)][]const i32, outs: [nIn(kind)][]QM31, half: usize, r: QM31 };
}

fn fold0(comptime kind: Kind) fn (*const Fold0Ctx(kind), usize, usize) void {
    const K = nIn(kind);
    return struct {
        fn run(c: *const Fold0Ctx(kind), s: usize, e: usize) void {
            @setEvalBranchQuota(100_000);
            const rp = PQ.splat(c.r);
            inline for (0..K) |j| {
                var x = s;
                if (LANES > 1) {
                    while (x + LANES <= e) : (x += LANES) {
                        const lo = packedFromI32(c.ins[j], x);
                        const hi = packedFromI32(c.ins[j], x + c.half);
                        storeP(c.outs[j], x, rp.mulBase(f.subPackedM31(hi, lo)).add(PQ.fromBase(lo)));
                    }
                }
                while (x < e) : (x += 1) {
                    const lo = f.fromI32(c.ins[j][x]);
                    const hi = f.fromI32(c.ins[j][x + c.half]);
                    c.outs[j][x] = c.r.mulM31(hi.sub(lo)).add(QM31.fromBase(lo));
                }
            }
        }
    }.run;
}

fn RoundCtx(comptime kind: Kind) type {
    return struct { facs: [nIn(kind)][]QM31, T: []const QM31, half: usize, partial: []Sums, chunk: usize, with_q1: bool };
}

fn roundK(comptime kind: Kind) fn (*const RoundCtx(kind), usize, usize) void {
    const K = nIn(kind);
    return struct {
        fn run(c: *const RoundCtx(kind), s: usize, e: usize) void {
            @setEvalBranchQuota(100_000);
            var out: Sums = .{ QM31.zero(), QM31.zero(), QM31.zero() };
            var x = s;
            if (LANES > 1) {
                var p0 = PQ.zero();
                var p1 = PQ.zero();
                var p2 = PQ.zero();
                while (x + LANES <= e) : (x += LANES) {
                    var lo: [K]PQ = undefined;
                    var hi: [K]PQ = undefined;
                    var two: [K]PQ = undefined;
                    inline for (0..K) |j| {
                        lo[j] = loadP(c.facs[j], x);
                        hi[j] = loadP(c.facs[j], x + c.half);
                        two[j] = hi[j].add(hi[j]).sub(lo[j]);
                    }
                    const t = loadP(c.T, x);
                    p0 = p0.add(t.mul(gExtP(kind, &lo)));
                    p2 = p2.add(t.mul(gExtP(kind, &two)));
                    if (c.with_q1) p1 = p1.add(t.mul(gExtP(kind, &hi)));
                }
                out = .{ sumLanes(p0), sumLanes(p1), sumLanes(p2) };
            }
            while (x < e) : (x += 1) {
                var lo: [K]QM31 = undefined;
                var hi: [K]QM31 = undefined;
                var two: [K]QM31 = undefined;
                inline for (0..K) |j| {
                    lo[j] = c.facs[j][x];
                    hi[j] = c.facs[j][x + c.half];
                    two[j] = hi[j].add(hi[j]).sub(lo[j]);
                }
                const t = c.T[x];
                out[0] = out[0].add(t.mul(gExt(kind, &lo)));
                out[2] = out[2].add(t.mul(gExt(kind, &two)));
                if (c.with_q1) out[1] = out[1].add(t.mul(gExt(kind, &hi)));
            }
            c.partial[s / c.chunk] = out;
        }
    }.run;
}

fn FoldCtx(comptime kind: Kind) type {
    return struct { facs: [nIn(kind)][]QM31, T: []QM31, half: usize, r: QM31 };
}

/// Folds factors at r and halves T (T'[i] = T[i] + T[i + half/2]).
fn foldK(comptime kind: Kind) fn (*const FoldCtx(kind), usize, usize) void {
    const K = nIn(kind);
    return struct {
        fn run(c: *const FoldCtx(kind), s: usize, e: usize) void {
            @setEvalBranchQuota(100_000);
            const rp = PQ.splat(c.r);
            inline for (0..K) |j| {
                const fac = c.facs[j];
                var x = s;
                if (LANES > 1) {
                    while (x + LANES <= e) : (x += LANES) {
                        const lo = loadP(fac, x);
                        const hi = loadP(fac, x + c.half);
                        storeP(fac, x, lo.add(rp.mul(hi.sub(lo))));
                    }
                }
                while (x < e) : (x += 1) fac[x] = fac[x].add(c.r.mul(fac[x + c.half].sub(fac[x])));
            }
        }
    }.run;
}

const TCtx = struct { T: []QM31, q: usize };
fn halveT(c: *const TCtx, s: usize, e: usize) void {
    for (s..e) |i| c.T[i] = c.T[i].add(c.T[i + c.q]);
}

fn reduceParallel(comptime Ctx: type, comptime func: anytype, pool: *f.Pool, partial_buf: []Sums, ctx: *Ctx, work: usize) Sums {
    const target = pool.n_threads * 4;
    var chunk = (work + target - 1) / target;
    if (chunk < 4096) chunk = 4096;
    if (chunk > work) chunk = work;
    const n_chunks = (work + chunk - 1) / chunk;
    ctx.chunk = chunk;
    ctx.partial = partial_buf[0..n_chunks];
    if (n_chunks <= 1) {
        func(ctx, 0, work);
    } else {
        var wg: std.Thread.WaitGroup = .{};
        var s: usize = 0;
        while (s < work) : (s += chunk) pool.pool.spawnWg(&wg, func, .{ ctx, s, @min(work, s + chunk) });
        pool.pool.waitAndWork(&wg);
    }
    var out: Sums = .{ QM31.zero(), QM31.zero(), QM31.zero() };
    for (ctx.partial) |p| {
        for (0..3) |i| out[i] = out[i].add(p[i]);
    }
    return out;
}

inline fn e1(rho: QM31, t: QM31) QM31 {
    // (1 - rho)(1 - t) + rho t
    return QM31.one().sub(rho).mul(QM31.one().sub(t)).add(rho.mul(t));
}

/// Same transcript/result as proveActive(K+1, {eq*g}, claim, {eq(rho), A..}, 2^n).
/// finals = [eq(rho, point), A_1(point), .., A_K(point)].
pub fn prove(
    comptime kind: Kind,
    a: std.mem.Allocator,
    pool: *f.Pool,
    tr: *Transcript,
    claim: QM31,
    rho: []const QM31,
    ins: [nIn(kind)][]const i32,
) !sc.ProveResult {
    const K = comptime nIn(kind);
    const n = rho.len;
    const len = @as(usize, 1) << @intCast(n);
    inline for (0..K) |j| std.debug.assert(ins[j].len == len);
    if (n == 0) {
        // degenerate single point: generic prover
        var gf: [K + 1][]QM31 = undefined;
        gf[0] = try a.alloc(QM31, 1);
        gf[0][0] = QM31.one();
        inline for (0..K) |j| {
            gf[j + 1] = try a.alloc(QM31, 1);
            gf[j + 1][0] = QM31.fromBase(f.fromI32(ins[j][0]));
        }
        defer inline for (0..K + 1) |j| a.free(gf[j]);
        const terms = if (kind == .product) &T_PRODUCT else &T_EQ3;
        return sc.proveActive(K + 1, terms, a, pool, tr, claim, gf, 1);
    }

    const rounds = try a.alloc(sc.RoundPoly, n);
    errdefer a.free(rounds);
    const point = try a.alloc(QM31, n);
    errdefer a.free(point);
    const T = try f.eqTablePar(a, pool, rho[1..], QM31.one());
    defer a.free(T);
    var facs: [K][]QM31 = undefined;
    inline for (0..K) |j| facs[j] = try a.alloc(QM31, len / 2);
    defer inline for (0..K) |j| a.free(facs[j]);
    const partial = try a.alloc(Sums, pool.n_threads * 4 + 2);
    defer a.free(partial);

    var C = QM31.one();
    var cur = claim;
    var half = len / 2;
    for (0..n) |k| {
        const rk = rho[k];
        const cr = C.mul(rk);
        const derive_q1 = !cr.isZero();
        var q: Sums = undefined;
        if (k == 0) {
            var ctx = Round0Ctx(kind){ .ins = ins, .T = T[0..half], .half = half, .partial = partial, .chunk = 1, .with_q1 = !derive_q1 };
            q = reduceParallel(Round0Ctx(kind), comptime round0(kind), pool, partial, &ctx, half);
        } else {
            var fv: [K][]QM31 = undefined;
            inline for (0..K) |j| fv[j] = facs[j][0 .. 2 * half];
            var ctx = RoundCtx(kind){ .facs = fv, .T = T[0..half], .half = half, .partial = partial, .chunk = 1, .with_q1 = !derive_q1 };
            q = reduceParallel(RoundCtx(kind), comptime roundK(kind), pool, partial, &ctx, half);
        }
        const one_m = QM31.one().sub(rk);
        // s(0) = C (1 - rho) q(0); s(1) = claim - s(0) = C rho q(1)
        const s0 = C.mul(one_m).mul(q[0]);
        const s1 = cur.sub(s0);
        if (derive_q1) q[1] = s1.mul(cr.inv() catch unreachable);
        // q has degree <= 2: q(3) = q(0) - 3 q(1) + 3 q(2)
        const three = QM31.fromBase(M31.fromCanonical(3));
        const q3 = q[0].sub(three.mul(q[1])).add(three.mul(q[2]));
        const s2 = C.mul(e1(rk, QM31.fromBase(M31.fromCanonical(2)))).mul(q[2]);
        const s3 = C.mul(e1(rk, three)).mul(q3);
        var rp = sc.RoundPoly{ .evals = [_]QM31{QM31.zero()} ** sc.MAX_DEG };
        rp.evals[0] = s0;
        rp.evals[1] = s2;
        rp.evals[2] = s3;
        tr.mixFelts(rp.evals[0..3]);
        rounds[k] = rp;
        const r = tr.draw();
        point[k] = r;
        const vals = [4]QM31{ s0, s1, s2, s3 };
        cur = sc.interpolateAt(&vals, r);
        // fold
        if (k == 0) {
            const fctx = Fold0Ctx(kind){ .ins = ins, .outs = facs, .half = half, .r = r };
            pool.parallelFor(half, 4096, &fctx, comptime fold0(kind));
        } else {
            var fv: [K][]QM31 = undefined;
            inline for (0..K) |j| fv[j] = facs[j][0 .. 2 * half];
            const fctx = FoldCtx(kind){ .facs = fv, .T = T, .half = half, .r = r };
            pool.parallelFor(half, 4096, &fctx, comptime foldK(kind));
        }
        if (half >= 2) {
            const tctx = TCtx{ .T = T, .q = half / 2 };
            pool.parallelFor(half / 2, 8192, &tctx, halveT);
        }
        C = C.mul(e1(rk, r));
        half /= 2;
    }
    const finals = try a.alloc(QM31, K + 1);
    finals[0] = C;
    inline for (0..K) |j| finals[j + 1] = facs[j][0];
    return .{ .proof = .{ .rounds = rounds, .deg = 3 }, .point = point, .finals = finals };
}

const T_EQ3 = [_]sc.Term{.{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1, 2 } }};
const T_PRODUCT = [_]sc.Term{ .{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1, 2 } }, .{ .coeff = QM31.fromU32Unchecked(f.P - 1, 0, 0, 0), .factors = &[_]u8{ 0, 3 } } };

fn checkAgainstGeneric(comptime kind: Kind, n: usize, seed: u64, zero_rho0: bool, wrong_claim: bool) !void {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 3);
    defer pool.deinit();
    const K = comptime nIn(kind);
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();
    const len = @as(usize, 1) << @intCast(n);
    var ins: [K][]i32 = undefined;
    inline for (0..K) |j| {
        ins[j] = try a.alloc(i32, len);
        for (ins[j]) |*v| v.* = rnd.intRangeAtMost(i32, -(1 << 30), 1 << 30);
    }
    defer inline for (0..K) |j| a.free(ins[j]);
    const rho = try a.alloc(QM31, n);
    defer a.free(rho);
    for (rho) |*r| r.* = QM31.fromU32Unchecked(rnd.uintLessThan(u32, f.P), rnd.uintLessThan(u32, f.P), rnd.uintLessThan(u32, f.P), rnd.uintLessThan(u32, f.P));
    if (zero_rho0) rho[0] = QM31.zero();
    // generic factors
    var gf: [K + 1][]QM31 = undefined;
    gf[0] = try f.eqTablePar(a, &pool, rho, QM31.one());
    inline for (0..K) |j| {
        gf[j + 1] = try a.alloc(QM31, len);
        for (ins[j], gf[j + 1]) |v, *o| o.* = QM31.fromBase(f.fromI32(v));
    }
    defer inline for (0..K + 1) |j| a.free(gf[j]);
    // claim (also exercise a wrong claim: transcripts must still agree)
    var claim = QM31.zero();
    for (0..len) |x| {
        var g = gf[1][x].mul(gf[2][x]);
        if (kind == .product) g = g.sub(gf[3][x]);
        claim = claim.add(gf[0][x].mul(g));
    }
    if (wrong_claim) {
        // Honest-prover equivalence only holds for true claims (q(1) is derived
        // from the claim). For a false claim the proof must still be rejected.
        claim = claim.add(QM31.one());
        var t1 = Transcript.initDomain("e");
        var cins: [K][]const i32 = undefined;
        inline for (0..K) |j| cins[j] = ins[j];
        var r1 = try prove(kind, a, &pool, &t1, claim, rho, cins);
        defer r1.deinit(a);
        var tv = Transcript.initDomain("e");
        const vr = try sc.verify(a, &tv, claim, n, 3, r1.proof);
        defer a.free(vr.point);
        var g = r1.finals[1].mul(r1.finals[2]);
        if (kind == .product) g = g.sub(r1.finals[3]);
        const expect = f.eqEval(rho, vr.point).mul(g);
        try std.testing.expect(!vr.final_claim.eql(expect));
        return;
    }
    var t1 = Transcript.initDomain("e");
    var t2 = Transcript.initDomain("e");
    var cins: [K][]const i32 = undefined;
    inline for (0..K) |j| cins[j] = ins[j];
    var r1 = try prove(kind, a, &pool, &t1, claim, rho, cins);
    defer r1.deinit(a);
    const terms = if (kind == .product) &T_PRODUCT else &T_EQ3;
    var r2 = try sc.proveActive(K + 1, terms, a, &pool, &t2, claim, gf, len);
    defer r2.deinit(a);
    for (r1.proof.rounds, r2.proof.rounds) |x, y| for (0..3) |i| try std.testing.expect(x.evals[i].eql(y.evals[i]));
    for (r1.point, r2.point) |x, y| try std.testing.expect(x.eql(y));
    for (r1.finals, r2.finals) |x, y| try std.testing.expect(x.eql(y));
    try std.testing.expect(t1.draw().eql(t2.draw()));
}

test "split-eq sumcheck matches generic prover exactly" {
    for ([_]usize{ 1, 2, 3, 7, 13 }) |n| {
        try checkAgainstGeneric(.product, n, 2 * n, false, false);
        try checkAgainstGeneric(.product, n, 2 * n + 1, false, false);
        try checkAgainstGeneric(.hadamard, n, 2 * n, false, false);
        try checkAgainstGeneric(.hadamard, n, 2 * n + 1, false, false);
        try checkAgainstGeneric(.product, n, 2 * n, true, false);
        try checkAgainstGeneric(.hadamard, n, 2 * n + 1, true, false);
        try checkAgainstGeneric(.product, n, 3 * n, false, true);
        try checkAgainstGeneric(.hadamard, n, 3 * n, false, true);
    }
}
