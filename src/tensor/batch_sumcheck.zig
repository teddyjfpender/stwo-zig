//! Sumcheck for a random combination of E inner products with shared
//! challenges:  claim = sum_x sum_e xi_e f_e(x) g_e(x).
//!
//! Used to batch all matmuls of one shape class (same T, K, N): every member's
//! weight claim then sits at the same local point (r, rho_n), so the weight
//! table sees one column point per class instead of one per matmul. The proof
//! format is `sumcheck.Proof` with deg 2 (s(0), s(2) per round), so
//! `sumcheck.verify` checks it; the caller checks the final claim
//! sum_e xi_e f_e(r) g_e(r).
const std = @import("std");
const f = @import("field.zig");
const sc = @import("sumcheck.zig");
const Transcript = @import("transcript.zig").Transcript;

const QM31 = f.QM31;

pub const Result = struct {
    proof: sc.Proof,
    point: []QM31,
    f_finals: []QM31,
    g_finals: []QM31,

    pub fn deinitExceptProof(self: *Result, a: std.mem.Allocator) void {
        a.free(self.point);
        a.free(self.f_finals);
        a.free(self.g_finals);
    }
};

/// Folds the vectors in place (they are consumed).
pub fn prove(a: std.mem.Allocator, tr: *Transcript, claim: QM31, fs: []const []QM31, gs: []const []QM31, xi: []const QM31) !Result {
    std.debug.assert(fs.len == gs.len and fs.len == xi.len and fs.len > 0);
    const len0 = fs[0].len;
    for (fs, gs) |x, y| std.debug.assert(x.len == len0 and y.len == len0);
    const n = f.log2Exact(len0);
    const rounds = try a.alloc(sc.RoundPoly, n);
    errdefer a.free(rounds);
    const point = try a.alloc(QM31, n);
    errdefer a.free(point);
    var cur = claim;
    var len = len0;
    for (0..n) |round| {
        const half = len / 2;
        var s0 = QM31.zero();
        var s2 = QM31.zero();
        for (fs, gs, xi) |fe, ge, x| {
            var e0 = QM31.zero();
            var e2 = QM31.zero();
            for (0..half) |i| {
                e0 = e0.add(fe[i].mul(ge[i]));
                const f2 = fe[i + half].add(fe[i + half]).sub(fe[i]);
                const g2 = ge[i + half].add(ge[i + half]).sub(ge[i]);
                e2 = e2.add(f2.mul(g2));
            }
            s0 = s0.add(e0.mul(x));
            s2 = s2.add(e2.mul(x));
        }
        var rp = sc.RoundPoly{ .evals = [_]QM31{QM31.zero()} ** sc.MAX_DEG };
        rp.evals[0] = s0;
        rp.evals[1] = s2;
        tr.mixFelts(rp.evals[0..2]);
        rounds[round] = rp;
        const r = tr.draw();
        point[round] = r;
        cur = sc.interpolateAt(&.{ s0, cur.sub(s0), s2 }, r);
        for (fs, gs) |fe, ge| {
            for (0..half) |i| {
                fe[i] = fe[i].add(r.mul(fe[i + half].sub(fe[i])));
                ge[i] = ge[i].add(r.mul(ge[i + half].sub(ge[i])));
            }
        }
        len = half;
    }
    const ff = try a.alloc(QM31, fs.len);
    const gf = try a.alloc(QM31, gs.len);
    for (fs, gs, 0..) |fe, ge, e| {
        ff[e] = fe[0];
        gf[e] = ge[0];
    }
    return .{ .proof = .{ .rounds = rounds, .deg = 2 }, .point = point, .f_finals = ff, .g_finals = gf };
}

/// sum_e xi_e f_e g_e from final values.
pub fn finalValue(xi: []const QM31, ff: []const QM31, gf: []const QM31) QM31 {
    var acc = QM31.zero();
    for (xi, ff, gf) |x, a, b| acc = acc.add(x.mul(a.mul(b)));
    return acc;
}

test "batched inner-product sumcheck roundtrip and rejection" {
    const a = std.testing.allocator;
    const n = 6;
    const N = 1 << n;
    const E = 3;
    var fs: [E][]QM31 = undefined;
    var gs: [E][]QM31 = undefined;
    var xi: [E]QM31 = undefined;
    var claim = QM31.zero();
    for (0..E) |e| {
        fs[e] = try a.alloc(QM31, N);
        gs[e] = try a.alloc(QM31, N);
        xi[e] = QM31.fromU32Unchecked(@intCast(e + 3), 1, 2, @intCast(e));
        var ip = QM31.zero();
        for (0..N) |i| {
            fs[e][i] = QM31.fromU32Unchecked(@intCast(i * 7 + e), @intCast(i), 0, 1);
            gs[e][i] = QM31.fromU32Unchecked(@intCast(i * 3 + 1), 5, @intCast(e), 0);
            ip = ip.add(fs[e][i].mul(gs[e][i]));
        }
        claim = claim.add(xi[e].mul(ip));
    }
    defer for (0..E) |e| {
        a.free(fs[e]);
        a.free(gs[e]);
    };
    // reference MLE evaluations of the original vectors at the final point
    var fcopy: [E][]QM31 = undefined;
    var gcopy: [E][]QM31 = undefined;
    for (0..E) |e| {
        fcopy[e] = try a.dupe(QM31, fs[e]);
        gcopy[e] = try a.dupe(QM31, gs[e]);
    }
    defer for (0..E) |e| {
        a.free(fcopy[e]);
        a.free(gcopy[e]);
    };
    var tp = Transcript.initDomain("bsc");
    var res = try prove(a, &tp, claim, &fs, &gs, &xi);
    defer res.proof.deinit(a);
    defer res.deinitExceptProof(a);
    for (0..E) |e| {
        try std.testing.expect(res.f_finals[e].eql(try f.mleEval(a, fcopy[e], res.point)));
        try std.testing.expect(res.g_finals[e].eql(try f.mleEval(a, gcopy[e], res.point)));
    }
    var tv = Transcript.initDomain("bsc");
    const vr = try sc.verify(a, &tv, claim, n, 2, res.proof);
    defer a.free(vr.point);
    try std.testing.expect(vr.final_claim.eql(finalValue(&xi, res.f_finals, res.g_finals)));
    // wrong claim: final check fails
    var tv2 = Transcript.initDomain("bsc");
    const vr2 = try sc.verify(a, &tv2, claim.add(QM31.one()), n, 2, res.proof);
    defer a.free(vr2.point);
    try std.testing.expect(!vr2.final_claim.eql(finalValue(&xi, res.f_finals, res.g_finals)));
}
