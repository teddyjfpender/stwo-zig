//! Accelerator dispatch hook for the tensor prover.
//!
//! `Accel` is a small vtable that a device backend (e.g. `metal/gpu.zig`)
//! fills in. Every entry may decline (return null), in which case the CPU
//! path runs. Results must be bit-identical to the CPU path: the transcript,
//! round-message assembly and all challenge derivation stay here on the CPU;
//! the device only does the data-parallel work (row encoding + Merkle
//! hashing, sumcheck round sums and folds).
const std = @import("std");
const f = @import("field.zig");
const sc = @import("sumcheck.zig");
const pcs = @import("pcs.zig");
const Transcript = @import("transcript.zig").Transcript;

const QM31 = f.QM31;

pub const Accel = struct {
    ctx: *anyopaque,
    /// pcs.commit for i32 / i8 matrices; null = not handled.
    commit_i32: *const fn (ctx: *anyopaque, a: std.mem.Allocator, tw: *const pcs.Twiddles, m: pcs.Matrix(i32), log_blowup: u32) anyerror!?pcs.Committed,
    commit_i8: *const fn (ctx: *anyopaque, a: std.mem.Allocator, tw: *const pcs.Twiddles, m: pcs.Matrix(i8), log_blowup: u32) anyerror!?pcs.Committed,
    /// Starts a device sumcheck over `factors` (all of length `len`, entries
    /// >= `active` are zero). Null = not handled.
    sc_begin: *const fn (ctx: *anyopaque, factors: []const []QM31, terms: []const sc.Term, active: usize) anyerror!?*anyopaque,
    /// Folds the previous round with `r_prev` (if any), then returns the round
    /// sums {s(0), s(2), s(3)} of the current round.
    sc_round: *const fn (ctx: *anyopaque, s: *anyopaque, r_prev: ?QM31) anyerror![3]QM31,
    /// Applies the last fold and leaves factors[j][0 .. len/2] (the folded
    /// prefix) in host memory; releases the session.
    sc_finish: *const fn (ctx: *anyopaque, s: *anyopaque, r_last: QM31) anyerror!void,
    sc_abort: *const fn (ctx: *anyopaque, s: *anyopaque) void,
    /// Device rounds run while the round's work (min(half, active)) is at
    /// least this; the remaining small rounds run on the CPU.
    sc_min_work: usize = 1 << 14,
};

pub fn commit(acc: ?*const Accel, comptime T: type, a: std.mem.Allocator, pool: *f.Pool, tw: *const pcs.Twiddles, m: pcs.Matrix(T), log_blowup: u32) !pcs.Committed {
    if (acc) |A| {
        const r = switch (T) {
            i32 => try A.commit_i32(A.ctx, a, tw, m, log_blowup),
            i8 => try A.commit_i8(A.ctx, a, tw, m, log_blowup),
            else => null,
        };
        if (r) |c| return c;
    }
    return pcs.commit(T, a, pool, tw, m, log_blowup);
}

fn termDegree(comptime terms: []const sc.Term) u8 {
    var d: usize = 2;
    for (terms) |t| d = @max(d, t.factors.len);
    return @intCast(d);
}

/// Same contract (and identical output) as `sc.proveActive`.
pub fn proveActive(
    acc: ?*const Accel,
    comptime NF: usize,
    comptime terms: []const sc.Term,
    a: std.mem.Allocator,
    pool: *f.Pool,
    tr: *Transcript,
    claim: QM31,
    factors_in: [NF][]QM31,
    active_in: usize,
) !sc.ProveResult {
    const A = acc orelse return sc.proveActive(NF, terms, a, pool, tr, claim, factors_in, active_in);
    const len0 = factors_in[0].len;
    const deg = comptime termDegree(terms);
    if (NF > 4 or terms.len > 4 or deg > 3 or len0 < 2 or @min(len0 / 2, active_in) < A.sc_min_work)
        return sc.proveActive(NF, terms, a, pool, tr, claim, factors_in, active_in);
    const s = (try A.sc_begin(A.ctx, &factors_in, terms, @min(active_in, len0))) orelse
        return sc.proveActive(NF, terms, a, pool, tr, claim, factors_in, active_in);
    var done = false;
    errdefer if (!done) A.sc_abort(A.ctx, s);

    const n = f.log2Exact(len0);
    var head_rounds: [64]sc.RoundPoly = undefined;
    var head_point: [64]QM31 = undefined;
    var k: usize = 0;
    var cur_claim = claim;
    var len = len0;
    var active = @min(active_in, len0);
    var r_prev: ?QM31 = null;
    while (k < n) {
        const half = len / 2;
        const work = @min(half, active);
        if (work < A.sc_min_work) break;
        const g = try A.sc_round(A.ctx, s, r_prev);
        var sums: [sc.MAX_DEG + 1]QM31 = .{ g[0], QM31.zero(), g[1], g[2] };
        sums[1] = cur_claim.sub(sums[0]);
        var rp = sc.RoundPoly{ .evals = [_]QM31{QM31.zero()} ** sc.MAX_DEG };
        rp.evals[0] = sums[0];
        for (2..deg + 1) |t| rp.evals[t - 1] = sums[t];
        tr.mixFelts(rp.evals[0..deg]);
        head_rounds[k] = rp;
        const r = tr.draw();
        head_point[k] = r;
        cur_claim = sc.interpolateAt(sums[0 .. deg + 1], r);
        r_prev = r;
        len = half;
        active = work;
        k += 1;
    }
    std.debug.assert(r_prev != null);
    done = true;
    try A.sc_finish(A.ctx, s, r_prev.?);

    var tail_f: [NF][]QM31 = undefined;
    inline for (0..NF) |j| tail_f[j] = factors_in[j][0..len];
    const tail = try sc.proveActive(NF, terms, a, pool, tr, cur_claim, tail_f, active);
    defer {
        a.free(tail.proof.rounds);
        a.free(tail.point);
    }
    const rounds = try a.alloc(sc.RoundPoly, n);
    errdefer a.free(rounds);
    const point = try a.alloc(QM31, n);
    @memcpy(rounds[0..k], head_rounds[0..k]);
    @memcpy(rounds[k..], tail.proof.rounds);
    @memcpy(point[0..k], head_point[0..k]);
    @memcpy(point[k..], tail.point);
    return .{ .proof = .{ .rounds = rounds, .deg = deg }, .point = point, .finals = tail.finals };
}
