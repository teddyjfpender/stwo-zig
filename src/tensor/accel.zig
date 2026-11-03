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
    /// Applies the last fold, copies the folded prefix of every factor into
    /// out[j][0 .. len] (len = current length) and releases the session.
    sc_finish: *const fn (ctx: *anyopaque, s: *anyopaque, r_last: QM31, out: []const []QM31) anyerror!void,
    /// Device-resident batch sumcheck factors: F = wtab (as QM31) and
    /// E = sum_c gamma_c eq(point_c, . - offset_c). Null = not handled.
    /// Integer matmul accumulators acc = X (T x K, i32) . W (K x N, i8) as i64.
    matmul_acc: ?*const fn (ctx: *anyopaque, a: std.mem.Allocator, x: []const i32, T: usize, wm: pcs.Matrix(i8)) anyerror!?[]i64 = null,
    /// MLE of an integer vector (length 2^point.len) at `point`.
    mle_eval_i32: ?*const fn (ctx: *anyopaque, values: []const i32, point: []const QM31) anyerror!?QM31 = null,
    /// Vectors shorter than this are evaluated on the CPU.
    mle_min_len: usize = 1 << 16,
    sc_begin_batch: ?*const fn (ctx: *anyopaque, wtab: []const i32, claims: []const BatchClaim, active: usize) anyerror!?*anyopaque = null,
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
    return deviceRounds(A, s, NF, terms, a, pool, tr, claim, len0, @min(active_in, len0), factors_in);
}

/// Device rounds while the work is large, then the CPU prover on the folded
/// prefix (written to `tail_out[j][0 .. len]`). Consumes the session.
fn deviceRounds(
    A: *const Accel,
    s: *anyopaque,
    comptime NF: usize,
    comptime terms: []const sc.Term,
    a: std.mem.Allocator,
    pool: *f.Pool,
    tr: *Transcript,
    claim: QM31,
    len0: usize,
    active0: usize,
    tail_out: [NF][]QM31,
) !sc.ProveResult {
    const deg = comptime termDegree(terms);
    var done = false;
    errdefer if (!done) A.sc_abort(A.ctx, s);

    const n = f.log2Exact(len0);
    var head_rounds: [64]sc.RoundPoly = undefined;
    var head_point: [64]QM31 = undefined;
    var k: usize = 0;
    var cur_claim = claim;
    var len = len0;
    var active = active0;
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
    if (r_prev == null) {
        // no device round ran (work below threshold): copy everything back
        done = true;
        A.sc_abort(A.ctx, s);
        return error.AccelNoRounds;
    }
    done = true;
    var tail_f: [NF][]QM31 = undefined;
    inline for (0..NF) |j| tail_f[j] = tail_out[j][0..len];
    try A.sc_finish(A.ctx, s, r_prev.?, &tail_f);

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

pub const BatchClaim = struct {
    /// offset of the claimed tensor in the witness table
    offset: usize,
    point: []const QM31,
    gamma: QM31,
};

const T_PROD2 = [_]sc.Term{.{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1 } }};

/// Claim-batching sumcheck: proves sum_x F(x) E(x) = batch_claim with
/// F = wtab (as QM31) and E = sum_c gamma_c eq(point_c, x - offset_c);
/// entries >= `active` are zero. Identical output on every path.
pub fn batchProve(
    acc: ?*const Accel,
    a: std.mem.Allocator,
    pool: *f.Pool,
    tr: *Transcript,
    wtab: []const i32,
    active: usize,
    claims: []const BatchClaim,
    batch_claim: QM31,
) !sc.ProveResult {
    const total = wtab.len;
    if (acc) |A| if (A.sc_begin_batch) |begin| if (total >= 2 and @min(total / 2, active) >= A.sc_min_work) {
        if (try begin(A.ctx, wtab, claims, @min(active, total))) |s| {
            const tail_len = @max(1, A.sc_min_work * 2);
            const tf = try a.alloc(QM31, 2 * @min(total, tail_len));
            defer a.free(tf);
            const half = tf.len / 2;
            return deviceRounds(A, s, 2, &T_PROD2, a, pool, tr, batch_claim, total, @min(active, total), .{ tf[0..half], tf[half..] });
        }
    };
    const E = try a.alloc(QM31, total);
    defer a.free(E);
    @memset(E, QM31.zero());
    for (claims) |c| {
        const eq = try f.eqTablePar(a, pool, c.point, c.gamma);
        defer a.free(eq);
        for (E[c.offset..][0..eq.len], eq) |*e, v| e.* = e.add(v);
    }
    const F = try a.alloc(QM31, total);
    defer a.free(F);
    const Ctx = struct { v: []const i32, out: []QM31 };
    const ctx = Ctx{ .v = wtab, .out = F };
    pool.parallelFor(total, 8192, &ctx, struct {
        fn run(c: *const Ctx, s: usize, e: usize) void {
            for (s..e) |i| c.out[i] = QM31.fromBase(f.fromI32(c.v[i]));
        }
    }.run);
    return proveActive(acc, 2, &T_PROD2, a, pool, tr, batch_claim, .{ F, E }, active);
}

/// Device matmul accumulators (X rows = 2^log_t); null = use the CPU kernel.
pub fn matmulAcc(acc: ?*const Accel, a: std.mem.Allocator, log_t: u32, x: []const i32, wm: pcs.Matrix(i8)) !?[]i64 {
    const A = acc orelse return null;
    const mm = A.matmul_acc orelse return null;
    return mm(A.ctx, a, x, @as(usize, 1) << @intCast(log_t), wm);
}

/// MLE of an integer vector at `point` (same value as `f.mleEvalI32`).
pub fn mleEvalI32(acc: ?*const Accel, a: std.mem.Allocator, values: []const i32, point: []const QM31) !QM31 {
    if (acc) |A| if (A.mle_eval_i32) |ev| if (values.len >= A.mle_min_len) {
        if (try ev(A.ctx, values, point)) |v| return v;
    };
    return f.mleEvalI32(a, values, point);
}
