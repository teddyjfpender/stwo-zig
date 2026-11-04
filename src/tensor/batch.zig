//! Fast prover for the witness batch sumcheck  sum_x F(x) E(x).
//!
//! F is the committed witness table (small integers, i.e. base-field values);
//! E = sum_c gamma_c eq(z_c, .) restricted to tensor c's block. The protocol is
//! exactly `sumcheck.proveActive(2, {F*E})` (same round polynomials, same
//! transcript); this module only changes how the prover computes them:
//!
//!  * E is accumulated in place (one pass per claim, no full-size eq table);
//!  * round 0 runs with F in the base field (M31 x QM31 products, no QM31
//!    copy of the whole witness table) and folds F straight into a half-size
//!    QM31 buffer; later rounds use the generic (packed) sumcheck kernels.
const std = @import("std");
const f = @import("field.zig");
const sc = @import("sumcheck.zig");
const Transcript = @import("transcript.zig").Transcript;

const QM31 = f.QM31;
const M31 = f.M31;
const PQ = f.PackedQM31;
const PM = f.PackedM31;
const LANES = f.PACK_WIDTH;

const T_PROD2 = [_]sc.Term{.{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1 } }};

/// dst[i] += scale * eq(point, i) for i in [0, 2^point.len).
pub fn addEqScaled(a: std.mem.Allocator, pool: *f.Pool, dst: []QM31, point: []const QM31, scale: QM31) !void {
    return eqScaledInto(a, pool, dst, point, scale, true);
}

/// dst[i] (+)= scale * eq(point, i); `accumulate = false` overwrites dst
/// (first touch, no read of uninitialised memory).
pub fn eqScaledInto(a: std.mem.Allocator, pool: *f.Pool, dst: []QM31, point: []const QM31, scale: QM31, accumulate: bool) !void {
    const n = point.len;
    std.debug.assert(dst.len == (@as(usize, 1) << @intCast(n)));
    const top: usize = @min(n, 8);
    const prefix = try f.eqTable(a, point[0..top], scale);
    defer a.free(prefix);
    const suffix = try f.eqTable(a, point[top..], QM31.one());
    defer a.free(suffix);
    const Ctx = struct { dst: []QM31, prefix: []const QM31, suffix: []const QM31, acc: bool };
    const ctx = Ctx{ .dst = dst, .prefix = prefix, .suffix = suffix, .acc = accumulate };
    const min_chunk: usize = @max(1, (@as(usize, 1) << 14) / suffix.len);
    pool.parallelFor(prefix.len, min_chunk, &ctx, struct {
        fn run(c: *const Ctx, s: usize, e: usize) void {
            const S = c.suffix.len;
            for (s..e) |hi| {
                const base = hi * S;
                const p = c.prefix[hi];
                var lo: usize = 0;
                if (LANES > 1 and S >= LANES) {
                    const pp = PQ.splat(p);
                    while (lo + LANES <= S) : (lo += LANES) {
                        const sv = PQ.fromLanes(c.suffix[lo..][0..LANES].*);
                        var r = pp.mul(sv);
                        if (c.acc) r = r.add(PQ.fromLanes(c.dst[base + lo ..][0..LANES].*));
                        inline for (0..LANES) |l| c.dst[base + lo + l] = r.lane(l);
                    }
                }
                while (lo < S) : (lo += 1) {
                    const v = p.mul(c.suffix[lo]);
                    c.dst[base + lo] = if (c.acc) c.dst[base + lo].add(v) else v;
                }
            }
        }
    }.run);
}

pub const RegionClaim = struct { point: []const QM31, gamma: QM31 };

/// dst[i] = sum_c gamma_c * eq(point_c, i) in one write pass (every point must
/// have log2(dst.len) coordinates). Claims at identical points are merged
/// (gammas added) first; with no claims dst is zeroed.
pub fn fillRegion(a: std.mem.Allocator, pool: *f.Pool, dst: []QM31, claims_in: []const RegionClaim) !void {
    const n = f.log2Exact(dst.len);
    var merged: std.ArrayList(RegionClaim) = .empty;
    defer merged.deinit(a);
    outer: for (claims_in) |c| {
        std.debug.assert(c.point.len == n);
        for (merged.items) |*m| {
            var same = true;
            for (m.point, c.point) |x, y| same = same and x.eql(y);
            if (same) {
                m.gamma = m.gamma.add(c.gamma);
                continue :outer;
            }
        }
        try merged.append(a, c);
    }
    const m = merged.items.len;
    if (m == 0) {
        const Z = struct { dst: []QM31 };
        const z = Z{ .dst = dst };
        pool.parallelFor(dst.len, 1 << 14, &z, struct {
            fn run(c: *const Z, s: usize, e: usize) void {
                @memset(c.dst[s..e], QM31.zero());
            }
        }.run);
        return;
    }
    const top: usize = @min(n, 8);
    const P = @as(usize, 1) << @intCast(top);
    const S = dst.len / P;
    const prefixes = try a.alloc(QM31, m * P);
    defer a.free(prefixes);
    const suffixes = try a.alloc(QM31, m * S);
    defer a.free(suffixes);
    for (merged.items, 0..) |c, ci| {
        const pre = try f.eqTable(a, c.point[0..top], c.gamma);
        defer a.free(pre);
        @memcpy(prefixes[ci * P ..][0..P], pre);
        const suf = try f.eqTable(a, c.point[top..], QM31.one());
        defer a.free(suf);
        @memcpy(suffixes[ci * S ..][0..S], suf);
    }
    const Ctx = struct { dst: []QM31, pre: []const QM31, suf: []const QM31, m: usize, P: usize, S: usize };
    const ctx = Ctx{ .dst = dst, .pre = prefixes, .suf = suffixes, .m = m, .P = P, .S = S };
    // work items: (prefix index, suffix block) pairs so small prefixes still parallelise
    const SB: usize = @min(S, 1024);
    const n_items = P * (S / SB);
    pool.parallelFor(n_items, @max(1, (@as(usize, 1) << 14) / SB), &ctx, struct {
        fn run(c: *const Ctx, s: usize, e: usize) void {
            const sb = @min(c.S, 1024);
            const per = c.S / sb;
            for (s..e) |item| {
                const hi = item / per;
                const lo0 = (item % per) * sb;
                const base = hi * c.S;
                var lo = lo0;
                if (LANES > 1 and sb >= LANES) {
                    while (lo + LANES <= lo0 + sb) : (lo += LANES) {
                        var acc = PQ.splat(c.pre[hi]).mul(PQ.fromLanes(c.suf[lo..][0..LANES].*));
                        for (1..c.m) |ci| {
                            acc = acc.add(PQ.splat(c.pre[ci * c.P + hi]).mul(PQ.fromLanes(c.suf[ci * c.S + lo ..][0..LANES].*)));
                        }
                        inline for (0..LANES) |l| c.dst[base + lo + l] = acc.lane(l);
                    }
                }
                while (lo < lo0 + sb) : (lo += 1) {
                    var acc = c.pre[hi].mul(c.suf[lo]);
                    for (1..c.m) |ci| acc = acc.add(c.pre[ci * c.P + hi].mul(c.suf[ci * c.S + lo]));
                    c.dst[base + lo] = acc;
                }
            }
        }
    }.run);
}

inline fn m31FromI32(x: anytype) M31 {
    return f.fromI32(@as(i32, x));
}

/// LANES entries of an i32 or i8 slice as packed canonical M31 (i8 is widened).
inline fn packedFromI32(src: anytype, at: usize) PM {
    const Elem = @typeInfo(@TypeOf(src)).pointer.child;
    const raw: @Vector(LANES, Elem) = src[at..][0..LANES].*;
    const v: @Vector(LANES, i32) = raw;
    const u: PM = @bitCast(v);
    const p: PM = @splat(f.P);
    return @select(u32, v < @as(@Vector(LANES, i32), @splat(0)), u +% p, u);
}

fn R0Ctx(comptime T: type) type {
    return struct {
        F: []const T,
        E: []const QM31,
        half: usize,
        active: usize,
        partial: [][3]QM31,
        chunk: usize,
    };
}

fn round0Chunk(comptime T: type, c: *const R0Ctx(T), s: usize, e: usize) void {
    var s0 = QM31.zero();
    var s2 = QM31.zero();
    var x = s;
    const hi_end = if (c.active > c.half) @max(s, @min(e, c.active - c.half)) else s;
    if (LANES > 1) {
        var p0 = PQ.zero();
        var p2 = PQ.zero();
        while (x + LANES <= hi_end) : (x += LANES) {
            const flo = packedFromI32(c.F, x);
            const fhi = packedFromI32(c.F, x + c.half);
            const elo = PQ.fromLanes(c.E[x..][0..LANES].*);
            const ehi = PQ.fromLanes(c.E[x + c.half ..][0..LANES].*);
            p0 = p0.add(elo.mulBase(flo));
            const f2 = f.subPackedM31(f.addPackedM31(fhi, fhi), flo);
            const e2 = ehi.add(ehi).sub(elo);
            p2 = p2.add(e2.mulBase(f2));
        }
        while (x < hi_end) : (x += 1) {
            const flo = m31FromI32(c.F[x]);
            const fhi = m31FromI32(c.F[x + c.half]);
            const elo = c.E[x];
            const ehi = c.E[x + c.half];
            s0 = s0.add(elo.mulM31(flo));
            s2 = s2.add(ehi.add(ehi).sub(elo).mulM31(fhi.add(fhi).sub(flo)));
        }
        // high partner is an implicit zero: s(0) and s(2) both gain E*F ((-E)(-F) = EF)
        var pz = PQ.zero();
        while (x + LANES <= e) : (x += LANES) {
            pz = pz.add(PQ.fromLanes(c.E[x..][0..LANES].*).mulBase(packedFromI32(c.F, x)));
        }
        p0 = p0.add(pz);
        p2 = p2.add(pz);
        inline for (0..LANES) |l| {
            s0 = s0.add(p0.lane(l));
            s2 = s2.add(p2.lane(l));
        }
    }
    while (x < e) : (x += 1) {
        const has_hi = x + c.half < c.active;
        const flo = m31FromI32(c.F[x]);
        const fhi = if (has_hi) m31FromI32(c.F[x + c.half]) else M31.zero();
        const elo = c.E[x];
        const ehi = if (has_hi) c.E[x + c.half] else QM31.zero();
        s0 = s0.add(elo.mulM31(flo));
        s2 = s2.add(ehi.add(ehi).sub(elo).mulM31(fhi.add(fhi).sub(flo)));
    }
    c.partial[s / c.chunk] = .{ s0, QM31.zero(), s2 };
}

fn F0Ctx(comptime T: type) type {
    return struct {
        F: []const T,
        E: []QM31,
        /// may alias E[half..] (see fold0Chunk's read-before-write order)
        Fq: []QM31,
        half: usize,
        active: usize,
        r: QM31,
    };
}

fn fold0Chunk(comptime T: type, c: *const F0Ctx(T), s: usize, e: usize) void {
    var x = s;
    const hi_end = if (c.active > c.half) @max(s, @min(e, c.active - c.half)) else s;
    if (LANES > 1) {
        const rp = PQ.splat(c.r);
        while (x + LANES <= hi_end) : (x += LANES) {
            const flo = packedFromI32(c.F, x);
            const fhi = packedFromI32(c.F, x + c.half);
            const fv = rp.mulBase(f.subPackedM31(fhi, flo)).add(PQ.fromBase(flo));
            const elo = PQ.fromLanes(c.E[x..][0..LANES].*);
            const ehi = PQ.fromLanes(c.E[x + c.half ..][0..LANES].*);
            const ev = elo.add(rp.mul(ehi.sub(elo)));
            inline for (0..LANES) |l| {
                c.Fq[x + l] = fv.lane(l);
                c.E[x + l] = ev.lane(l);
            }
        }
        while (x < hi_end) : (x += 1) {
            const flo = m31FromI32(c.F[x]);
            const fhi = m31FromI32(c.F[x + c.half]);
            const ehi = c.E[x + c.half]; // read before Fq[x] (may alias E[x + half]) is written
            c.E[x] = c.E[x].add(c.r.mul(ehi.sub(c.E[x])));
            c.Fq[x] = c.r.mulM31(fhi.sub(flo)).add(QM31.fromBase(flo));
        }
        // high partner is an implicit zero: v' = v + r (0 - v) = (1 - r) v
        const omr = PQ.splat(QM31.one().sub(c.r));
        while (x + LANES <= e) : (x += LANES) {
            const fv = omr.mulBase(packedFromI32(c.F, x));
            const ev = omr.mul(PQ.fromLanes(c.E[x..][0..LANES].*));
            inline for (0..LANES) |l| {
                c.Fq[x + l] = fv.lane(l);
                c.E[x + l] = ev.lane(l);
            }
        }
    }
    while (x < e) : (x += 1) {
        const has_hi = x + c.half < c.active;
        const flo = m31FromI32(c.F[x]);
        const fhi = if (has_hi) m31FromI32(c.F[x + c.half]) else M31.zero();
        const ehi = if (has_hi) c.E[x + c.half] else QM31.zero();
        c.E[x] = c.E[x].add(c.r.mul(ehi.sub(c.E[x])));
        c.Fq[x] = c.r.mulM31(fhi.sub(flo)).add(QM31.fromBase(flo));
    }
}

/// Same transcript and result as
///   sc.proveActive(2, {F*E}, claim, {F as QM31, E}, active).
/// `E` (length F.len) is consumed; entries at index >= active are ignored.
pub fn proveBaseTimesExt(
    a: std.mem.Allocator,
    pool: *f.Pool,
    tr: *Transcript,
    claim: QM31,
    F: []const i32,
    E: []QM31,
    active_in: usize,
) !sc.ProveResult {
    return proveBaseTimesExtT(i32, a, pool, tr, claim, F, E, active_in);
}

/// proveBaseTimesExt over an i32 or i8 base table (i8: the committed weight
/// table itself, without a widened copy).
pub fn proveBaseTimesExtT(
    comptime T: type,
    a: std.mem.Allocator,
    pool: *f.Pool,
    tr: *Transcript,
    claim: QM31,
    F: []const T,
    E: []QM31,
    active_in: usize,
) !sc.ProveResult {
    std.debug.assert(F.len == E.len);
    const len = F.len;
    const n = f.log2Exact(len);
    const active = @min(active_in, len);
    if (n == 0) {
        const Fq = try a.alloc(QM31, len);
        defer a.free(Fq);
        for (F, Fq) |v, *o| o.* = QM31.fromBase(m31FromI32(v));
        return sc.proveActive(2, &T_PROD2, a, pool, tr, claim, .{ Fq, E }, active);
    }
    const half = len / 2;
    const work = @min(half, active);

    // --- round 0 (F in the base field)
    var sums = [3]QM31{ QM31.zero(), QM31.zero(), QM31.zero() };
    if (work > 0) {
        const target = pool.n_threads * 4;
        var chunk = (work + target - 1) / target;
        if (chunk < 4096) chunk = 4096;
        if (chunk > work) chunk = work;
        const n_chunks = (work + chunk - 1) / chunk;
        const partial = try a.alloc([3]QM31, n_chunks);
        defer a.free(partial);
        const ctx = R0Ctx(T){ .F = F, .E = E, .half = half, .active = active, .partial = partial, .chunk = chunk };
        if (n_chunks <= 1) {
            round0Chunk(T, &ctx, 0, work);
        } else {
            var wg: std.Thread.WaitGroup = .{};
            var s: usize = 0;
            while (s < work) : (s += chunk) pool.pool.spawnWg(&wg, struct {
                fn run(c: *const R0Ctx(T), lo: usize, hi: usize) void {
                    round0Chunk(T, c, lo, hi);
                }
            }.run, .{ &ctx, s, @min(work, s + chunk) });
            pool.pool.waitAndWork(&wg);
        }
        for (partial) |p| {
            sums[0] = sums[0].add(p[0]);
            sums[2] = sums[2].add(p[2]);
        }
    }
    sums[1] = claim.sub(sums[0]);
    const r0_evals = [2]QM31{ sums[0], sums[2] };
    tr.mixFelts(&r0_evals);
    const r0 = tr.draw();
    const claim1 = sc.interpolateAt(&sums, r0);

    // Fq lives in E's upper half: iteration x reads E[x + half] before writing
    // Fq[x] = E[half + x], and no other iteration touches that slot.
    const Fq = E[half..];
    const fctx = F0Ctx(T){ .F = F, .E = E, .Fq = Fq, .half = half, .active = active, .r = r0 };
    pool.parallelFor(work, 4096, &fctx, struct {
        fn run(c: *const F0Ctx(T), s: usize, e: usize) void {
            fold0Chunk(T, c, s, e);
        }
    }.run);

    // --- rounds 1.. (generic kernels)
    var rest = try sc.proveActive(2, &T_PROD2, a, pool, tr, claim1, .{ Fq, E[0..half] }, work);
    errdefer rest.deinit(a);
    const rounds = try a.alloc(sc.RoundPoly, n);
    errdefer a.free(rounds);
    const point = try a.alloc(QM31, n);
    rounds[0] = .{ .evals = [_]QM31{QM31.zero()} ** sc.MAX_DEG };
    rounds[0].evals[0] = sums[0];
    rounds[0].evals[1] = sums[2];
    @memcpy(rounds[1..], rest.proof.rounds);
    point[0] = r0;
    @memcpy(point[1..], rest.point);
    a.free(rest.proof.rounds);
    a.free(rest.point);
    return .{ .proof = .{ .rounds = rounds, .deg = 2 }, .point = point, .finals = rest.finals };
}

test "proveBaseTimesExt matches generic sumcheck exactly" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 3);
    defer pool.deinit();
    var prng = std.Random.DefaultPrng.init(11);
    const rnd = prng.random();
    for ([_]u32{ 0, 1, 3, 9, 14 }) |n| {
        const len = @as(usize, 1) << @intCast(n);
        for ([_]usize{ len, (len * 3 + 3) / 4, len / 2 + 1, 1 }) |active| {
            const F = try a.alloc(i32, len);
            defer a.free(F);
            const E = try a.alloc(QM31, len);
            defer a.free(E);
            const Fq = try a.alloc(QM31, len);
            defer a.free(Fq);
            const E2 = try a.alloc(QM31, len);
            defer a.free(E2);
            var claim = QM31.zero();
            for (0..len) |i| {
                F[i] = if (i < active) rnd.intRangeAtMost(i32, -(1 << 30), 1 << 30) else 0;
                E[i] = if (i < active) QM31.fromU32Unchecked(rnd.uintLessThan(u32, f.P), rnd.uintLessThan(u32, f.P), rnd.uintLessThan(u32, f.P), rnd.uintLessThan(u32, f.P)) else QM31.zero();
                Fq[i] = QM31.fromBase(f.fromI32(F[i]));
                E2[i] = E[i];
                claim = claim.add(Fq[i].mul(E[i]));
            }
            var t1 = Transcript.initDomain("b");
            var t2 = Transcript.initDomain("b");
            var r1 = try proveBaseTimesExt(a, &pool, &t1, claim, F, E, active);
            defer r1.deinit(a);
            var r2 = try sc.proveActive(2, &T_PROD2, a, &pool, &t2, claim, .{ Fq, E2 }, active);
            defer r2.deinit(a);
            try std.testing.expectEqual(r2.proof.rounds.len, r1.proof.rounds.len);
            for (r1.proof.rounds, r2.proof.rounds) |x, y| {
                try std.testing.expect(x.evals[0].eql(y.evals[0]));
                try std.testing.expect(x.evals[1].eql(y.evals[1]));
            }
            for (r1.point, r2.point) |x, y| try std.testing.expect(x.eql(y));
            for (r1.finals, r2.finals) |x, y| try std.testing.expect(x.eql(y));
            try std.testing.expect(t1.draw().eql(t2.draw()));
        }
    }
}

test "fillRegion matches summed eq tables (with merged duplicate points)" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 3);
    defer pool.deinit();
    for ([_]usize{ 0, 1, 5, 9, 12 }) |n| {
        var pts: [3][12]QM31 = undefined;
        for (0..3) |c| for (0..n) |i| {
            pts[c][i] = QM31.fromU32Unchecked(@intCast(i * 7 + 3 + c), @intCast(i + 1), 5, @intCast(i * i + c));
        };
        const gam = [4]QM31{ QM31.fromU32Unchecked(9, 8, 7, 6), QM31.fromU32Unchecked(1, 2, 3, 4), QM31.fromU32Unchecked(5, 0, 0, 1), QM31.fromU32Unchecked(11, 0, 2, 0) };
        // claims 0 and 3 share a point
        const cl = [_]RegionClaim{ .{ .point = pts[0][0..n], .gamma = gam[0] }, .{ .point = pts[1][0..n], .gamma = gam[1] }, .{ .point = pts[2][0..n], .gamma = gam[2] }, .{ .point = pts[0][0..n], .gamma = gam[3] } };
        const len = @as(usize, 1) << @intCast(n);
        const ref = try a.alloc(QM31, len);
        defer a.free(ref);
        @memset(ref, QM31.zero());
        for (cl) |c| try addEqScaled(a, &pool, ref, c.point, c.gamma);
        const dst = try a.alloc(QM31, len);
        defer a.free(dst);
        try fillRegion(a, &pool, dst, &cl);
        for (dst, ref) |d, r| try std.testing.expect(d.eql(r));
        try fillRegion(a, &pool, dst, &.{});
        for (dst) |d| try std.testing.expect(d.isZero());
    }
}

test "addEqScaled matches eqTable" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 3);
    defer pool.deinit();
    for ([_]usize{ 0, 1, 5, 9, 13 }) |n| {
        var pts: [13]QM31 = undefined;
        for (0..n) |i| pts[i] = QM31.fromU32Unchecked(@intCast(i * 7 + 3), @intCast(i + 1), 5, @intCast(i * i));
        const sc_ = QM31.fromU32Unchecked(9, 8, 7, 6);
        const ref = try f.eqTable(a, pts[0..n], sc_);
        defer a.free(ref);
        const dst = try a.alloc(QM31, ref.len);
        defer a.free(dst);
        for (dst, 0..) |*d, i| d.* = QM31.fromU32Unchecked(@intCast(i), 1, 2, 3);
        try addEqScaled(a, &pool, dst, pts[0..n], sc_);
        for (dst, ref, 0..) |d, r, i| try std.testing.expect(d.eql(r.add(QM31.fromU32Unchecked(@intCast(i), 1, 2, 3))));
    }
}

test "proveBaseTimesExtT(i8) equals the i32 path on the widened table" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 3);
    defer pool.deinit();
    var prng = std.Random.DefaultPrng.init(12);
    const rnd = prng.random();
    for ([_]u32{ 0, 1, 3, 9, 14 }) |n| {
        const len = @as(usize, 1) << @intCast(n);
        for ([_]usize{ len, (len * 3 + 3) / 4, len / 2 + 1, 1 }) |active| {
            const F8 = try a.alloc(i8, len);
            defer a.free(F8);
            const F = try a.alloc(i32, len);
            defer a.free(F);
            const E = try a.alloc(QM31, len);
            defer a.free(E);
            const E2 = try a.alloc(QM31, len);
            defer a.free(E2);
            var claim = QM31.zero();
            for (0..len) |i| {
                F8[i] = if (i < active) rnd.int(i8) else 0;
                F[i] = F8[i];
                E[i] = if (i < active) QM31.fromU32Unchecked(rnd.uintLessThan(u32, f.P), rnd.uintLessThan(u32, f.P), rnd.uintLessThan(u32, f.P), rnd.uintLessThan(u32, f.P)) else QM31.zero();
                E2[i] = E[i];
                claim = claim.add(QM31.fromBase(f.fromI32(F[i])).mul(E[i]));
            }
            var t1 = Transcript.initDomain("b8");
            var t2 = Transcript.initDomain("b8");
            var r1 = try proveBaseTimesExtT(i8, a, &pool, &t1, claim, F8, E, active);
            defer r1.deinit(a);
            var r2 = try proveBaseTimesExt(a, &pool, &t2, claim, F, E2, active);
            defer r2.deinit(a);
            try std.testing.expectEqual(r2.proof.rounds.len, r1.proof.rounds.len);
            for (r1.proof.rounds, r2.proof.rounds) |x, y| {
                try std.testing.expect(x.evals[0].eql(y.evals[0]));
                try std.testing.expect(x.evals[1].eql(y.evals[1]));
            }
            for (r1.point, r2.point) |x, y| try std.testing.expect(x.eql(y));
            for (r1.finals, r2.finals) |x, y| try std.testing.expect(x.eql(y));
            try std.testing.expect(t1.draw().eql(t2.draw()));
        }
    }
}
