//! Univariate IOP binding a multilinear evaluation claim to a committed
//! circle-domain column (Papini-Haboeck, eprint 2023/1284, Section 5.1).
//!
//! Adapted from upstream Stwo `crates/examples/src/xor/gkr_lookups/mle_eval.rs`
//! at 826591c (read only, never executed). The eq column convention is the
//! upstream one: `c` stored in bit-reversed circle-domain order satisfies
//! `c[p] = eq(bits_msb(p), r)` at storage index `p`.
//!
//! Experimental `WGKR-LS-RANGE-v0` material only. No default protocol uses it.
const std = @import("std");
const core = @import("stwo_core");
const QM31 = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const circle = core.circle;
const CirclePointQM31 = circle.CirclePointQM31;
const CirclePointM31 = circle.CirclePointM31;
const Coset = circle.Coset;
const canonic = core.poly.circle.canonic;
const constraints = core.constraints;
const utils = core.utils;

pub const MAX_VARIABLES: usize = 30;

pub const Error = error{
    EmptyEvalPoint,
    TooManyVariables,
    /// A coordinate in {0, 1}: the carry quotients divide by it. Completeness only.
    DegenerateEvalPoint,
    DivisionByZero,
};

/// Lagrange kernel over the boolean hypercube.
pub fn eqFor(comptime F: type, x: []const F, y: []const F) F {
    std.debug.assert(x.len == y.len);
    var out = F.one();
    for (x, y) |a, b| {
        out = out.mul(a.mul(b).add(F.one().sub(a).mul(F.one().sub(b))));
    }
    return out;
}

pub fn eq(x: []const QM31, y: []const QM31) QM31 {
    return eqFor(QM31, x, y);
}

/// Verifier-side succinct data of an MLE evaluation point.
pub const MleEvalPoint = MleEvalPointFor(QM31);

pub fn MleEvalPointFor(comptime F: type) type {
    return struct {
        n: usize,
        p: [MAX_VARIABLES]F,
        /// eq(0^n, p)
        eq0: F,
        /// eq(1^n, p)
        eq1: F,
        /// Half-coset-0 carry quotients; index n-1 includes the wrap factor.
        hc0: [MAX_VARIABLES]F,
        /// Inverses of `hc0`.
        hc1: [MAX_VARIABLES]F,

        pub fn init(point: []const F) Error!@This() {
            if (point.len == 0) return error.EmptyEvalPoint;
            if (point.len > MAX_VARIABLES) return error.TooManyVariables;
            var out: @This() = undefined;
            out.n = point.len;
            @memset(&out.p, F.zero());
            @memcpy(out.p[0..point.len], point);
            if (F == QM31) for (point) |v| {
                if (v.isZero() or v.eql(F.one())) return error.DegenerateEvalPoint;
            };
            out.eq0 = F.one();
            out.eq1 = F.one();
            for (point) |v| {
                out.eq0 = out.eq0.mul(F.one().sub(v));
                out.eq1 = out.eq1.mul(v);
            }
            // eq((1^i, 0), p[0..i+1]) / eq((0^i, 1), p[0..i+1])
            var prefix_ones = F.one();
            var prefix_zeros = F.one();
            for (point, 0..) |v, i| {
                const num = prefix_ones.mul(F.one().sub(v));
                const den = prefix_zeros.mul(v);
                out.hc0[i] = try divideFor(F, num, den);
                prefix_ones = prefix_ones.mul(v);
                prefix_zeros = prefix_zeros.mul(F.one().sub(v));
            }
            const last = point[point.len - 1];
            const wrap = try divideFor(F, last, F.one().sub(last));
            out.hc0[point.len - 1] = out.hc0[point.len - 1].mul(wrap);
            for (0..point.len) |i| {
                out.hc1[i] = try inverseFor(F, out.hc0[i]);
            }
            return out;
        }

        pub fn slice(self: *const @This()) []const F {
            return self.p[0..self.n];
        }
    };
}

/// Storage index (bit-reversed circle-domain order) of coset index `k`.
pub fn storageIndex(coset_index: usize, log_size: u32) usize {
    return utils.bitReverseIndex(utils.cosetIndexToCircleDomainIndex(coset_index, log_size), log_size);
}

/// `out[i] = eq(bits_msb(i), r)`; `r[0]` is the most significant bit.
pub fn genEqEvals(allocator: std.mem.Allocator, r: []const QM31) ![]QM31 {
    const n = @as(usize, 1) << @intCast(r.len);
    const out = try allocator.alloc(QM31, n);
    out[0] = QM31.one();
    var len: usize = 1;
    for (r) |ri| {
        var i = len;
        while (i > 0) {
            i -= 1;
            const v = out[i];
            out[2 * i + 1] = v.mul(ri);
            out[2 * i] = v.mul(QM31.one().sub(ri));
        }
        len *= 2;
    }
    return out;
}

/// Carry quotient column in storage order: for every coset index `k`,
/// `c(k) = c(k + 2) * q(k)` cyclically within each half coset.
pub fn genCarryQuotientCol(allocator: std.mem.Allocator, point: *const MleEvalPoint) ![]QM31 {
    const log_size: u32 = @intCast(point.n);
    const n = @as(usize, 1) << @intCast(log_size);
    const out = try allocator.alloc(QM31, n);
    for (0..n / 2) |i| {
        const t: usize = @ctz(~i);
        out[storageIndex(2 * i, log_size)] = point.hc0[t];
        out[storageIndex(2 * i + 1, log_size)] = point.hc1[t];
    }
    return out;
}

fn efFor(comptime F: type, p: CirclePointM31) circle.CirclePoint(F) {
    return .{ .x = F.fromBase(p.x), .y = F.fromBase(p.y) };
}

/// Lagrange selector of the first coset point, at an arbitrary point.
pub fn evalIsFirstFor(comptime F: type, coset: Coset, p: circle.CirclePoint(F)) Error!F {
    const num = constraints.cosetVanishing(F, coset, p);
    const pv = constraints.pointVanishing(F, efFor(F, coset.initial), p) catch return error.DivisionByZero;
    const size = M31.fromU64(@as(u64, 1) << @intCast(coset.log_size));
    return divideFor(F, num, pv.mul(F.fromBase(size)));
}

/// Polynomial that is 1 every `2^log_step` coset points and 0 elsewhere on the coset.
fn evalStepSelectorFor(comptime F: type, coset: Coset, log_step: u32, p_in: circle.CirclePoint(F)) Error!F {
    if (log_step == 0) return F.one();
    std.debug.assert(log_step >= 2 and log_step <= coset.log_size);
    var p = p_in.sub(efFor(F, coset.initial));
    var ys: [MAX_VARIABLES + 1]F = undefined;
    for (0..coset.log_size) |i| {
        ys[i] = p.y;
        p = p.double();
    }
    // Reverse and truncate to `log_step` values.
    var v: [MAX_VARIABLES + 1]F = undefined;
    for (0..log_step) |i| v[i] = ys[coset.log_size - 1 - i];
    var inv: [MAX_VARIABLES + 1]F = undefined;
    for (0..log_step) |i| inv[i] = try inverseFor(F, v[i]);
    const dbl = v[0].mul(inv[1]).square();
    var sum = F.zero();
    for (1..log_step) |i| sum = sum.add(inv[i]);
    const numer = dbl.add(v[0].mul(sum.add(sum)));
    const scale = M31.fromU64(@as(u64, 1) << @intCast(log_step + 1));
    return divideBaseFor(F, numer, scale);
}

fn evalStepSelectorWithOffsetFor(comptime F: type, coset: Coset, offset: usize, log_step: u32, p: circle.CirclePoint(F)) Error!F {
    const shift = coset.step.mul(offset);
    return evalStepSelectorFor(F, coset, log_step, p.sub(efFor(F, shift)));
}

/// Succinct evaluation of the carry quotient column's interpolant at `p`
/// (a point already folded to the trace coset of size `2^n`).
pub fn evalCarryQuotientFor(comptime F: type, point: *const MleEvalPointFor(F), p: circle.CirclePoint(F)) Error!F {
    const log_size: u32 = @intCast(point.n);
    const coset = canonic.CanonicCoset.new(log_size).coset();
    var acc = F.zero();
    if (point.n >= 2) {
        for (0..point.n - 1) |variable_i| {
            const log_step: u32 = @intCast(variable_i + 2);
            const offset = (@as(usize, 1) << @intCast(log_step - 1)) - 2;
            const s0 = try evalStepSelectorWithOffsetFor(F, coset, offset, log_step, p);
            const s1 = try evalStepSelectorWithOffsetFor(F, coset, offset + 1, log_step, p);
            acc = acc.add(s0.mul(point.hc0[variable_i])).add(s1.mul(point.hc1[variable_i]));
        }
    }
    const last0 = try evalIsFirstFor(F, coset, p.add(efFor(F, coset.step.double())));
    const first1 = try evalIsFirstFor(F, coset, p.add(efFor(F, coset.step)));
    acc = acc.add(point.hc0[point.n - 1].mul(last0)).add(point.hc1[point.n - 1].mul(first1));
    return acc;
}

/// `is_first` and `is_second` (`is_first` shifted by one coset step) at `p`.
pub fn evalAnchorsFor(comptime F: type, log_size: u32, p: circle.CirclePoint(F)) Error![2]F {
    const coset = canonic.CanonicCoset.new(log_size).coset();
    return .{
        try evalIsFirstFor(F, coset, p),
        try evalIsFirstFor(F, coset, p.sub(efFor(F, coset.step))),
    };
}

pub fn evalIsFirst(coset: Coset, p: CirclePointQM31) Error!QM31 {
    return evalIsFirstFor(QM31, coset, p);
}
pub fn evalCarryQuotient(point: *const MleEvalPoint, p: CirclePointQM31) Error!QM31 {
    return evalCarryQuotientFor(QM31, point, p);
}
pub fn evalAnchors(log: u32, p: CirclePointQM31) Error![2]QM31 {
    return evalAnchorsFor(QM31, log, p);
}
fn inverseFor(comptime F: type, value: F) Error!F {
    if (F == QM31) return value.inv() catch return error.DivisionByZero;
    return value.inv();
}
fn divideFor(comptime F: type, lhs: F, rhs: F) Error!F {
    if (F == QM31) return lhs.div(rhs) catch return error.DivisionByZero;
    return lhs.mul(try inverseFor(F, rhs));
}
fn divideBaseFor(comptime F: type, value: F, base: M31) Error!F {
    if (F == QM31) return value.divM31(base) catch return error.DivisionByZero;
    return value.mul(F.fromBase(base.inv() catch return error.DivisionByZero));
}

/// Multilinear extension of `values` (index bits MSB-first) at `r`.
pub fn mleEval(allocator: std.mem.Allocator, values: []const QM31, r: []const QM31) !QM31 {
    const weights = try genEqEvals(allocator, r);
    defer allocator.free(weights);
    var acc = QM31.zero();
    for (values, weights) |v, w| acc = acc.add(v.mul(w));
    return acc;
}

fn testPoint(seed: u32, n: usize, out: []QM31) void {
    var ch = core.channel.blake2s.Blake2sChannel{};
    ch.mixU32s(&.{ 0x4d4c4550, seed });
    for (out[0..n]) |*v| v.* = ch.drawSecureFelt();
}

test "logup-gkr mle point: eq column satisfies anchors and carry recurrence" {
    const a = std.testing.allocator;
    var log: u32 = 2;
    while (log <= 12) : (log += 1) {
        var buf: [MAX_VARIABLES]QM31 = undefined;
        testPoint(log, log, &buf);
        const point = try MleEvalPoint.init(buf[0..log]);
        const c = try genEqEvals(a, point.slice());
        defer a.free(c);
        const q = try genCarryQuotientCol(a, &point);
        defer a.free(q);
        const n = @as(usize, 1) << @intCast(log);
        try std.testing.expect(c[storageIndex(0, log)].eql(point.eq0));
        try std.testing.expect(c[storageIndex(1, log)].eql(point.eq1));
        for (0..n) |k| {
            const cur = c[storageIndex(k, log)];
            const next = c[storageIndex((k + 2) % n, log)];
            try std.testing.expect(cur.eql(next.mul(q[storageIndex(k, log)])));
        }
        // eq evals equal the MLE kernel at every storage index.
        for (0..n) |p| {
            var bits: [MAX_VARIABLES]QM31 = undefined;
            for (0..log) |b| bits[b] = if ((p >> @intCast(log - 1 - b)) & 1 == 1) QM31.one() else QM31.zero();
            try std.testing.expect(c[p].eql(eq(bits[0..log], point.slice())));
        }
    }
}

test "logup-gkr mle point: any single eq cell mutation violates the constraints" {
    const a = std.testing.allocator;
    const log: u32 = 6;
    var buf: [MAX_VARIABLES]QM31 = undefined;
    testPoint(99, log, &buf);
    const point = try MleEvalPoint.init(buf[0..log]);
    const c = try genEqEvals(a, point.slice());
    defer a.free(c);
    const q = try genCarryQuotientCol(a, &point);
    defer a.free(q);
    const n = @as(usize, 1) << @intCast(log);
    for (0..n) |cell| {
        const saved = c[cell];
        c[cell] = saved.add(QM31.one());
        var violated = false;
        for (0..n) |k| {
            const s = storageIndex(k, log);
            const cur = c[s];
            const anchor = if (k == 0) cur.sub(point.eq0) else if (k == 1) cur.sub(point.eq1) else QM31.zero();
            const rec = cur.sub(c[storageIndex((k + 2) % n, log)].mul(q[s]));
            if (!anchor.isZero() or !rec.isZero()) violated = true;
        }
        try std.testing.expect(violated);
        c[cell] = saved;
    }
}

test "logup-gkr mle point: succinct carry quotient and anchors match interpolation" {
    const a = std.testing.allocator;
    const prover_circle = @import("stwo_prover_engine").poly.circle;
    var log: u32 = 2;
    while (log <= 10) : (log += 1) {
        var buf: [MAX_VARIABLES]QM31 = undefined;
        testPoint(1000 + log, log, &buf);
        const point = try MleEvalPoint.init(buf[0..log]);
        const q = try genCarryQuotientCol(a, &point);
        defer a.free(q);
        const n = @as(usize, 1) << @intCast(log);
        const domain = canonic.CanonicCoset.new(log).circleDomain();
        var ch = core.channel.blake2s.Blake2sChannel{};
        ch.mixU32s(&.{log});
        const oods = circle.randomSecureFieldPoint(&ch);
        var coords: [4]QM31 = undefined;
        const tmp = try a.alloc(M31, n);
        defer a.free(tmp);
        for (0..4) |coord| {
            for (q, tmp) |v, *o| o.* = v.toM31Array()[coord];
            const ev = try prover_circle.evaluation.CircleEvaluation.init(domain, tmp);
            coords[coord] = try ev.evalAtPoint(a, oods);
        }
        const interpolated = QM31.fromPartialEvals(coords);
        try std.testing.expect(interpolated.eql(try evalCarryQuotient(&point, oods)));

        // is_first / is_second anchors.
        @memset(tmp, M31.zero());
        tmp[storageIndex(0, log)] = M31.one();
        const first = try (try prover_circle.evaluation.CircleEvaluation.init(domain, tmp)).evalAtPoint(a, oods);
        @memset(tmp, M31.zero());
        tmp[storageIndex(1, log)] = M31.one();
        const second = try (try prover_circle.evaluation.CircleEvaluation.init(domain, tmp)).evalAtPoint(a, oods);
        const anchors = try evalAnchors(log, oods);
        try std.testing.expect(first.eql(anchors[0]));
        try std.testing.expect(second.eql(anchors[1]));
    }
}

test "logup-gkr mle point: degenerate coordinates are rejected" {
    var buf = [_]QM31{ QM31.fromU32Unchecked(5, 1, 0, 0), QM31.one(), QM31.fromU32Unchecked(7, 0, 3, 0) };
    try std.testing.expectError(error.DegenerateEvalPoint, MleEvalPoint.init(&buf));
    buf[1] = QM31.zero();
    try std.testing.expectError(error.DegenerateEvalPoint, MleEvalPoint.init(&buf));
}
