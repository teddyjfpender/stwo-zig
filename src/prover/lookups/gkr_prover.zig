const std = @import("std");
const m31 = @import("../../core/fields/m31.zig");
const qm31 = @import("../../core/fields/qm31.zig");
const mle_mod = @import("mle.zig");
const utils = @import("utils.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const MleSecure = mle_mod.Mle(QM31);

pub const GkrProverError = error{
    InvalidK,
    DivisionByZero,
    ShapeMismatch,
};

/// Evaluations of `eq((0, x), y)` over the boolean hypercube.
pub const EqEvals = struct {
    y: []QM31,
    evals: MleSecure,

    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.y);
        self.evals.deinit(allocator);
        self.* = undefined;
    }

    pub fn ySlice(self: @This()) []const QM31 {
        return self.y;
    }

    pub fn at(self: @This(), index: usize) QM31 {
        return self.evals.evalsSlice()[index];
    }

    pub fn generate(allocator: std.mem.Allocator, y: []const QM31) !EqEvals {
        const y_owned = try allocator.dupe(QM31, y);
        errdefer allocator.free(y_owned);

        var evals = blk: {
            if (y.len == 0) {
                break :blk try MleSecure.initOwned(try allocator.dupe(QM31, &[_]QM31{QM31.one()}));
            }
            const v = QM31.one().sub(y[0]);
            break :blk try genEqEvals(allocator, y[1..], v);
        };
        errdefer evals.deinit(allocator);

        return .{
            .y = y_owned,
            .evals = evals,
        };
    }
};

/// Computes `r(t) = sum_x eq((t, x), y[-k:]) * p(t, x)` from evaluations of
/// `f(t) = sum_x eq(({0}^(n-k), 0, x), y) * p(t, x)`.
pub fn correctSumAsPolyInFirstVariable(
    allocator: std.mem.Allocator,
    f_at_0: QM31,
    f_at_2: QM31,
    claim: QM31,
    y: []const QM31,
    k: usize,
) (std.mem.Allocator.Error || GkrProverError)!utils.UnivariatePoly(QM31) {
    if (k == 0 or k > y.len) return GkrProverError.InvalidK;

    const n = y.len;
    const prefix_len = n - k + 1;
    const eq_prefix = try eqZerosPrefix(y[0..prefix_len]);
    const a_const = QM31.one().div(eq_prefix) catch return GkrProverError.DivisionByZero;

    const y_idx = y[n - k];
    const denom = QM31.one().sub(y_idx.add(y_idx));
    const b_const = QM31.one().sub(y_idx).div(denom) catch return GkrProverError.DivisionByZero;

    const eq_at_0 = QM31.one().sub(y_idx);

    const x_two = QM31.fromBase(M31.fromCanonical(2));
    const eq_at_2 = utils.eq(
        QM31,
        &[_]QM31{x_two},
        &[_]QM31{y_idx},
    ) catch return GkrProverError.ShapeMismatch;

    const r_at_0 = f_at_0.mul(eq_at_0).mul(a_const);
    const r_at_1 = claim.sub(r_at_0);
    const r_at_2 = f_at_2.mul(eq_at_2).mul(a_const);
    const r_at_b = QM31.zero();

    const xs = [_]QM31{ QM31.zero(), QM31.one(), x_two, b_const };
    const ys = [_]QM31{ r_at_0, r_at_1, r_at_2, r_at_b };
    return utils.UnivariatePoly(QM31).interpolateLagrange(allocator, xs[0..], ys[0..]) catch |err| switch (err) {
        utils.LookupUtilsError.ShapeMismatch => GkrProverError.ShapeMismatch,
        utils.LookupUtilsError.DivisionByZero => GkrProverError.DivisionByZero,
        else => err,
    };
}

fn genEqEvals(
    allocator: std.mem.Allocator,
    y: []const QM31,
    scale: QM31,
) !MleSecure {
    if (y.len == 0) {
        return try MleSecure.initOwned(try allocator.dupe(QM31, &[_]QM31{scale}));
    }

    var tail = try genEqEvals(allocator, y[1..], scale);
    defer tail.deinit(allocator);

    const tail_values = tail.evalsSlice();
    const out = try allocator.alloc(QM31, tail_values.len * 2);

    const eq0 = QM31.one().sub(y[0]);
    const eq1 = y[0];
    for (tail_values, 0..) |v, i| {
        out[i] = v.mul(eq0);
        out[i + tail_values.len] = v.mul(eq1);
    }

    return try MleSecure.initOwned(out);
}

fn eqZerosPrefix(y: []const QM31) GkrProverError!QM31 {
    var out = QM31.one();
    for (y) |yi| {
        out = out.mul(QM31.one().sub(yi));
    }
    if (out.isZero()) return GkrProverError.DivisionByZero;
    return out;
}

test "gkr prover: eq evals generation matches direct eq" {
    const alloc = std.testing.allocator;

    const y = [_]QM31{
        QM31.fromU32Unchecked(5, 0, 0, 0),
        QM31.fromU32Unchecked(7, 0, 0, 0),
        QM31.fromU32Unchecked(11, 0, 0, 0),
    };

    var eq_evals = try EqEvals.generate(alloc, y[0..]);
    defer eq_evals.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 1) << 2, eq_evals.evals.evalsSlice().len);

    const zero = QM31.zero();
    const one = QM31.one();
    const points = [_][2]QM31{
        .{ zero, zero },
        .{ zero, one },
        .{ one, zero },
        .{ one, one },
    };

    for (points) |point| {
        const got = try eq_evals.evals.evalAtPoint(alloc, point[0..]);
        const expected = try utils.eq(
            QM31,
            &[_]QM31{ zero, point[0], point[1] },
            y[0..],
        );
        try std.testing.expect(got.eql(expected));
    }
}

test "gkr prover: corrected sum polynomial interpolation" {
    const alloc = std.testing.allocator;

    const y = [_]QM31{
        QM31.fromU32Unchecked(3, 0, 0, 0),
        QM31.fromU32Unchecked(4, 0, 0, 0),
        QM31.fromU32Unchecked(7, 0, 0, 0),
    };
    const k: usize = 2;
    const n = y.len;
    const y_idx = y[n - k];

    const c0 = QM31.fromU32Unchecked(2, 0, 0, 0);
    const c1 = QM31.fromU32Unchecked(5, 0, 0, 0);
    const c2 = QM31.fromU32Unchecked(9, 0, 0, 0);
    const c3 = QM31.fromU32Unchecked(6, 0, 0, 0);

    const evalR = struct {
        fn at(t: QM31, c0_: QM31, c1_: QM31, c2_: QM31, c3_: QM31) QM31 {
            return c0_
                .add(c1_.mul(t))
                .add(c2_.mul(t.square()))
                .add(c3_.mul(t.square().mul(t)));
        }
    }.at;

    const zero = QM31.zero();
    const one = QM31.one();
    const two = QM31.fromBase(M31.fromCanonical(2));

    const prefix_len = n - k + 1;
    const eq_prefix = try eqZerosPrefix(y[0..prefix_len]);
    const a_const = QM31.one().div(eq_prefix) catch return GkrProverError.DivisionByZero;

    const denom = QM31.one().sub(y_idx.add(y_idx));
    const b_const = QM31.one().sub(y_idx).div(denom) catch return GkrProverError.DivisionByZero;

    const r0 = evalR(zero, c0, c1, c2, c3);
    const r1 = evalR(one, c0, c1, c2, c3);
    const r2 = evalR(two, c0, c1, c2, c3);

    const eq_at_0 = QM31.one().sub(y_idx);
    const eq_at_2 = try utils.eq(QM31, &[_]QM31{two}, &[_]QM31{y_idx});

    const f0 = r0.div(eq_at_0.mul(a_const)) catch return GkrProverError.DivisionByZero;
    const f2 = r2.div(eq_at_2.mul(a_const)) catch return GkrProverError.DivisionByZero;
    const claim = r0.add(r1);

    var poly = try correctSumAsPolyInFirstVariable(alloc, f0, f2, claim, y[0..], k);
    defer poly.deinit(alloc);

    try std.testing.expect(poly.evalAtPoint(zero).eql(r0));
    try std.testing.expect(poly.evalAtPoint(one).eql(r1));
    try std.testing.expect(poly.evalAtPoint(two).eql(r2));
    try std.testing.expect(poly.evalAtPoint(b_const).isZero());
}
