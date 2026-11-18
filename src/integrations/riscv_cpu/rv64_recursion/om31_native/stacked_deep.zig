//! DEEP opening of Circle polynomials stacked in the equal-height basis.
//! A cohort shares the original mask point and stacking width. Its weights
//! must be drawn after the samples, and its conjugate rows authenticated.
const std = @import("std");
const core = @import("stwo_core");
const C = @import("common.zig");
const I = C.Inner;
const F = C.F;
const max_log = core.poly.circle.MAX_CIRCLE_DOMAIN_LOG_SIZE;
pub const Base = @import("stwo_circuit_frontend").builder.wrappers.M31Wrapper(C.Var);
pub const Pair = struct { value: Base, adjacent: Base };

pub const Cohort = struct {
    weights: []const F,
    re: []const F,
    im: []const F,
    point: C.Point,

    /// Samples are group-major, followed within each group by source ordinal.
    pub fn init(ctx: *C.Context, width: usize, weights: []const F, samples: []const F, point: C.Point) !Cohort {
        if (width == 0 or !std.math.isPowerOfTwo(width) or width > @as(usize, 1) << max_log or
            weights.len == 0 or samples.len % width != 0 or samples.len / width != weights.len)
            return error.ShapeMismatch;
        const re = try ctx.scratch().alloc(F, width);
        const im = try ctx.scratch().alloc(F, width);
        @memset(re, F.zero());
        @memset(im, F.zero());
        _ = point.y.c1.inv();
        for (weights, 0..) |weight, group| {
            for (samples[group * width ..][0..width], re, im) |v, *r, *i| {
                r.* = r.add(weight.mulInner(v.c0));
                i.* = i.add(weight.mulInner(v.c1));
            }
        }
        return .{ .weights = weights, .re = re, .im = im, .point = point };
    }

    pub fn answer(self: Cohort, x: I, y: I, rows: []const Pair) !F {
        if (rows.len != self.weights.len) return error.ShapeMismatch;
        const z = self.point;
        var plus = F.zero();
        for (self.weights, rows) |weight, row| plus = plus.add(weight.mulInner(I.wire(row.value.get())));
        if (self.re.len == 1) {
            const line = plus.sub(self.re[0]).mulInner(z.y.c1).add(self.im[0].mulInner(z.y.c0.sub(y)));
            const den = z.x.c0.sub(x).mul(z.y.c1).sub(z.y.c0.sub(y).mul(z.x.c1));
            return lineScale(line.mulInner(den.inv()));
        }
        var minus = F.zero();
        for (self.weights, rows) |weight, row| minus = minus.add(weight.mulInner(I.wire(row.adjacent.get())));
        const log = std.math.log2_int(usize, self.re.len);
        var factors: [max_log]I = undefined;
        var folded_x = x;
        var ratio = I.one();
        for (factors[0..log]) |*factor| {
            factor.* = folded_x;
            ratio = ratio.mul(folded_x.double());
            folded_x = folded_x.square().double().sub(I.one());
        }
        const folded_y = y.mul(ratio);
        _ = folded_y.inv();
        const h = I.fromBase(core.fields.m31.M31.fromCanonical(1 << 30));
        const re = basis(self.re, factors[0..log]);
        const im = basis(self.im, factors[0..log]);
        // Project the even and odd parts separately before dividing on each fiber.
        const center = plus.add(minus).mulInner(h).sub(re).mulInner(z.y.c1).add(im.mulInner(z.y.c0));
        const delta = plus.sub(minus).mulInner(h.mul(ratio)).mulInner(z.y.c1).sub(im.mulInner(folded_y));
        const den = z.x.c0.sub(folded_x).mul(z.y.c1).sub(z.y.c0.mul(z.x.c1));
        const dy = folded_y.mul(z.x.c1);
        const q0 = center.add(delta).mulInner(den.add(dy).inv());
        const q1 = center.sub(delta).mulInner(den.sub(dy).inv());
        return lineScale(q0.add(q1).add(q0.sub(q1).mulInner(ratio.inv())).mulInner(h));
    }
};

/// Binary reduction of the basis in ordinal order, with logarithmic live state.
fn basis(values: []const F, factors: []const I) F {
    var levels: [max_log + 1]F = undefined;
    for (values, 0..) |v, ordinal| {
        const depth = @ctz(~ordinal);
        var result = v;
        for (factors[0..depth], 0..) |factor, i| result = levels[i].add(result.mulInner(factor));
        levels[depth] = result;
    }
    return levels[factors.len];
}

fn lineScale(s: F) F {
    const nr = core.fields.om31.NONRESIDUE;
    return .{ .c0 = s.c1.mul(I.fromQm31(nr.add(nr).neg())), .c1 = s.c0.double().neg() };
}

test {
    _ = @import("stacked_deep_test.zig");
}
