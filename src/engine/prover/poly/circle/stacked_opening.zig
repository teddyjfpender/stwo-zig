//! Coefficient packing and the paired-query DEEP equation for equal-height
//! Circle columns. This private algebra is independent of Merkle and transcript
//! policy. A protocol using it must authenticate the ordered columns, their
//! common masks and both adjacent rows before evaluating the equation.
const std = @import("std");
const core = @import("stwo_core");
const Base = core.fields.m31.M31;
const Secure = core.fields.om31.OM31;
const BasePoint = core.circle.CirclePointM31;
const SamplePoint = core.circle.CirclePoint(Secure);
const max_log = core.poly.circle.domain.MAX_CIRCLE_DOMAIN_LOG_SIZE;
const half = Base.fromCanonical(1 << 30);
const Inner = Secure.InnerField;

pub const Pair = struct {
    value: Secure,
    conjugate: Secure,
};

fn validWidth(width: usize) bool {
    return width >= 2 and std.math.isPowerOfTwo(width) and std.math.log2_int(usize, width) < max_log;
}

/// The low coefficient bit selects the 1 or y factor. Insert the column bits
/// immediately above it. Higher factors then start at the folded x coordinate.
pub fn pack(columns: []const Base, width: usize, output: []Base) !void {
    if (!validWidth(width) or columns.len != output.len or !std.math.isPowerOfTwo(columns.len) or
        columns.len / width < 2 or std.math.log2_int(usize, columns.len) > max_log) return error.InvalidStackShape;
    const src_address = @intFromPtr(columns.ptr);
    const dst_address = @intFromPtr(output.ptr);
    const distance = @max(src_address, dst_address) - @min(src_address, dst_address);
    if (distance / @sizeOf(Base) < columns.len) return error.OverlappingBuffers;
    const rows = columns.len / width;
    for (0..rows / 2) |pair| {
        for (0..width) |column| {
            const src = column * rows + 2 * pair;
            const dst = 2 * (pair * width + column);
            output[dst..][0..2].* = columns[src..][0..2].*;
        }
    }
}

/// Evaluates the low x-coordinate basis at the query using one base-field
/// scaling per internal node of the binary reduction. No weight table is built.
fn sampleAtQuery(samples: []const Secure, factors: []const Base) Secure {
    var pending: [max_log]Secure = undefined;
    for (samples, 0..) |sample, i| {
        var acc = sample;
        const level = @ctz(~i);
        for (factors[0..level], 0..) |factor, depth|
            acc = pending[depth].add(acc.mulM31(factor));
        pending[level] = acc;
    }
    return pending[factors.len];
}

/// Each source f_j has the form A_j(x) + y B_j(x). At w and its circle
/// conjugate the packed opening gives the same weighted A and opposite B.
/// Substitute the folded y to obtain both source evaluations, take their
/// native DEEP quotients, then substitute the original y to pack the answer.
pub fn quotient(w: BasePoint, opened: Base, sibling: Base, z: SamplePoint, samples: []const Secure) !Secure {
    if (!validWidth(samples.len)) return error.InvalidStackShape;
    if (!w.isOnCircle() or !z.isOnCircle()) return error.InvalidCirclePoint;
    var factors: [max_log]Base = undefined;
    const log = std.math.log2_int(usize, samples.len);
    const fiber = try Fiber.init(w, factors[0..log]);
    const sample = sampleAtQuery(samples, factors[0..log]);
    const line = try core.constraints.quadraticConjugateLineCoeffs(Secure, z, sample, Secure.one());
    return (try fiber.combine(z, line.c.mulM31(opened), line.c.mulM31(sibling), line.a, line.b)).value;
}

const Fiber = struct {
    folded: BasePoint,
    y: Base,
    ratio: Base,

    fn init(w: BasePoint, factors: []Base) !Fiber {
        var x = w.x;
        var ratio = Base.one();
        for (factors) |*factor| {
            factor.* = x;
            ratio = ratio.mul(x.add(x));
            x = BasePoint.doubleX(x);
        }
        const folded = BasePoint{ .x = x, .y = w.y.mul(ratio) };
        if (folded.y.isZero()) return error.SingularFiber;
        return .{ .folded = folded, .y = w.y, .ratio = ratio };
    }

    fn combine(f: Fiber, z: SamplePoint, opened: Secure, sibling: Secure, a: Secure, b: Secure) !Pair {
        const d = z.x.c0.sub(Inner.fromBase(f.folded.x)).mul(z.y.c1).sub(z.y.c0.mul(z.x.c1));
        const slope = z.x.c1.mul(Inner.fromBase(f.y));
        const e = slope.mul(Inner.fromBase(f.ratio));
        const inv = try d.square().sub(e.square()).inv();
        const center = opened.add(sibling).mulM31(half).sub(b);
        const delta = opened.sub(sibling).mulM31(half).sub(a.mulM31(f.y));
        // The original denominators are d +/- e. Keep delta at the packed
        // y coordinate so the odd projection cancels the fold ratio.
        const diag = d.mul(inv);
        const upper = slope.mul(inv);
        const lower = upper.mul(Inner.fromBase(f.ratio.square()));
        const even = center.mulInner(diag).sub(delta.mulInner(lower));
        const odd = delta.mulInner(diag).sub(center.mulInner(upper));
        return .{ .value = even.add(odd), .conjugate = even.sub(odd) };
    }
};

/// One common source point, source height and packed width. Both ends select
/// the same groups and derive their weights after all OODS values are bound.
/// Project samples once across groups, so each query reduces two width-sized
/// vectors regardless of how many groups share the geometry.
pub const Batch = struct {
    storage: []Secure,
    weights: []const Secure,
    real: []const Secure,
    imaginary: []const Secure,
    point: SamplePoint,

    pub fn init(allocator: std.mem.Allocator, width: usize, weights: []const Secure, point: SamplePoint, samples: []const Secure) !Batch {
        if ((width != 1 and !validWidth(width)) or weights.len == 0 or
            samples.len / width != weights.len or samples.len % width != 0) return error.InvalidStackShape;
        if (!point.isOnCircle()) return error.InvalidCirclePoint;
        if (point.y.c1.isZero()) return error.DegenerateLine;
        const storage = try allocator.alloc(Secure, try std.math.add(usize, 2 * width, weights.len));
        const saved_weights = storage[2 * width ..];
        @memcpy(saved_weights, weights);
        const real = storage[0..width];
        const imaginary = storage[width..][0..width];
        @memset(storage[0 .. 2 * width], Secure.zero());
        for (weights, 0..) |alpha, g| {
            for (samples[g * width ..][0..width], real, imaginary) |s, *re, *im| {
                // Conjugation acts on s alone. The post-sample weight can
                // have a nonzero imaginary part, so both sums are secure.
                re.* = re.add(alpha.mulInner(s.c0));
                im.* = im.add(alpha.mulInner(s.c1));
            }
        }
        return .{ .storage = storage, .weights = saved_weights, .real = real, .imaginary = imaginary, .point = point };
    }

    pub fn deinit(batch: *Batch, allocator: std.mem.Allocator) void {
        allocator.free(batch.storage);
        batch.* = undefined;
    }

    pub fn answer(batch: Batch, w: BasePoint, opened: []const Base, siblings: []const Base) !Secure {
        if (batch.real.len != 1) return (try batch.answerPair(w, opened, siblings)).value;
        if (opened.len != batch.weights.len or siblings.len != batch.weights.len) return error.InvalidStackShape;
        if (!w.isOnCircle()) return error.InvalidCirclePoint;
        return batch.direct(w, opened);
    }

    fn direct(batch: Batch, w: BasePoint, opened: []const Base) !Secure {
        var value = Secure.zero();
        for (batch.weights, opened) |alpha, word| value = value.add(alpha.mulM31(word));
        const y = batch.point.y;
        const d = core.constraints.quadraticLineDenominator(Secure, batch.point, w);
        const line = value.sub(batch.real[0]).mulInner(y.c1).add(batch.imaginary[0].mulInner(y.c0.sub(Inner.fromBase(w.y))));
        return scaleLine(line.mulInner(try d.inv()));
    }

    /// Evaluate the two orientations together. Both source rows use the
    /// same post-sample weights and must be authenticated by the caller.
    pub fn answerPair(batch: Batch, w: BasePoint, opened: []const Base, siblings: []const Base) !Pair {
        if (opened.len != batch.weights.len or siblings.len != batch.weights.len or batch.real.len == 1) return error.InvalidStackShape;
        if (!w.isOnCircle()) return error.InvalidCirclePoint;
        const log = std.math.log2_int(usize, batch.real.len);
        var factors: [max_log]Base = undefined;
        const fiber = try Fiber.init(w, factors[0..log]);
        const re = sampleAtQuery(batch.real, factors[0..log]);
        const im = sampleAtQuery(batch.imaginary, factors[0..log]);
        const y = batch.point.y;
        const b = re.mulInner(y.c1).sub(im.mulInner(y.c0));
        var plus = Secure.zero();
        var minus = Secure.zero();
        for (batch.weights, opened, siblings) |alpha, v, sibling| {
            plus = plus.add(alpha.mulM31(v));
            minus = minus.add(alpha.mulM31(sibling));
        }
        const q = try fiber.combine(batch.point, plus.mulInner(y.c1), minus.mulInner(y.c1), im, b);
        return .{ .value = scaleLine(q.value), .conjugate = scaleLine(q.conjugate) };
    }
};

// The quadratic generator sends (real, imaginary) to (nr * imaginary, real).
fn scaleLine(value: Secure) Secure {
    const nonresidue = core.fields.om31.NONRESIDUE;
    return .{
        .c0 = value.c1.mul(nonresidue.add(nonresidue).neg()),
        .c1 = value.c0.add(value.c0).neg(),
    };
}
