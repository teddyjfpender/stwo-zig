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
    const log = std.math.log2_int(usize, samples.len);
    var factors: [max_log]Base = undefined;
    var folded_x = w.x;
    var y_ratio = Base.one();
    for (factors[0..log]) |*factor| {
        factor.* = folded_x;
        y_ratio = y_ratio.mul(folded_x.add(folded_x));
        folded_x = BasePoint.doubleX(folded_x);
    }
    const folded = BasePoint{ .x = folded_x, .y = w.y.mul(y_ratio) };
    if (folded.y.isZero()) return error.SingularFiber;
    const sample = sampleAtQuery(samples, factors[0..log]);
    const line = try core.constraints.quadraticConjugateLineCoeffs(Secure, z, sample, Secure.one());
    const d0 = core.constraints.quadraticLineDenominator(Secure, z, folded);
    const d1 = core.constraints.quadraticLineDenominator(Secure, z, folded.conjugate());
    const inv = try d0.mul(d1).inv();

    const center = opened.add(sibling).mul(half);
    const delta = opened.sub(sibling).mul(half).mul(y_ratio);
    const ay = line.a.mulM31(folded.y);
    const q0 = line.c.mulM31(center.add(delta)).sub(ay).sub(line.b).mulInner(d1.mul(inv));
    const q1 = line.c.mulM31(center.sub(delta)).add(ay).sub(line.b).mulInner(d0.mul(inv));
    return q0.add(q1).add(q0.sub(q1).mulM31(try y_ratio.inv())).mulM31(half);
}
