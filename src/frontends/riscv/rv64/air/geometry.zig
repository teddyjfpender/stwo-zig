//! Circle geometry shared by independently sized RV64 proof components.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Point = core.circle.CirclePointQM31;
const canonic = core.poly.circle.canonic;
const lane = @import("lane.zig");

/// PCS samples each smaller polynomial after doubling the global point.
pub fn localPoint(point: Point, global_log: u32, local_log: u32) !Point {
    if (local_log == 0 or global_log < local_log or global_log >= core.circle.M31_CIRCLE_LOG_ORDER) return error.InvalidRv64MaskGeometry;
    return point.repeatedDouble(global_log - local_log);
}

/// Masks remain in the global domain; PCS applies the component's folding.
pub fn previousPoint(point: Point, global_log: u32) Point {
    const step = canonic.CanonicCoset.new(global_log).coset().step;
    return point.sub(.{ .x = Q.fromBase(step.x), .y = Q.fromBase(step.y) });
}

pub fn denominatorInverse(point: Point, global_log: u32, local_log: u32) !Q {
    return (try core.constraints.cosetVanishing(Q, canonic.CanonicCoset.new(local_log).coset(), try localPoint(point, global_log, local_log)).inv());
}

/// A circle point with coordinates in an arbitrary evaluation lane.
pub fn PointFor(comptime F: type) type {
    return core.circle.CirclePoint(F);
}

/// Same vanishing inverse over an external lane: the global point is doubled
/// down to the component domain, shifted by the canonic coset, and the x
/// coordinate doubled `local_log - 1` times. QM31 keeps the native path.
pub fn denominatorInverseFor(comptime F: type, point: PointFor(F), global_log: u32, local_log: u32) !F {
    if (F == Q) return denominatorInverse(point, global_log, local_log);
    comptime lane.assertExternalLane(F);
    if (local_log == 0 or global_log < local_log or global_log >= core.circle.M31_CIRCLE_LOG_ORDER) return error.InvalidRv64MaskGeometry;
    const coset = canonic.CanonicCoset.new(local_log).coset();
    const local = point.repeatedDouble(global_log - local_log);
    const shifted = local.sub(liftPoint(F, coset.initial)).add(liftPoint(F, coset.half_step));
    var x = shifted.x;
    for (1..local_log) |_| {
        const square = x.square();
        x = square.add(square).sub(F.one());
    }
    return x.inv();
}
fn liftPoint(comptime F: type, point: core.circle.CirclePointM31) PointFor(F) {
    return .{ .x = F.fromBase(point.x), .y = F.fromBase(point.y) };
}

/// Denominators are constant on blocks in committed bit-reversed order.
pub fn denominatorInverses(a: std.mem.Allocator, local_log: u32, eval_log: u32) ![]M {
    if (local_log == 0 or eval_log <= local_log or eval_log >= core.circle.M31_CIRCLE_LOG_ORDER) return error.InvalidRv64MaskGeometry;
    const bits = eval_log - local_log;
    const result = try a.alloc(M, @as(usize, 1) << @intCast(bits));
    errdefer a.free(result);
    const domain = canonic.CanonicCoset.new(eval_log).circleDomain();
    for (result, 0..) |*value, i| value.* = try core.constraints.cosetVanishing(M, canonic.CanonicCoset.new(local_log).coset(), domain.at(core.utils.bitReverseIndex(i, bits))).inv();
    return result;
}

pub fn liftedIndex(position: usize, global_log: u32, local_log: u32) !usize {
    if (global_log < local_log or global_log >= @bitSizeOf(usize) or position >= (@as(usize, 1) << @intCast(global_log))) return error.InvalidRv64MaskGeometry;
    const shift: std.math.Log2Int(usize) = @intCast(global_log - local_log + 1);
    return ((position >> shift) << 1) + (position & 1);
}

test "unequal domains preserve predecessor points and quotient denominators" {
    const a = std.testing.allocator;
    const global_log = 12;
    const local_log = 8;
    const domain = canonic.CanonicCoset.new(global_log + 2).circleDomain();
    const inverses = try denominatorInverses(a, local_log, local_log + 2);
    defer a.free(inverses);
    const small = canonic.CanonicCoset.new(local_log + 2).circleDomain();
    for (0..domain.size()) |row| {
        const p = domain.at(core.utils.bitReverseIndex(row, global_log + 2));
        const point: Point = .{ .x = Q.fromBase(p.x), .y = Q.fromBase(p.y) };
        const local = try localPoint(point, global_log, local_log);
        const local_previous = previousPoint(local, local_log);
        const folded_previous = try localPoint(previousPoint(point, global_log), global_log, local_log);
        try std.testing.expect(local_previous.x.eql(folded_previous.x));
        try std.testing.expect(local_previous.y.eql(folded_previous.y));
        const index = try liftedIndex(row, global_log + 2, local_log + 2);
        const expected = small.at(core.utils.bitReverseIndex(index, local_log + 2));
        try std.testing.expect(local.x.eql(Q.fromBase(expected.x)));
        try std.testing.expect(local.y.eql(Q.fromBase(expected.y)));
        try std.testing.expect((try denominatorInverse(point, global_log, local_log)).eql(Q.fromBase(inverses[index >> local_log])));
    }
}
