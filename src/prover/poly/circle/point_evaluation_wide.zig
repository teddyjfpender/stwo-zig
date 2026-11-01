//! Bounded split-product evaluation of M31 coefficients at an OM31 point.
//! The factor authority is point_evaluation_family; only O(sqrt(N)) weights
//! are materialized. Native packed secure-by-M31 dots reuse field kernels.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;
const pack_ops = core.fields.packed_om31;
const m = core.fields.m31;
const Factors = @import("point_evaluation_family.zig").ForField(O);
pub const Basis = struct {
    storage: []O,
    low: []O,
    high: []O,
    pub fn init(a: std.mem.Allocator, point: core.circle.CirclePoint(O), log: u32) !Basis {
        if (log > core.circle.M31_CIRCLE_LOG_ORDER or log >= @bitSizeOf(usize)) return error.ShapeMismatch;
        var buffer: [core.circle.M31_CIRCLE_LOG_ORDER]O = undefined;
        const factors = Factors.fillEvalFactorsForPoint(point, log, &buffer);
        const low_log = (log + 1) / 2;
        const low_rows = @as(usize, 1) << @intCast(low_log);
        const high_rows = @as(usize, 1) << @intCast(log - low_log);
        const storage = try a.alloc(O, try std.math.add(usize, low_rows, high_rows));
        const low = storage[0..low_rows];
        const high = storage[low_rows..];
        fill(factors[0..low_log], low);
        fill(factors[low_log..], high);
        return .{ .storage = storage, .low = low, .high = high };
    }
    pub fn deinit(self: *Basis, a: std.mem.Allocator) void {
        a.free(self.storage);
        self.* = undefined;
    }
    pub fn evaluate(self: Basis, coefficients: []const M) O {
        std.debug.assert(coefficients.len == self.low.len * self.high.len);
        var result = O.zero();
        for (self.high, 0..) |factor, block| result = result.add(dot(coefficients[block * self.low.len ..][0..self.low.len], self.low).mul(factor));
        return result;
    }
};
fn fill(factors: []const O, out: []O) void {
    std.debug.assert(out.len == @as(usize, 1) << @intCast(factors.len));
    out[0] = O.one();
    for (out[1..], 1..) |*value, i| value.* = out[i & (i - 1)].mul(factors[@ctz(i)]);
}
fn dot(coefficients: []const M, weights: []const O) O {
    var sum = pack_ops.splat(O.zero());
    var i: usize = 0;
    while (i + m.PACK_WIDTH <= coefficients.len) : (i += m.PACK_WIDTH) sum = sum.add(pack_ops.loadNative(weights[i..]).mulBase(m.loadPacked(coefficients[i..].ptr)));
    var result = O.zero();
    inline for (0..m.PACK_WIDTH) |lane| result = result.add(pack_ops.lane(sum, lane));
    for (i..coefficients.len) |tail| result = result.add(weights[tail].mulM31(coefficients[tail]));
    return result;
}
