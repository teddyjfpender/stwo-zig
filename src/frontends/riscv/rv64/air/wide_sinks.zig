//! Explicit degree-eight accumulators; legacy QM31 sink types remain unchanged.
const std = @import("std");
const lane = @import("lane.zig");
const core = @import("stwo_core");
pub fn Weighted(comptime C: type, comptime S: type) type {
    return struct { powers: []const C, accumulation: S = S.zero() };
}
pub fn Sink(comptime C: type, comptime B: type, comptime S: type) type {
    return struct {
        values: ?[]S = null,
        count: usize = 0,
        accumulator: ?*(if (C == S) core.air.accumulation.ForField(C).PointEvaluationAccumulator else lane.PointAccumulator(S)) = null,
        weighted_accumulator: ?*Weighted(C, S) = null,
        scale: ?S = null,
        pub fn zeros(self: *@This(), n: usize) void {
            if (self.values) |v| @memset(v[self.count..][0..n], S.zero());
            if (self.accumulator) |a| a.accumulation = a.accumulation.mul(lane.pow(S, a.random_coeff, n));
            self.count += n;
        }
        pub fn emit(self: *@This(), value: anytype) void {
            const F = @TypeOf(value);
            comptime if (F != B and F != S) @compileError("incorrect wide sink residual family");
            const is_base = B != S and F == B;
            if (self.values) |v| v[self.count] = if (is_base) S.fromBase(value) else value;
            if (self.accumulator) |a| {
                const secure = if (is_base) S.fromBase(value) else value;
                a.accumulate(if (self.scale) |scale| scale.mul(secure) else secure);
            }
            if (self.weighted_accumulator) |a| {
                std.debug.assert(self.count < a.powers.len);
                const scalar = a.powers[a.powers.len - 1 - self.count];
                const power = if (C == S) scalar else S.splat(scalar);
                const factor = if (self.scale) |scale| power.mul(scale) else power;
                // Preserve the packed-base multiply for local domain residuals.
                const weighted = if (is_base) factor.mulBase(value) else factor.mul(value);
                a.accumulation = a.accumulation.add(weighted);
            }
            self.count += 1;
        }
    };
}
