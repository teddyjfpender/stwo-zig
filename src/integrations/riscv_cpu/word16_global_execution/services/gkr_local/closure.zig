//! Shared native/circuit arithmetic for whole-local projective output closure.
//! This is NOT an accepting receiver: terminal inputs still need MAIN binding.
const std = @import("std");
const O = @import("stwo_core").fields.om31.OM31;
pub const Check = enum { pole, local_sum };
pub fn closeFor(comptime F: type, outputs: []const []const F, inverse_hints: []const F, checks: anytype) !void {
    if (outputs.len == 0 or outputs.len != inverse_hints.len) return error.LocalGkrOutputShape;
    var numerator = F.zero();
    var denominator = F.one();
    for (outputs, inverse_hints) |pair, inverse| {
        if (pair.len != 2) return error.LocalGkrOutputShape;
        // No witness-dependent branch in the circuit authority. This excludes
        // every denominator pole, including a zero-weight0/0 input.
        try checks.requireEq(pair[1].mul(inverse), F.one(), Check.pole);
        numerator = numerator.mul(pair[1]).add(pair[0].mul(denominator));
        denominator = denominator.mul(pair[1]);
    }
    try checks.requireEq(numerator, F.zero(), Check.local_sum);
}
pub const NativeChecks = struct {
    pub fn requireEq(_: NativeChecks, lhs: O, rhs: O, kind: Check) !void {
        if (!lhs.eql(rhs)) return if (kind == .pole) error.LocalGkrPole else error.UnclosedLocalGkr;
    }
};
pub fn close(a: std.mem.Allocator, outputs: []const []const O) !void {
    if (outputs.len == 0) return error.LocalGkrOutputShape;
    const inverses = try a.alloc(O, outputs.len);
    defer a.free(inverses);
    for (outputs, inverses) |pair, *inverse| {
        if (pair.len != 2) return error.LocalGkrOutputShape;
        if (pair[1].isZero()) return error.LocalGkrPole;
        inverse.* = try pair[1].inv();
    }
    try closeFor(O, outputs, inverses, NativeChecks{});
}
