//! Explicit degree-eight classic LogUp kernels for global RAM/KIO/Wire only.
//! Tuple/weight authority stays with the original role emitter. These kernels
//! never reinterpret the legacy four-coordinate interaction layout.
const std = @import("std");
const E = @import("../evaluation.zig");
pub const Cost = struct { secure_values: usize, columns: usize, samples: usize, physical_claims: usize };
pub fn singlesCost(queries: usize) !Cost {
    const values = try std.math.add(usize, queries, 1);
    return .{ .secure_values = values, .columns = try std.math.mul(usize, 8, values), .samples = try std.math.mul(usize, 8, try std.math.add(usize, queries, 2)), .physical_claims = 1 };
}
pub fn clearedPairsCost(queries: usize) !Cost {
    const pairs = (try std.math.add(usize, queries, 1)) / 2;
    return .{ .secure_values = try std.math.mul(usize, 2, pairs), .columns = try std.math.mul(usize, 16, pairs), .samples = try std.math.mul(usize, 24, pairs), .physical_claims = pairs };
}
fn validate(comptime F: type, width: usize, current: []const F, previous: []const F) !void {
    comptime if (E.extensionDegree(E.ConstFor(F)) != 8) @compileError("wide classic argument requires explicit degree-eight lanes");
    if (current.len != width or previous.len != width) return error.InvalidWideGlobalShape;
}
fn secure(comptime F: type, values: []const F, index: usize) E.SecureFor(F) {
    return E.secureForField(E.ConstFor(F), F, values, 8 * index);
}
/// Strict single inverses plus ONE prefix. Supports quadratic coefficients
/// with affine denominators at degree3 and minimizes predecessor openings.
pub fn singlesFor(comptime F: type, denominators: []const E.SecureFor(F), weights: []const F, current: []const F, previous: []const F, first: F, last: F, claim: E.ConstFor(F), out: *E.SinkFor(F)) !void {
    if (denominators.len != weights.len) return error.InvalidWideGlobalShape;
    const cost = try singlesCost(denominators.len);
    try validate(F, cost.columns, current, previous);
    var contribution = E.SecureFor(F).zero();
    for (denominators, weights, 0..) |d, w, i| {
        const inverse = secure(F, current, i);
        out.emit(d.mul(inverse).sub(E.SecureFor(F).one()));
        contribution = contribution.add(E.mulBaseFor(F, inverse, w));
    }
    const sum = secure(F, current, denominators.len);
    out.emit(sum.sub(secure(F, previous, denominators.len)).add(E.mulBaseFor(F, E.splatFor(F, claim), first)).sub(contribution));
    out.emit(E.mulBaseFor(F, sum, last));
}
/// Strict paired inverses and ONE joint prefix. The caller's authoritative
/// polynomial catalog must bound weights/denominators by degree1; quadratic
/// weights here would create degree4. No runtime producer degree declaration.
pub fn linearPairsFor(comptime F: type, denominators: []const E.SecureFor(F), weights: []const F, current: []const F, previous: []const F, first: F, last: F, claim: E.ConstFor(F), out: *E.SinkFor(F)) !void {
    if (denominators.len != weights.len) return error.InvalidWideGlobalShape;
    const pairs = (try std.math.add(usize, denominators.len, 1)) / 2;
    const width = try std.math.mul(usize, 8, try std.math.add(usize, pairs, 1));
    try validate(F, width, current, previous);
    const S = E.SecureFor(F);
    var contribution = S.zero();
    for (0..pairs) |i| {
        const d = denominators[2 * i];
        const w = weights[2 * i];
        const e = if (2 * i + 1 < denominators.len) denominators[2 * i + 1] else S.one();
        const v = if (2 * i + 1 < weights.len) weights[2 * i + 1] else F.zero();
        const inverse = secure(F, current, i);
        out.emit(d.mul(e).mul(inverse).sub(S.one()));
        contribution = contribution.add(inverse.mul(E.mulBaseFor(F, e, w).add(E.mulBaseFor(F, d, v))));
    }
    const sum = secure(F, current, pairs);
    out.emit(sum.sub(secure(F, previous, pairs)).add(E.mulBaseFor(F, E.splatFor(F, claim), first)).sub(contribution));
    out.emit(E.mulBaseFor(F, sum, last));
}
/// One independently claimed cleared pair. Affine D and quadratic w stay D3:
/// delta*D0*D1-w0*D1-w1*D0=0. The independent inverse forbids cancellation at
/// either pole, including zero-weight events. Callers must bind EVERY pair's
/// claim in the transcript and close their sum, not accept just a host sum.
pub fn clearedPairFor(comptime F: type, denominators: [2]E.SecureFor(F), weights: [2]F, current: []const F, previous: []const F, first: F, last: F, claim: E.ConstFor(F), out: *E.SinkFor(F)) !void {
    try validate(F, 16, current, previous);
    const d = denominators[0];
    const e = denominators[1];
    out.emit(secure(F, current, 0).mul(d).mul(e).sub(E.SecureFor(F).one()));
    const sum = secure(F, current, 1);
    const delta = sum.sub(secure(F, previous, 1)).add(E.mulBaseFor(F, E.splatFor(F, claim), first));
    out.emit(delta.mul(d).mul(e).sub(E.mulBaseFor(F, e, weights[0])).sub(E.mulBaseFor(F, d, weights[1])));
    out.emit(E.mulBaseFor(F, sum, last));
}
