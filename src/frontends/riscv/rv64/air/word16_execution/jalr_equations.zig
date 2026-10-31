//! Unit composite delegation: JALR10 -> ADD0 and AND16. All three use the SAME
//! FUNCTION vector. Signed field multiplicities are forbidden: marginals alone
//! would allow false joins. Base ADD/AND proofs establish the arithmetic truth.
const E = @import("../evaluation.zig");
const T = @import("types.zig");
const M = @import("stwo_core").fields.m31.M31;
pub const MAIN = 18;
pub const INTERACTION = 12;
pub const FIXED = 2;
pub const CONSTRAINTS = 6;
pub const ACTIVE = 16;
pub const WEIGHT = 17;
pub fn tuple(comptime F: type, operation: u32, a: []const F, b: []const F, c: []const F) [13]F {
    var out: [13]F = undefined;
    out[0] = T.literal(F, operation);
    @memcpy(out[1..5], a[0..4]);
    @memcpy(out[5..9], b[0..4]);
    @memcpy(out[9..13], c[0..4]);
    return out;
}
pub fn request(comptime F: type, row: []const F) [13]F {
    return tuple(F, 10, row[0..4], row[4..8], row[8..12]);
}
pub fn add(comptime F: type, row: []const F) [13]F {
    return tuple(F, 0, row[0..4], row[4..8], row[12..16]);
}
pub fn and_(comptime F: type, row: []const F) [13]F {
    const mask = [_]F{ T.literal(F, 65534), T.literal(F, 65535), T.literal(F, 65535), T.literal(F, 65535) };
    return tuple(F, 16, row[12..16], &mask, row[8..12]);
}
pub fn DenominatorsFor(comptime F: type) type {
    const S = E.SecureFor(F);
    return struct { request: S, add: S, and_: S };
}
pub fn denominatorsFor(comptime F: type, row: []const F, ch: T.FunctionChallengesFor(E.ConstFor(F))) DenominatorsFor(F) {
    return .{ .request = ch.denominatorFor(F, request(F, row)), .add = ch.denominatorFor(F, add(F, row)), .and_ = ch.denominatorFor(F, and_(F, row)) };
}
pub fn contributionFor(comptime F: type, ds: DenominatorsFor(F), weight: F, inverse_request: E.SecureFor(F), inverse_pair: E.SecureFor(F)) E.SecureFor(F) {
    return E.mulBaseFor(F, ds.add.add(ds.and_).mul(inverse_pair).sub(inverse_request), weight);
}
pub fn emitFor(comptime F: type, fixed: []const F, row: []const F, current: []const F, previous: []const F, claim: E.ConstFor(F), ch: T.FunctionChallengesFor(E.ConstFor(F)), sink: *E.SinkFor(F)) void {
    E.booleanFor(F, sink, row[ACTIVE]);
    sink.emit(row[WEIGHT].sub(row[ACTIVE]));
    const ds = denominatorsFor(F, row, ch);
    const inverse_request = E.secureFor(F, current, 0);
    const inverse_pair = E.secureFor(F, current, 4);
    sink.emit(ds.request.mul(inverse_request).sub(E.SecureFor(F).one()));
    sink.emit(ds.add.mul(ds.and_).mul(inverse_pair).sub(E.SecureFor(F).one()));
    const sum = E.secureFor(F, current, 8);
    sink.emit(sum.sub(E.secureFor(F, previous, 8)).add(E.mulBaseFor(F, E.splatFor(F, claim), fixed[0])).sub(contributionFor(F, ds, row[WEIGHT], inverse_request, inverse_pair)));
    sink.emit(E.mulBaseFor(F, sum, fixed[1]));
}
fn dot(ch: T.FunctionChallenges, values: [13]M) E.Q {
    var out = ch.offset;
    for (ch.coefficients, values) |coefficient, value| out = out.sub(coefficient.mulM31(value));
    return out;
}
pub fn nativeDenominators(row: []const M, ch: T.FunctionChallenges) DenominatorsFor(E.Q) {
    return .{ .request = dot(ch, request(M, row)), .add = dot(ch, add(M, row)), .and_ = dot(ch, and_(M, row)) };
}
