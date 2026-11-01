//! One combined FUNCTION/R16 LogUp prefix. The receiver must close all support
//! queries against the existing unsigned MUL truth and canonical U16 provider.
const E = @import("../../../evaluation.zig");
const R = @import("../../../providers/scalar_range.zig");
const L = @import("layout.zig");
const A = @import("equations.zig");
pub fn ChallengesFor(comptime C: type) type {
    return struct {
        function: struct { offset: C, coefficients: [13]C },
        range16: R.ChallengesFor(C),
    };
}
pub const Challenges = ChallengesFor(E.Q);
pub fn DenominatorsFor(comptime F: type) type {
    const S = E.SecureFor(F);
    return struct { linear: [32]S, weights: [32]F, quadratic: [2]S };
}
pub fn denominatorsFor(comptime F: type, main: []const F, ch: ChallengesFor(E.ConstFor(F))) DenominatorsFor(F) {
    var out: DenominatorsFor(F) = undefined;
    const active = A.activeFor(F, main);
    for ([_]?bool{ null, false, true }, 0..) |support, i| {
        out.linear[i] = E.denominatorFor(F, ch.function.offset, &ch.function.coefficients, &A.tupleFor(F, main, support), true);
        out.weights[i] = if (i == 0) active.neg() else active;
    }
    const ranges = A.rangeValuesFor(F, main);
    for (0..28) |i| {
        out.linear[3 + i] = ch.range16.denominatorFor(F, ranges[i]);
        out.weights[3 + i] = F.one();
    }
    out.linear[31] = ch.range16.denominatorFor(F, ranges[30]);
    out.weights[31] = F.one();
    for (L.RANGE_QUADRATIC, 0..) |query, i| out.quadratic[i] = ch.range16.denominatorFor(F, ranges[query]);
    return out;
}
pub fn inverseDenominatorsFor(comptime F: type, ds: DenominatorsFor(F)) [18]E.SecureFor(F) {
    var out: [18]E.SecureFor(F) = undefined;
    for (0..L.PAIRS) |i| out[i] = ds.linear[2 * i].mul(ds.linear[2 * i + 1]);
    @memcpy(out[L.PAIRS..], &ds.quadratic);
    return out;
}
pub fn contributionFor(comptime F: type, ds: DenominatorsFor(F), inverses: [18]E.SecureFor(F)) E.SecureFor(F) {
    var sum = E.SecureFor(F).zero();
    for (0..L.PAIRS) |i| {
        const numerator = E.mulBaseFor(F, ds.linear[2 * i + 1], ds.weights[2 * i]).add(E.mulBaseFor(F, ds.linear[2 * i], ds.weights[2 * i + 1]));
        sum = sum.add(numerator.mul(inverses[i]));
    }
    for (inverses[L.PAIRS..]) |value| sum = sum.add(value);
    return sum;
}
pub fn emitFor(comptime F: type, fixed: []const F, main: []const F, previous_count: F, count: F, current: []const F, previous_prefix: E.SecureFor(F), claim: E.ConstFor(F), ch: ChallengesFor(E.ConstFor(F)), sink: *E.SinkFor(F)) void {
    A.emitFor(F, fixed, main, previous_count, count, sink);
    const ds = denominatorsFor(F, main, ch);
    const denominators = inverseDenominatorsFor(F, ds);
    var inverses: [18]E.SecureFor(F) = undefined;
    for (&inverses, 0..) |*inverse, i| {
        inverse.* = E.secureFor(F, current, 4 * i);
        sink.emit(inverse.mul(denominators[i]).sub(E.SecureFor(F).one()));
    }
    R.prefix(F, contributionFor(F, ds, inverses), E.secureFor(F, current, L.PREFIX), previous_prefix, fixed[1], fixed[2], claim, sink);
}
