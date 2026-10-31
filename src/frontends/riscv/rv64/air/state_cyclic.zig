//! Versioned state relation with three cyclic prefixes, rather than eight
//! committed inverses and one prefix. Not selected by the legacy CPU profile.
//!
//! The AFTER timestamp is deliberately unmasked: index*enable would make each
//! denominator quadratic and a triple exceed the degree-four CPU budget.
//! Disabled events have zero numerator; their tuple need not be zero.
const E = @import("evaluation.zig");
const std = @import("std");
const R = @import("relations.zig");
const Q = E.Q;
const L = E.L;
pub const INTERACTION = 12;
pub const CONSTRAINTS = 3;
pub const MAX_DEGREE = 4;
pub const Values = [INTERACTION]Q;
pub const Challenges = R.Challenges;
pub const ChallengesFor = R.ChallengesFor;
pub const Term = TermFor(Q);
pub fn TermFor(comptime F: type) type {
    return struct { denominator: E.SecureFor(F), numerator: E.SecureFor(F) };
}

pub fn draw(channel: *@import("protocol.zig").Channel) Challenges {
    return drawWithPolicy(channel, .cyclic_v2);
}

pub fn drawWithPolicy(channel: *@import("protocol.zig").Channel, policy: @import("state_policy.zig").Policy) Challenges {
    std.debug.assert(@import("state_policy.zig").isCyclic(policy));
    channel.mixU32s(&.{ 0x52563634, 0x43535441, @intFromEnum(policy) });
    var result: Challenges = undefined;
    result.offset = channel.drawSecureFelt();
    for (&result.coefficients) |*coefficient| coefficient.* = channel.drawSecureFelt();
    return result;
}

/// Public boundary tuples and their expected claim retain the original schema.
pub fn tuple(v: E.View, slot: usize, before: bool, index: Q) R.Tuple {
    return tupleFor(Q, v, slot, before, index);
}
pub fn tupleFor(comptime F: type, v: E.ViewFor(F), slot: usize, before: bool, index: F) [R.ARITY]F {
    var entry = R.tupleFor(F, v, slot, before);
    if (!before) entry[9] = index.mul(E.qFor(F, 4)).add(E.qFor(F, @intCast(slot + 1)));
    return entry;
}

/// Eight signed events in stable slot order, grouped 3/3/2. Every denominator
/// is affine in the supplied view and index, including at arbitrary OODS points.
pub fn terms(v: E.View, index: Q, challenges: Challenges) [CONSTRAINTS]Term {
    return termsFor(Q, v, index, challenges);
}
pub fn termsFor(comptime F: type, v: E.ViewFor(F), index: F, challenges: ChallengesFor(E.ConstFor(F))) [CONSTRAINTS]TermFor(F) {
    const denominators = @import("state_cyclic_denominators.zig").evaluateFor(F, v, index, challenges);
    const pair0 = denominators[0].mul(denominators[1]);
    const pair2 = denominators[4].mul(denominators[5]);
    const active = v.f[L.fixed.slot_start..][0..4];
    return .{
        .{ .denominator = pair0.mul(denominators[2]), .numerator = E.mulBaseFor(F, denominators[1].sub(denominators[0]), active[0]).mul(denominators[2]).add(E.mulBaseFor(F, pair0, active[1])) },
        .{ .denominator = denominators[3].mul(pair2), .numerator = E.mulBaseFor(F, denominators[3], active[2]).mul(denominators[5].sub(denominators[4])).sub(E.mulBaseFor(F, pair2, active[1])) },
        .{ .denominator = denominators[6].mul(denominators[7]), .numerator = E.mulBaseFor(F, denominators[7].sub(denominators[6]), active[3]) },
    };
}

/// Only these four coordinates need a predecessor opening. All three prefixes
/// form one cyclic chain, so the claim is injected exactly once per domain.
pub fn needsPrevious(column: usize) bool {
    return column >= INTERACTION - 4 and column < INTERACTION;
}

pub fn secure(values: *const Values, group: usize) Q {
    return secureFor(Q, values, group);
}
pub fn secureFor(comptime F: type, values: *const [INTERACTION]F, group: usize) E.SecureFor(F) {
    return E.secureFor(F, values, group * 4);
}

pub fn evaluate(v: E.View, index: Q, first: Q, current: *const Values, previous: *const Values, challenges: Challenges, claim: Q, out: *E.Sink) void {
    return evaluateFor(Q, v, index, first, current, previous, challenges, claim, out);
}
pub fn evaluateFor(comptime F: type, v: E.ViewFor(F), index: F, first: F, current: *const [INTERACTION]F, previous: *const [INTERACTION]F, challenges: ChallengesFor(E.ConstFor(F)), claim: E.ConstFor(F), out: *E.SinkFor(F)) void {
    const fractions = termsFor(F, v, index, challenges);
    var prior = secureFor(F, previous, CONSTRAINTS - 1).sub(E.mulBaseFor(F, E.splatFor(F, claim), first));
    for (fractions, 0..) |fraction, group| {
        const prefix = secureFor(F, current, group);
        out.emit(prefix.sub(prior).mul(fraction.denominator).sub(fraction.numerator));
        prior = prefix;
    }
}

/// Native witness generation uses three inversions per row. The returned final
/// prefix becomes the next row's predecessor; the final domain prefix is claim.
pub fn advance(v: E.View, index: Q, challenges: Challenges, previous: Q) ![CONSTRAINTS]Q {
    var result: [CONSTRAINTS]Q = undefined;
    var prefix = previous;
    for (terms(v, index, challenges), 0..) |fraction, group| {
        prefix = prefix.add(fraction.numerator.mul(try fraction.denominator.inv()));
        result[group] = prefix;
    }
    return result;
}
