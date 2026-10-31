//! Scalar range relation shared by concrete U8/U16 consumers and providers.
//! Challenge sampling belongs to the enclosing proof after all main roots seal.
const E = @import("../evaluation.zig");

pub const Challenges = struct {
    offset: E.Q,
    coefficient: E.Q,
    pub fn denominatorFor(self: @This(), comptime F: type, value: F) E.SecureFor(F) {
        return affineDenominatorFor(F, self.offset, self.coefficient, value);
    }
};

/// One denominator authority, including external arithmetic constant lanes.
pub fn affineDenominatorFor(comptime F: type, offset: E.ConstFor(F), coefficient: E.ConstFor(F), value: F) E.SecureFor(F) {
    return E.splatFor(F, offset).sub(E.mulBaseFor(F, E.splatFor(F, coefficient), value));
}

pub fn prefix(comptime F: type, contribution: E.SecureFor(F), current: E.SecureFor(F), previous: E.SecureFor(F), first: F, last: F, claim: E.Q, sink: *E.SinkFor(F)) void {
    sink.emit(current.sub(previous).add(E.mulBaseFor(F, E.splatFor(F, claim), first)).sub(contribution));
    sink.emit(E.mulBaseFor(F, current, last));
}

pub fn single(comptime F: type, denominator: E.SecureFor(F), weight: F, inverse: E.SecureFor(F), current: E.SecureFor(F), previous: E.SecureFor(F), first: F, last: F, claim: E.Q, sink: *E.SinkFor(F)) void {
    sink.emit(inverse.mul(denominator).sub(E.SecureFor(F).one()));
    prefix(F, E.mulBaseFor(F, inverse, weight), current, previous, first, last, claim, sink);
}

pub fn rangeFor(comptime F: type, fixed: []const F, main: []const F, current: []const F, previous: []const F, claim: E.Q, challenges: Challenges, sink: *E.SinkFor(F)) void {
    single(F, challenges.denominatorFor(F, fixed[0]), main[0].neg(), E.secureFor(F, current, 0), E.secureFor(F, current, 4), E.secureFor(F, previous, 4), fixed[1], fixed[2], claim, sink);
}
