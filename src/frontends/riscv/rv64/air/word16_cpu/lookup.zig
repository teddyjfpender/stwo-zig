//! Concrete typed affine denominators for the thin CPU. Challenge drawing stays
//! in the one-PCS coordinator, after every participating main commitment.
const E = @import("../evaluation.zig");
const Function = @import("../word16_v1/function_bus.zig");
pub const FunctionChallenges = Function.Challenges;
pub const RegisterChallenges = struct {
    offset: E.Q,
    coefficients: [6]E.Q,
    pub fn denominatorFor(self: @This(), comptime F: type, tuple: [6]F) E.SecureFor(F) {
        return E.denominatorFor(F, self.offset, &self.coefficients, &tuple, true);
    }
};
pub const RomChallenges = struct {
    offset: E.Q,
    coefficients: [16]E.Q,
    pub fn denominatorFor(self: @This(), comptime F: type, tuple: [16]F) E.SecureFor(F) {
        return E.denominatorFor(F, self.offset, &self.coefficients, &tuple, true);
    }
};
pub const RangeChallenges = struct {
    offset: E.Q,
    coefficient: E.Q,
    pub fn denominatorFor(self: @This(), comptime F: type, value: F) E.SecureFor(F) {
        return E.splatFor(F, self.offset).sub(E.mulBaseFor(F, E.splatFor(F, self.coefficient), value));
    }
};
pub const Challenges = struct { register: RegisterChallenges, function: FunctionChallenges, rom: RomChallenges, range16: RangeChallenges, range8: RangeChallenges };
pub fn prefix(comptime F: type, contribution: E.SecureFor(F), current: E.SecureFor(F), previous: E.SecureFor(F), first: F, last: F, claim: E.Q, sink: *E.SinkFor(F)) void {
    sink.emit(current.sub(previous).add(E.mulBaseFor(F, E.splatFor(F, claim), first)).sub(contribution));
    sink.emit(E.mulBaseFor(F, current, last));
}
pub fn single(comptime F: type, denominator: E.SecureFor(F), weight: F, inverse: E.SecureFor(F), current: E.SecureFor(F), previous: E.SecureFor(F), first: F, last: F, claim: E.Q, sink: *E.SinkFor(F)) void {
    sink.emit(inverse.mul(denominator).sub(E.SecureFor(F).one()));
    prefix(F, E.mulBaseFor(F, inverse, weight), current, previous, first, last, claim, sink);
}
