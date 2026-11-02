//! The existing integer product authority, with affine strict pairs and ONE
//! joint BYTE/FUNCTION prefix. No multiplication semantics are copied here.
const E = @import("../../evaluation.zig");
const Old = @import("provider.zig");
const L = @import("degree3_layout.zig");
pub const ChallengesFor = Old.ChallengesFor;
pub const Challenges = Old.Challenges;
pub fn evaluateFor(comptime F: type, geometry: [L.FIXED]F, main: *const [L.MAIN]F, current: *const [L.INTERACTION]F, previous_prefix: E.SecureFor(F), previous_count: F, count: F, ch: ChallengesFor(E.ConstFor(F)), alpha: E.ConstFor(F), claim: E.ConstFor(F), out: *E.SinkFor(F)) void {
    const S = E.SecureFor(F);
    Old.arithmeticFor(F, geometry, main, previous_count, count, out);
    const bytes = Old.byteValuesFor(F, main);
    var contribution = S.zero();
    for (0..L.BYTE_PAIRS) |pair| {
        const x = E.splatFor(F, alpha).sub(E.liftFor(F, bytes[2 * pair]));
        const y = E.splatFor(F, alpha).sub(E.liftFor(F, bytes[2 * pair + 1]));
        const inverse = E.secureFor(F, current, 4 * pair);
        out.emit(x.mul(y).mul(inverse).sub(S.one()));
        contribution = contribution.add(x.add(y).mul(inverse));
    }
    const inverse = E.secureFor(F, current, L.FUNCTION_INVERSE);
    out.emit(inverse.mul(E.denominatorFor(F, ch.offset, &ch.coefficients, &Old.tupleFor(F, main), false)).sub(S.one()));
    contribution = contribution.sub(E.mulBaseFor(F, inverse, Old.activeFor(F, main)));
    const prefix = E.secureFor(F, current, L.PREFIX);
    out.emit(prefix.sub(previous_prefix).add(E.mulBaseFor(F, E.splatFor(F, claim), geometry[1])).sub(contribution));
    out.emit(E.mulBaseFor(F, prefix, geometry[2]));
}
