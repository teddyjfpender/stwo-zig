//! Typed DIV/REM operand/result bus. Requests and provider rows share these
//! challenges only after all producer and provider main columns are committed.
const E = @import("../../evaluation.zig");
const D = @import("layout.zig");
const ops = @import("../../operations.zig");
/// Bus challenges over constant lane C (QM31 natively, external wires otherwise).
pub fn ChallengesFor(comptime C: type) type {
    return struct {
        offset: C,
        coefficients: [D.TUPLE]C,
        pub fn draw(channel: *@import("../../protocol.zig").Channel) @This() {
            // Explicit relation version and tuple tag, independent of ROM/range.
            channel.mixU32s(&.{ 0x44495632, D.TUPLE });
            var result: @This() = undefined;
            result.offset = channel.drawSecureFelt();
            for (&result.coefficients) |*coefficient| coefficient.* = channel.drawSecureFelt();
            return result;
        }
        pub fn denominator(self: @This(), entry: *const D.Tuple) E.Q {
            var result = self.offset;
            for (self.coefficients, entry) |coefficient, value| result = result.add(coefficient.mul(value));
            return result;
        }
    };
}
pub const Challenges = ChallengesFor(E.Q);
pub fn evaluate(geometry: [D.FIXED]E.Q, physical: *const D.Physical, current: *const [D.INTERACTION]E.Q, previous: *const [D.INTERACTION]E.Q, previous_count: E.Q, public_count: usize, challenges: Challenges, claim: E.Q, out: *E.Sink) void {
    return evaluateFor(E.Q, geometry, physical, current, previous, previous_count, E.q(@intCast(public_count)), challenges, claim, out);
}
/// The same authorities constrain CPU reference rows, provider domain points
/// and provider OODS points over any lane. No native division is verifier authority.
pub fn evaluateFor(comptime F: type, geometry: [D.FIXED]F, physical: *const [D.MAIN]F, current: *const [D.INTERACTION]F, previous: *const [D.INTERACTION]F, previous_count: F, public_count: F, challenges: ChallengesFor(E.ConstFor(F)), claim: E.ConstFor(F), out: *E.SinkFor(F)) void {
    var fixed: E.FixedFor(F) = undefined;
    var logical: E.MainFor(F) = undefined;
    D.inflateGeneric(F, physical, &fixed, &logical);
    const v = E.ViewFor(F){ .f = &fixed, .m = &logical };
    var selected = F.zero();
    for (physical[0..D.OPCODES.len]) |selector| {
        E.booleanFor(F, out, selector);
        selected = selected.add(selector);
    }
    E.booleanFor(F, out, selected);
    const count = physical[D.COUNT];
    out.emit(count.sub(F.one().sub(geometry[1]).mul(previous_count)).sub(selected));
    out.emit(geometry[1].mul(count.sub(selected)));
    out.emit(geometry[2].mul(count.sub(public_count)));
    for (D.WORDS, 0..) |word, w| {
        for (0..64) |bit| E.booleanFor(F, out, physical[D.WORD_START + w * 64 + bit]);
        for (0..8) |i| out.emit(F.one().sub(selected).mul(v.byte(word, i)));
    }
    for (D.CARRIES) |kind| for (0..8) |i| {
        const value = v.carry(kind, i);
        E.booleanFor(F, out, value);
        var enable = F.zero();
        for (D.OPCODES) |op| if (ops.carryActive(kind, i, op)) {
            enable = enable.add(v.op(op));
        };
        out.emit(F.one().sub(enable).mul(value));
    };
    for ([_]usize{ E.L.divisor_zero, E.L.sign_a, E.L.sign_b, E.L.negate, E.L.apply_negate }) |column| E.booleanFor(F, out, logical[column]);
    const word = v.sum(&.{ .DIVW, .DIVUW, .REMW, .REMUW });
    for (4..8) |i| out.emit(word.mul(v.byte(.result, i).sub(v.bit(.result, 31).mul(E.qFor(F, 255)))));
    @import("../../product_constraints.zig").evaluateGeneric(F, v, out);
    @import("../../division_constraints.zig").evaluateGeneric(F, v, out);
    const entry = D.tupleGeneric(F, &fixed, &logical);
    const inverse = E.secureFor(F, current, 0);
    const sum = E.secureFor(F, current, 4);
    const prior = E.secureFor(F, previous, 4);
    out.emit(E.denominatorFor(F, challenges.offset, &challenges.coefficients, &entry, false).mul(inverse).sub(E.liftFor(F, selected)));
    out.emit(E.mulBaseFor(F, inverse, F.one().sub(selected)));
    out.emit(sum.sub(E.mulBaseFor(F, prior, F.one().sub(geometry[1]))).add(inverse));
    out.emit(E.mulBaseFor(F, sum.add(inverse), geometry[1]));
    out.emit(E.mulBaseFor(F, sum.sub(E.splatFor(F, claim)), geometry[2]));
}
