//! Typed DIV/REM operand/result bus. Requests and provider rows share these
//! challenges only after all producer and provider main columns are committed.
const E = @import("../../evaluation.zig");
const D = @import("layout.zig");
const ops = @import("../../operations.zig");
const rom = @import("../../program/provider.zig");
pub const Challenges = struct {
    offset: E.Q,
    coefficients: [D.TUPLE]E.Q,
    pub fn draw(channel: *@import("../../protocol.zig").Channel) Challenges {
        // Explicit relation version and tuple tag, independent of ROM/range.
        channel.mixU32s(&.{ 0x44495632, D.TUPLE });
        var result: Challenges = undefined;
        result.offset = channel.drawSecureFelt();
        for (&result.coefficients) |*coefficient| coefficient.* = channel.drawSecureFelt();
        return result;
    }
    pub fn denominator(self: Challenges, entry: *const D.Tuple) E.Q {
        var result = self.offset;
        for (self.coefficients, entry) |coefficient, value| result = result.add(coefficient.mul(value));
        return result;
    }
};
pub fn evaluate(geometry: [D.FIXED]E.Q, physical: *const D.Physical, current: *const [D.INTERACTION]E.Q, previous: *const [D.INTERACTION]E.Q, previous_count: E.Q, public_count: usize, challenges: Challenges, claim: E.Q, out: *E.Sink) void {
    var fixed: E.Fixed = undefined;
    var logical: E.Main = undefined;
    D.inflate(physical, &fixed, &logical);
    const v = E.View{ .f = &fixed, .m = &logical };
    var selected = E.Q.zero();
    for (physical[0..D.OPCODES.len]) |selector| {
        E.boolean(out, selector);
        selected = selected.add(selector);
    }
    E.boolean(out, selected);
    const count = physical[D.COUNT];
    out.emit(count.sub(E.Q.one().sub(geometry[1]).mul(previous_count)).sub(selected));
    out.emit(geometry[1].mul(count.sub(selected)));
    out.emit(geometry[2].mul(count.sub(E.q(@intCast(public_count)))));
    for (D.WORDS, 0..) |word, w| {
        for (0..64) |bit| E.boolean(out, physical[D.WORD_START + w * 64 + bit]);
        for (0..8) |i| out.emit(E.Q.one().sub(selected).mul(v.byte(word, i)));
    }
    for (D.CARRIES) |kind| for (0..8) |i| {
        const value = v.carry(kind, i);
        E.boolean(out, value);
        var enable = E.Q.zero();
        for (D.OPCODES) |op| if (ops.carryActive(kind, i, op)) {
            enable = enable.add(v.op(op));
        };
        out.emit(E.Q.one().sub(enable).mul(value));
    };
    for ([_]usize{ E.L.divisor_zero, E.L.sign_a, E.L.sign_b, E.L.negate, E.L.apply_negate }) |column| E.boolean(out, logical[column]);
    const word = v.sum(&.{ .DIVW, .DIVUW, .REMW, .REMUW });
    for (4..8) |i| out.emit(word.mul(v.byte(.result, i).sub(v.bit(.result, 31).mul(E.q(255)))));
    // The same authorities constrain CPU reference rows, provider domain points
    // and provider OODS points. No native division is verifier authority.
    @import("../../product_constraints.zig").evaluate(v, out);
    @import("../../division_constraints.zig").evaluate(v, out);
    const entry = D.tuple(&fixed, &logical);
    const inverse = rom.secure(current, 0);
    const sum = rom.secure(current, 4);
    const prior = rom.secure(previous, 4);
    out.emit(challenges.denominator(&entry).mul(inverse).sub(selected));
    out.emit(E.Q.one().sub(selected).mul(inverse));
    out.emit(sum.sub(E.Q.one().sub(geometry[1]).mul(prior)).add(inverse));
    out.emit(geometry[1].mul(sum.add(inverse)));
    out.emit(geometry[2].mul(sum.sub(claim)));
}
