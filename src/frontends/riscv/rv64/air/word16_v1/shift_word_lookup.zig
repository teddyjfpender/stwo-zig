//! Concrete D3 Word16 SHIFT lookup polynomial; BYTE has a separate component.
const E = @import("../evaluation.zig");
const S = @import("shift_word.zig");
const Bus = @import("function_bus.zig");
const Range = @import("../providers/scalar_range.zig");
const Table = @import("shift_word_table.zig");
const Pair = @import("shift_lookup_pair.zig");
pub const MAIN = S.LOCAL_MAIN + 1;
pub const encoding = @import("shift_word_encoding.zig");
pub const INTERACTION = encoding.INTERACTION;
pub const FUNCTION_INVERSE = encoding.FUNCTION_INVERSE;
pub const PREFIX = encoding.PREFIX;
pub const CONSTRAINTS = S.CONSTRAINTS + encoding.PAIRS + 4;
pub const Challenges = struct { shift: Table.Challenges, range16: Range.Challenges, function: Bus.Challenges };
pub const Claims = struct { shift: E.Q, range16: E.Q, function: E.Q };
pub fn ChallengesFor(comptime C: type) type {
    if (C == E.Q) return Challenges;
    return struct { shift: struct { offset: C, coefficients: [6]C }, range16: struct { offset: C, coefficient: C }, function: struct { offset: C, coefficients: [13]C } };
}
pub fn ClaimsFor(comptime C: type) type {
    if (C == E.Q) return Claims;
    return struct { shift: C, range16: C, function: C };
}
/// First five unit queries are SHIFT, then nine U16. The third pair crosses
/// the family boundary; both denominators are affine and both weights are1.
pub fn unitDenominatorFor(comptime F: type, row: *const S.RowFor(F), query: usize, ch: ChallengesFor(E.ConstFor(F))) E.SecureFor(F) {
    if (query < 5) {
        const tuple = S.tableTupleFor(F, row, query);
        return E.denominatorFor(F, ch.shift.offset, &ch.shift.coefficients, &tuple, true);
    }
    return Range.affineDenominatorFor(F, ch.range16.offset, ch.range16.coefficient, S.rangeValueFor(F, row, query - 5));
}
pub fn emitFor(comptime F: type, main: []const F, current: []const F, previous: []const F, first: F, last: F, claims: ClaimsFor(E.ConstFor(F)), ch: ChallengesFor(E.ConstFor(F)), sink: *E.SinkFor(F)) void {
    const Secure = E.SecureFor(F);
    const row = S.rowFromColumnsFor(F, main);
    S.emitFor(F, &row, sink);
    const multiplicity = main[S.LOCAL_MAIN];
    sink.emit(F.one().sub(row.active).mul(multiplicity));
    var contribution = Secure.zero();
    for (0..encoding.PAIRS) |pair| {
        const a = unitDenominatorFor(F, &row, 2 * pair, ch);
        const b = unitDenominatorFor(F, &row, 2 * pair + 1, ch);
        const value = Pair.forDenominators(F, a, b, E.secureFor(F, current, 4 * pair));
        sink.emit(value.residual);
        contribution = contribution.add(value.contribution);
    }
    const inverse = E.secureFor(F, current, FUNCTION_INVERSE);
    sink.emit(E.denominatorFor(F, ch.function.offset, &ch.function.coefficients, &row.payload, true).mul(inverse).sub(Secure.one()));
    contribution = contribution.sub(E.mulBaseFor(F, inverse, multiplicity));
    const sum = E.secureFor(F, current, PREFIX);
    sink.emit(sum.sub(E.secureFor(F, previous, PREFIX)).add(E.mulBaseFor(F, E.splatFor(F, claims.shift.add(claims.range16).add(claims.function)), first)).sub(contribution));
    sink.emit(E.mulBaseFor(F, sum, last));
}
