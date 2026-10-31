//! Concrete D3 Word16 SHIFT lookup polynomial; BYTE has a separate component.
const E = @import("../evaluation.zig");
const S = @import("shift_word.zig");
const Bus = @import("function_bus.zig");
const Range = @import("../providers/scalar_range.zig");
const Table = @import("shift_word_table.zig");
const Pair = @import("shift_lookup_pair.zig");
pub const MAIN = S.LOCAL_MAIN + 1;
pub const INTERACTION = 48;
pub const CONSTRAINTS = S.CONSTRAINTS + 16;
pub const Challenges = struct { shift: Table.Challenges, range16: Range.Challenges, function: Bus.Challenges };
pub const Claims = struct { shift: E.Q, range16: E.Q, function: E.Q };
pub fn emitFor(comptime F: type, main: []const F, current: []const F, previous: []const F, first: F, last: F, claims: Claims, ch: Challenges, sink: *E.SinkFor(F)) void {
    const Secure = E.SecureFor(F);
    const row = S.rowFromColumnsFor(F, main);
    S.emitFor(F, &row, sink);
    const multiplicity = main[S.LOCAL_MAIN];
    sink.emit(F.one().sub(row.active).mul(multiplicity));
    var shift_sum = Secure.zero();
    for (0..3) |batch| {
        const a = S.tableTupleFor(F, &row, 2 * batch);
        const da = E.denominatorFor(F, ch.shift.offset, &ch.shift.coefficients, &a, true);
        var db: ?Secure = null;
        if (2 * batch + 1 < 5) {
            const b = S.tableTupleFor(F, &row, 2 * batch + 1);
            db = E.denominatorFor(F, ch.shift.offset, &ch.shift.coefficients, &b, true);
        }
        const pair = Pair.forDenominators(F, da, db, E.secureFor(F, current, 4 * batch));
        sink.emit(pair.residual);
        shift_sum = shift_sum.add(pair.contribution);
    }
    var range_sum = Secure.zero();
    for (0..5) |batch| {
        const a = ch.range16.denominatorFor(F, S.rangeValueFor(F, &row, 2 * batch));
        const b: ?Secure = if (2 * batch + 1 < 9) ch.range16.denominatorFor(F, S.rangeValueFor(F, &row, 2 * batch + 1)) else null;
        const pair = Pair.forDenominators(F, a, b, E.secureFor(F, current, 16 + 4 * batch));
        sink.emit(pair.residual);
        range_sum = range_sum.add(pair.contribution);
    }
    Range.prefix(F, shift_sum, E.secureFor(F, current, 12), E.secureFor(F, previous, 12), first, last, claims.shift, sink);
    Range.prefix(F, range_sum, E.secureFor(F, current, 36), E.secureFor(F, previous, 36), first, last, claims.range16, sink);
    Bus.emitFor(F, row.payload, multiplicity.neg(), first, last, E.secureFor(F, current, 40), E.secureFor(F, current, 44), E.secureFor(F, previous, 44), claims.function, ch.function, sink);
}
