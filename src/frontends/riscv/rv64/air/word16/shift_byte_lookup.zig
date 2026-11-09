//! Complete paired D3 SHIFT polynomial. No challenge sampling or native row
//! classification occurs here; scalar OODS and SIMD domains share this emitter.
const E = @import("../evaluation.zig");
const S = @import("shift_byte.zig");
const Bus = @import("function_bus.zig");
const Range = @import("../providers/scalar_range.zig");
const Pair = @import("shift_lookup_pair.zig");
const Tables = @import("../providers/tables.zig");
pub const MAIN = S.LOCAL_MAIN + 1;
pub const INTERACTION = 56;
pub const CONSTRAINTS = S.CONSTRAINTS + 18;
pub const Challenges = struct { shift: Tables.Challenges, range16: Range.Challenges, function: Bus.Challenges };
pub const Claims = struct { shift: E.Q, range16: E.Q, function: E.Q };

pub fn emitFor(comptime F: type, main: []const F, current: []const F, previous: []const F, first: F, last: F, claims: Claims, ch: Challenges, sink: *E.SinkFor(F)) void {
    const Secure = E.SecureFor(F);
    const row = S.rowFromColumnsFor(F, main);
    S.emitFor(F, &row, sink);
    const multiplicity = main[S.LOCAL_MAIN];
    sink.emit(F.one().sub(row.active).mul(multiplicity));
    var shift_sum = Secure.zero();
    var range_sum = Secure.zero();
    for (0..5) |batch| {
        const a = S.tableTupleFor(F, &row, 2 * batch);
        const da = E.denominatorFor(F, ch.shift.offset, &ch.shift.coefficients, &a, true);
        const ra = ch.range16.denominatorFor(F, S.rangeValueFor(F, &row, 2 * batch));
        var db: ?Secure = null;
        var rb: ?Secure = null;
        if (2 * batch + 1 < 9) {
            const b = S.tableTupleFor(F, &row, 2 * batch + 1);
            db = E.denominatorFor(F, ch.shift.offset, &ch.shift.coefficients, &b, true);
            rb = ch.range16.denominatorFor(F, S.rangeValueFor(F, &row, 2 * batch + 1));
        }
        const shift = Pair.forDenominators(F, da, db, E.secureFor(F, current, 4 * batch));
        const range = Pair.forDenominators(F, ra, rb, E.secureFor(F, current, 24 + 4 * batch));
        sink.emit(shift.residual);
        sink.emit(range.residual);
        shift_sum = shift_sum.add(shift.contribution);
        range_sum = range_sum.add(range.contribution);
    }
    Range.prefix(F, shift_sum, E.secureFor(F, current, 20), E.secureFor(F, previous, 20), first, last, claims.shift, sink);
    Range.prefix(F, range_sum, E.secureFor(F, current, 44), E.secureFor(F, previous, 44), first, last, claims.range16, sink);
    Bus.emitFor(F, row.payload, multiplicity.neg(), first, last, E.secureFor(F, current, 48), E.secureFor(F, current, 52), E.secureFor(F, previous, 52), claims.function, ch.function, sink);
}
