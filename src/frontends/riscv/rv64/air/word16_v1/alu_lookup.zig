//! D3/2n ALU: twenty U16 memberships, ten strict pair inverses, one JOINT prefix
//! for ranges and the shared affine function13 relation. No integer product-of-limbs AIR.
const std = @import("std");
const E = @import("../evaluation.zig");
const A = @import("alu.zig");
const Bus = @import("function_bus.zig");
const Ranges = @import("../providers/scalar_range.zig");
pub const MAIN = A.encoding.MAIN;
pub const INTERACTION = A.encoding.INTERACTION;
pub const CONSTRAINTS = A.CONSTRAINTS + 14;
pub const FUNCTION_INVERSE = A.encoding.FUNCTION_INVERSE;
pub const PREFIX = A.encoding.PREFIX;
pub const Challenges = struct { range16: Ranges.Challenges, function: Bus.Challenges };
pub const Claims = struct { range16: E.Q, function: E.Q };
/// Only the arithmetic constant lane varies; native public types stay exact.
pub fn ClaimsFor(comptime C: type) type {
    if (C == E.Q) return Claims;
    return struct { range16: C, function: C };
}
pub fn ChallengesFor(comptime C: type) type {
    if (C == E.Q) return Challenges;
    return struct { range16: struct { offset: C, coefficient: C }, function: struct { offset: C, coefficients: [13]C } };
}

pub fn rowFromColumnsFor(comptime F: type, values: []const F) A.RowFor(F) {
    std.debug.assert(values.len >= A.LOCAL_MAIN);
    var row: A.RowFor(F) = undefined;
    var cursor: usize = 0;
    inline for (std.meta.fields(A.RowFor(F))) |field| {
        if (@typeInfo(field.type) == .array) {
            const n = @typeInfo(field.type).array.len;
            @memcpy(&@field(row, field.name), values[cursor..][0..n]);
            cursor += n;
        } else {
            @field(row, field.name) = values[cursor];
            cursor += 1;
        }
    }
    std.debug.assert(cursor == A.LOCAL_MAIN);
    return row;
}
pub fn rowToColumnsFor(comptime F: type, row: A.RowFor(F)) [A.LOCAL_MAIN]F {
    var values: [A.LOCAL_MAIN]F = undefined;
    var cursor: usize = 0;
    inline for (std.meta.fields(A.RowFor(F))) |field| {
        if (@typeInfo(field.type) == .array) {
            const n = @typeInfo(field.type).array.len;
            @memcpy(values[cursor..][0..n], &@field(row, field.name));
            cursor += n;
        } else {
            values[cursor] = @field(row, field.name);
            cursor += 1;
        }
    }
    return values;
}
pub fn emitFor(comptime F: type, main: []const F, current: []const F, previous: []const F, first: F, last: F, claims: ClaimsFor(E.ConstFor(F)), ch: ChallengesFor(E.ConstFor(F)), sink: anytype) void {
    const S = E.SecureFor(F);
    const row = rowFromColumnsFor(F, main);
    A.emitFor(F, &row, sink);
    const multiplicity = main[A.LOCAL_MAIN];
    sink.emit(F.one().sub(row.active).mul(multiplicity));
    var contribution = S.zero();
    for (0..10) |batch| {
        const dx = Ranges.affineDenominatorFor(F, ch.range16.offset, ch.range16.coefficient, A.rangeValueFor(F, &row, 2 * batch));
        const dy = Ranges.affineDenominatorFor(F, ch.range16.offset, ch.range16.coefficient, A.rangeValueFor(F, &row, 2 * batch + 1));
        const inverse = E.secureFor(F, current, 4 * batch);
        sink.emit(dx.mul(dy).mul(inverse).sub(S.one()));
        contribution = contribution.add(dx.add(dy).mul(inverse));
    }
    const inverse = E.secureFor(F, current, FUNCTION_INVERSE);
    sink.emit(E.denominatorFor(F, ch.function.offset, &ch.function.coefficients, &row.payload, true).mul(inverse).sub(S.one()));
    contribution = contribution.sub(E.mulBaseFor(F, inverse, multiplicity));
    const sum = E.secureFor(F, current, PREFIX);
    // Two transcript-bound ledger fields, ONE authenticated physical total.
    sink.emit(sum.sub(E.secureFor(F, previous, PREFIX)).add(E.mulBaseFor(F, E.splatFor(F, claims.range16.add(claims.function)), first)).sub(contribution));
    sink.emit(E.mulBaseFor(F, sum, last));
}
