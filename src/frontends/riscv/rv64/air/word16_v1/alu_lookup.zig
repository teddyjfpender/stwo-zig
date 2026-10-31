//! D3/2n ALU: twenty U16 memberships, ten strict pair inverses, one prefix,
//! and the shared affine function13 relation. No integer product-of-limbs AIR.
const std = @import("std");
const E = @import("../evaluation.zig");
const A = @import("alu.zig");
const Bus = @import("function_bus.zig");
const Ranges = @import("../providers/scalar_range.zig");
pub const MAIN = A.LOCAL_MAIN + 1;
pub const INTERACTION = 52;
pub const CONSTRAINTS = A.CONSTRAINTS + 16;
pub const Challenges = struct { range16: Ranges.Challenges, function: Bus.Challenges };
pub const Claims = struct { range16: E.Q, function: E.Q };
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
pub fn emitFor(comptime F: type, main: []const F, current: []const F, previous: []const F, first: F, last: F, claims: Claims, ch: Challenges, sink: anytype) void {
    const S = E.SecureFor(F);
    const row = rowFromColumnsFor(F, main);
    A.emitFor(F, &row, sink);
    const multiplicity = main[A.LOCAL_MAIN];
    sink.emit(F.one().sub(row.active).mul(multiplicity));
    var contribution = S.zero();
    for (0..10) |batch| {
        const dx = ch.range16.denominatorFor(F, A.rangeValueFor(F, &row, 2 * batch));
        const dy = ch.range16.denominatorFor(F, A.rangeValueFor(F, &row, 2 * batch + 1));
        const inverse = E.secureFor(F, current, 4 * batch);
        sink.emit(dx.mul(dy).mul(inverse).sub(S.one()));
        contribution = contribution.add(dx.add(dy).mul(inverse));
    }
    const sum = E.secureFor(F, current, 40);
    sink.emit(sum.sub(E.secureFor(F, previous, 40)).add(E.mulBaseFor(F, E.splatFor(F, claims.range16), first)).sub(contribution));
    sink.emit(E.mulBaseFor(F, sum, last));
    Bus.emitFor(F, row.payload, multiplicity.neg(), first, last, E.secureFor(F, current, 44), E.secureFor(F, current, 48), E.secureFor(F, previous, 48), claims.function, ch.function, sink);
}
