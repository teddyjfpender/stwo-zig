//! Diagnostic closed BINARY chip equations. Pair batching keeps the complete
//! chip at degree three / a 2n quotient domain, with explicit pole inverses.
const std = @import("std");
const E = @import("../evaluation.zig");
const B = @import("binary.zig");
const Tables = @import("../providers/tables.zig");
pub const MAIN = B.LOCAL_MAIN + 1; // final column is committed fact multiplicity.
pub const INTERACTION = 28; // AND:4 inverses+prefix; function:inverse+prefix.
pub const CONSTRAINTS = B.CONSTRAINTS + 10;
const FunctionBus = @import("function_bus.zig");
pub const FunctionChallenges = FunctionBus.Challenges;
pub const Challenges = struct { and_: Tables.Challenges, function: FunctionChallenges };
pub const Claims = struct { and_: E.Q, function: E.Q };

pub fn rowFromColumnsFor(comptime F: type, values: []const F) B.RowFor(F) {
    std.debug.assert(values.len >= B.LOCAL_MAIN);
    var row: B.RowFor(F) = undefined;
    var cursor: usize = 0;
    inline for (std.meta.fields(B.RowFor(F))) |field| {
        if (@typeInfo(field.type) == .array) {
            const n = @typeInfo(field.type).array.len;
            @memcpy(&@field(row, field.name), values[cursor..][0..n]);
            cursor += n;
        } else {
            @field(row, field.name) = values[cursor];
            cursor += 1;
        }
    }
    std.debug.assert(cursor == B.LOCAL_MAIN);
    return row;
}
pub fn rowToColumnsFor(comptime F: type, row: B.RowFor(F)) [B.LOCAL_MAIN]F {
    var values: [B.LOCAL_MAIN]F = undefined;
    var cursor: usize = 0;
    inline for (std.meta.fields(B.RowFor(F))) |field| {
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

/// A cyclic prefix starts at -claim and ends at zero. The explicit inverse
/// equation rejects a pole even when multiplicity is zero.
pub const emitFunctionFor = FunctionBus.emitFor;

pub fn emitFor(comptime F: type, main: []const F, current: []const F, previous: []const F, first: F, last: F, claims: Claims, ch: Challenges, sink: anytype) void {
    const S = E.SecureFor(F);
    const row = rowFromColumnsFor(F, main);
    B.emitFor(F, &row, sink);
    const multiplicity = main[B.LOCAL_MAIN];
    sink.emit(F.one().sub(row.active).mul(multiplicity));
    var contribution = S.zero();
    for (0..4) |batch| {
        const a = ch.and_;
        const x = B.andTupleFor(F, &row, 2 * batch);
        const y = B.andTupleFor(F, &row, 2 * batch + 1);
        const dx = E.denominatorFor(F, a.offset, a.coefficients[0..3], &x, true);
        const dy = E.denominatorFor(F, a.offset, a.coefficients[0..3], &y, true);
        const inverse = E.secureFor(F, current, 4 * batch);
        sink.emit(dx.mul(dy).mul(inverse).sub(S.one()));
        contribution = contribution.add(dx.add(dy).mul(inverse));
    }
    const sum = E.secureFor(F, current, 16);
    sink.emit(sum.sub(E.secureFor(F, previous, 16)).add(E.mulBaseFor(F, E.splatFor(F, claims.and_), first)).sub(contribution));
    sink.emit(E.mulBaseFor(F, sum, last));
    emitFunctionFor(F, row.payload, multiplicity.neg(), first, last, E.secureFor(F, current, 20), E.secureFor(F, current, 24), E.secureFor(F, previous, 24), claims.function, ch.function, sink);
}
