//! Diagnostic closed BINARY chip equations. Pair batching keeps the complete
//! chip at degree three / a 2n quotient domain, with explicit pole inverses.
const std = @import("std");
const E = @import("../evaluation.zig");
const B = @import("binary.zig");
const Tables = @import("../providers/tables.zig");
pub const MAIN = B.LOCAL_MAIN + 1; // final column is committed fact multiplicity.
pub const INTERACTION = 24; // Four AND pair inverses, FUNCTION inverse, one merged prefix.
pub const encoding = @import("binary_encoding.zig");
pub const CONSTRAINTS = B.CONSTRAINTS + 8;
const FunctionBus = @import("function_bus.zig");
pub const FunctionChallenges = FunctionBus.Challenges;
pub const Challenges = struct { and_: Tables.Challenges, function: FunctionChallenges };
/// Only the sum is authenticated by this component. Integrations must close
/// the combined debt against the AND provider and FUNCTION consumers; these
/// fields are an additive ledger decomposition, not separate certificates.
pub const Claims = struct { and_: E.Q, function: E.Q };
pub fn ClaimsFor(comptime C: type) type {
    return if (C == E.Q) Claims else struct { and_: C, function: C };
}
pub fn ChallengesFor(comptime C: type) type {
    if (C == E.Q) return Challenges;
    return struct {
        and_: struct { offset: C, coefficients: [6]C },
        function: struct {
            offset: C,
            coefficients: [13]C,
            pub fn denominatorFor(self: @This(), comptime F: type, tuple: [13]F) E.SecureFor(F) {
                return E.denominatorFor(F, self.offset, &self.coefficients, &tuple, true);
            }
        },
    };
}

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

pub fn emitFor(comptime F: type, main: []const F, current: []const F, previous: []const F, first: F, last: F, claims: ClaimsFor(E.ConstFor(F)), ch: ChallengesFor(E.ConstFor(F)), sink: anytype) void {
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
    const inverse = E.secureFor(F, current, 16);
    sink.emit(inverse.mul(ch.function.denominatorFor(F, row.payload)).sub(S.one()));
    contribution = contribution.sub(E.mulBaseFor(F, inverse, multiplicity));
    const sum = E.secureFor(F, current, 20);
    sink.emit(sum.sub(E.secureFor(F, previous, 20)).add(E.mulBaseFor(F, E.splatFor(F, claims.and_.add(claims.function)), first)).sub(contribution));
    sink.emit(E.mulBaseFor(F, sum, last));
}
