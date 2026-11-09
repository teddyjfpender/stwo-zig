//! D3/2n ALU (main47, derived op/C payload): twelve U16 memberships, six strict pair inverses, one JOINT prefix
//! for ranges and the shared affine function13 relation. No integer product-of-limbs AIR.
const std = @import("std");
const E = @import("../evaluation.zig");
const A = @import("alu.zig");
const Bus = @import("function_bus.zig");
const Ranges = @import("../providers/scalar_range.zig");
pub const MAIN = A.encoding.MAIN;
pub const INTERACTION = A.encoding.INTERACTION;
pub const CONSTRAINTS = A.PROJECTED_CONSTRAINTS + A.RANGE_QUERIES / 2 + 4;
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

/// Physical MAIN commits only A/B of the payload. op and C are derived at
/// every native, packed, OODS and external-circuit evaluation.
pub fn rowFromColumnsFor(comptime F: type, values: []const F) A.RowFor(F) {
    std.debug.assert(values.len >= A.LOCAL_MAIN);
    var row: A.RowFor(F) = undefined;
    var cursor: usize = 0;
    inline for (std.meta.fields(A.RowFor(F))) |field| {
        if (comptime std.mem.eql(u8, field.name, "payload")) {
            @memcpy(row.payload[A.COMMITTED_PAYLOAD_START..A.COMMITTED_PAYLOAD_END], values[cursor..][0 .. A.COMMITTED_PAYLOAD_END - A.COMMITTED_PAYLOAD_START]);
            cursor += A.COMMITTED_PAYLOAD_END - A.COMMITTED_PAYLOAD_START;
        } else if (@typeInfo(field.type) == .array) {
            const n = @typeInfo(field.type).array.len;
            @memcpy(&@field(row, field.name), values[cursor..][0..n]);
            cursor += n;
        } else {
            @field(row, field.name) = values[cursor];
            cursor += 1;
        }
    }
    std.debug.assert(cursor == A.LOCAL_MAIN);
    A.derivePayloadFor(F, &row);
    return row;
}
pub fn rowToColumnsFor(comptime F: type, row: A.RowFor(F)) [A.LOCAL_MAIN]F {
    var values: [A.LOCAL_MAIN]F = undefined;
    var cursor: usize = 0;
    inline for (std.meta.fields(A.RowFor(F))) |field| {
        if (comptime std.mem.eql(u8, field.name, "payload")) {
            @memcpy(values[cursor..][0 .. A.COMMITTED_PAYLOAD_END - A.COMMITTED_PAYLOAD_START], row.payload[A.COMMITTED_PAYLOAD_START..A.COMMITTED_PAYLOAD_END]);
            cursor += A.COMMITTED_PAYLOAD_END - A.COMMITTED_PAYLOAD_START;
        } else if (@typeInfo(field.type) == .array) {
            const n = @typeInfo(field.type).array.len;
            @memcpy(values[cursor..][0..n], &@field(row, field.name));
            cursor += n;
        } else {
            values[cursor] = @field(row, field.name);
            cursor += 1;
        }
    }
    std.debug.assert(cursor == A.LOCAL_MAIN);
    return values;
}
/// Opt-in fused-tail layout (Geometry.alu_fused_tail): 28 instead of 32
/// interaction columns, the same LogUp statement. The FUNCTION denominator is
/// quadratic (derived payload), so the strict FUNCTION inverse cannot be fused
/// at degree 3; instead every committed slot is a degree-one fraction and the
/// LAST U16 pair is fused into the prefix:
///   K_j*dx*dy = dx + dy (j < 5), G*d_fn = multiplicity,
///   (S - S' + claim*first - sum K + G)*dx5*dy5 - (dx5 + dy5) = 0.
/// If every pole is nonzero these force the legacy increment. A one-sided pole
/// with nonzero numerator is unsatisfiable; d_fn = 0 with multiplicity 0 frees
/// G. Each denominator is z - <alpha, tuple> with the tuple committed before
/// (z, alpha), so the 13 non-strict poles per row occur with probability at
/// most 13*2*2^22/|QM31| < 2^-96 per proof (d_fn has degree 2 in MAIN but
/// degree 1 in z). Range closure uses only the rational identity.
pub const fused = struct {
    pub const PAIR_WITNESSES = A.RANGE_QUERIES / 2 - 1;
    pub const FUNCTION = 4 * PAIR_WITNESSES;
    pub const PREFIX = FUNCTION + 4;
    pub const INTERACTION = FUNCTION + 8;
    /// One fewer interaction residual (the legacy FUNCTION inverse and six
    /// pair inverses become five fractions, the FUNCTION fraction and the fused tail).
    pub const CONSTRAINTS = A.PROJECTED_CONSTRAINTS + A.RANGE_QUERIES / 2 + 3;
};
comptime {
    if (fused.INTERACTION != 28 or fused.CONSTRAINTS + 1 != CONSTRAINTS) @compileError("ALU fused-tail ledger mismatch");
}
/// Separate transcript domain, mixed ONLY when Geometry.alu_fused_tail is set.
pub fn fusedIdentity() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("rv64.word16.alu.fused-tail.v1:inter28/D3;K_j*dx*dy=dx+dy (pairs 0..4);G*d_fn=multiplicity;fused((S-S'+claim*first-sumK+G)*dx5*dy5-(dx5+dy5));last*S");
    return hash.finalResult();
}
pub fn emitFusedFor(comptime F: type, main: []const F, current: []const F, previous: []const F, first: F, last: F, claims: ClaimsFor(E.ConstFor(F)), ch: ChallengesFor(E.ConstFor(F)), sink: anytype) void {
    const S = E.SecureFor(F);
    const row = rowFromColumnsFor(F, main);
    A.emitProjectedFor(F, &row, sink);
    const multiplicity = main[A.LOCAL_MAIN];
    sink.emit(F.one().sub(row.active).mul(multiplicity));
    var contribution = S.zero();
    for (0..fused.PAIR_WITNESSES) |batch| {
        const dx = Ranges.affineDenominatorFor(F, ch.range16.offset, ch.range16.coefficient, A.rangeValueFor(F, &row, 2 * batch));
        const dy = Ranges.affineDenominatorFor(F, ch.range16.offset, ch.range16.coefficient, A.rangeValueFor(F, &row, 2 * batch + 1));
        const k = E.secureFor(F, current, 4 * batch);
        sink.emit(dx.mul(dy).mul(k).sub(dx.add(dy)));
        contribution = contribution.add(k);
    }
    const g = E.secureFor(F, current, fused.FUNCTION);
    sink.emit(E.denominatorFor(F, ch.function.offset, &ch.function.coefficients, &row.payload, true).mul(g).sub(E.liftFor(F, multiplicity)));
    contribution = contribution.sub(g);
    const last_pair = A.RANGE_QUERIES / 2 - 1;
    const dx = Ranges.affineDenominatorFor(F, ch.range16.offset, ch.range16.coefficient, A.rangeValueFor(F, &row, 2 * last_pair));
    const dy = Ranges.affineDenominatorFor(F, ch.range16.offset, ch.range16.coefficient, A.rangeValueFor(F, &row, 2 * last_pair + 1));
    const sum = E.secureFor(F, current, fused.PREFIX);
    const step = sum.sub(E.secureFor(F, previous, fused.PREFIX)).add(E.mulBaseFor(F, E.splatFor(F, claims.range16.add(claims.function)), first)).sub(contribution);
    sink.emit(step.mul(dx).mul(dy).sub(dx.add(dy)));
    sink.emit(E.mulBaseFor(F, sum, last));
}
pub fn emitFor(comptime F: type, main: []const F, current: []const F, previous: []const F, first: F, last: F, claims: ClaimsFor(E.ConstFor(F)), ch: ChallengesFor(E.ConstFor(F)), sink: anytype) void {
    const S = E.SecureFor(F);
    const row = rowFromColumnsFor(F, main);
    A.emitProjectedFor(F, &row, sink);
    const multiplicity = main[A.LOCAL_MAIN];
    sink.emit(F.one().sub(row.active).mul(multiplicity));
    var contribution = S.zero();
    for (0..A.RANGE_QUERIES / 2) |batch| {
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
