//! Positive lookup consumers for shared AND and byte-shift providers. Three
//! linear tuple denominators share one inverse, retaining degree four.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const E = @import("../evaluation.zig");
const L = E.L;
const Plan = @import("../encoding.zig").Plan;
const Tables = @import("../providers/tables.zig");
const Cpu = @import("cpu.zig");
const W = @import("../witness.zig");
pub const Kind = Tables.Kind;
pub fn requests(plan: *const Plan, kind: Kind) usize {
    return switch (kind) {
        .byte_and => if (plan.byte_bitwise) 8 else 0,
        .byte_shift => if (plan.support.shifts) 9 else 0,
    };
}
pub fn interactionCount(plan: *const Plan, kind: Kind) usize {
    const count = requests(plan, kind);
    return if (count == 0) 0 else ((count + 2) / 3 + 1) * 4;
}
pub fn tuple(plan: *const Plan, kind: Kind, logical: *const E.Main, physical: []const Q, request: usize) [6]Q {
    return tupleFor(Q, plan, kind, logical, physical, request);
}
pub fn tupleFor(comptime F: type, plan: *const Plan, kind: Kind, logical: *const E.MainFor(F), physical: []const F, request: usize) [6]F {
    return switch (kind) {
        .byte_and => .{ logical[L.byte(.a, request)], logical[L.byte(.rhs, request)], physical[plan.and_start + request], F.zero(), F.zero(), F.zero() },
        .byte_shift => .{ if (request == 8) E.qFor(F, 255) else logical[L.byte(.a, request)], physical[plan.shift_amount], physical[plan.shift_outputs + request * 4], physical[plan.shift_outputs + request * 4 + 1], physical[plan.shift_outputs + request * 4 + 2], physical[plan.shift_outputs + request * 4 + 3] },
    };
}
pub fn evaluate(plan: *const Plan, kind: Kind, logical: *const E.Main, physical: []const Q, current: []const Q, previous: []const Q, first: Q, last: Q, challenges: Tables.Challenges, claim: Q, out: *E.Sink) void {
    return evaluateFor(Q, plan, kind, logical, physical, current, previous, first, last, challenges, claim, out);
}
pub fn evaluateFor(comptime F: type, plan: *const Plan, kind: Kind, logical: *const E.MainFor(F), physical: []const F, current: []const F, previous: []const F, first: F, last: F, challenges: Tables.ChallengesFor(E.ConstFor(F)), claim: E.ConstFor(F), out: *E.SinkFor(F)) void {
    const count = requests(plan, kind);
    if (count == 0) return;
    const S = E.SecureFor(F);
    const batches = (count + 2) / 3;
    var contribution = S.zero();
    for (0..batches) |batch| {
        var numerator = S.zero();
        var denominator = S.one();
        for (batch * 3..@min(count, batch * 3 + 3)) |request| {
            const values = tupleFor(F, plan, kind, logical, physical, request);
            const d = E.denominatorFor(F, challenges.offset, challenges.coefficients[0..kind.arity()], values[0..kind.arity()], true);
            numerator = numerator.mul(d).add(denominator);
            denominator = denominator.mul(d);
        }
        const inverse = Cpu.secureFor(F, current, batch * 4);
        out.emit(denominator.mul(inverse).sub(S.one()));
        contribution = contribution.add(numerator.mul(inverse));
    }
    const sum = Cpu.secureFor(F, current, batches * 4);
    out.emit(sum.sub(E.mulBaseFor(F, Cpu.secureFor(F, previous, batches * 4), F.one().sub(first))).sub(contribution));
    out.emit(E.mulBaseFor(F, sum.sub(E.splatFor(F, claim)), last));
}

/// Validates witness tuples while counting; the verifier uses only authenticated
/// fixed provider rows and polynomial closure, never this host validation.
pub fn counts(a: std.mem.Allocator, plan: *const Plan, kind: Kind, columns: []const []const M) ![]u64 {
    if (columns.len != plan.main_count or columns.len == 0) return error.InvalidLookupGeometry;
    const result = try a.alloc(u64, kind.size());
    errdefer a.free(result);
    @memset(result, 0);
    var physical: [L.MAIN]Q = undefined;
    const size = columns[0].len;
    for (columns) |column| if (column.len != size) return error.InvalidLookupGeometry;
    for (0..size) |row| {
        for (columns, 0..) |column, c| physical[c] = Q.fromBase(column[row]);
        const logical = plan.inflateMain(physical[0..plan.main_count]);
        for (0..requests(plan, kind)) |request| {
            const values = tuple(plan, kind, &logical, physical[0..plan.main_count], request);
            var base: Tables.Tuple = undefined;
            for (values, 0..) |value, i| base[i] = (try value.tryIntoM31()).v;
            const index = try kind.rowIndex(base);
            result[index] = try std.math.add(u64, result[index], 1);
        }
    }
    return result;
}
pub fn buildInteraction(a: std.mem.Allocator, plan: *const Plan, kind: Kind, columns: []const []const M, log_size: u32, challenges: Tables.Challenges) !Cpu.Columns {
    if (log_size >= @bitSizeOf(usize) or columns.len != plan.main_count or requests(plan, kind) == 0) return error.InvalidLookupGeometry;
    const size = @as(usize, 1) << @intCast(log_size);
    for (columns) |column| if (column.len != size) return error.InvalidLookupGeometry;
    const storage = try a.alloc(M, try std.math.mul(usize, size, interactionCount(plan, kind)));
    errdefer a.free(storage);
    // A challenge-dependent dictionary is bounded by the provider, rather than
    // the execution height. Repeated operations never repeat field inversion.
    const inverses = try a.alloc(Q, kind.size());
    defer a.free(inverses);
    for (inverses, 0..) |*inverse, index| {
        const values = kind.tupleAt(index);
        var secure_tuple: [Tables.MAX_ARITY]Q = undefined;
        for (&secure_tuple, values) |*value, base| value.* = Q.fromBase(M.fromCanonical(base));
        inverse.* = try challenges.denominator(secure_tuple[0..kind.arity()]).inv();
    }
    var physical: [L.MAIN]Q = undefined;
    var sum = Q.zero();
    const count = requests(plan, kind);
    const batches = (count + 2) / 3;
    for (0..size) |i| {
        const row = W.physical(i, log_size);
        for (columns, 0..) |column, c| physical[c] = Q.fromBase(column[row]);
        const logical = plan.inflateMain(physical[0..plan.main_count]);
        for (0..batches) |batch| {
            var inverse = Q.one();
            var contribution = Q.zero();
            for (batch * 3..@min(count, batch * 3 + 3)) |request| {
                const values = tuple(plan, kind, &logical, physical[0..plan.main_count], request);
                var base_tuple: Tables.Tuple = undefined;
                for (values, 0..) |value, c| base_tuple[c] = (try value.tryIntoM31()).v;
                const index = try kind.rowIndex(base_tuple);
                inverse = inverse.mul(inverses[index]);
                contribution = contribution.add(inverses[index]);
            }
            store(storage, size, row, batch * 4, inverse);
            sum = sum.add(contribution);
        }
        store(storage, size, row, batches * 4, sum);
    }
    return .{ .allocator = a, .storage = storage, .log_size = log_size, .claim = sum };
}
fn store(storage: []M, size: usize, row: usize, column: usize, value: Q) void {
    for (value.toM31Array(), 0..) |coordinate, i| storage[(column + i) * size + row] = coordinate;
}
