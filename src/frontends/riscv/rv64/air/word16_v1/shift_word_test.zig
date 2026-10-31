const std = @import("std");
const E = @import("../evaluation.zig");
const S = @import("shift_word.zig");
const Ops = @import("operations.zig");
const Tables = @import("../providers/tables.zig");
const WordTable = @import("shift_word_table.zig");
const P = @import("shift_word_lookup.zig");
fn residuals(row: *const S.RowFor(E.Q)) [S.CONSTRAINTS]E.Q {
    var values: [S.CONSTRAINTS]E.Q = undefined;
    var sink = E.Sink{ .values = &values };
    S.emitFor(E.Q, row, &sink);
    std.debug.assert(sink.count == values.len);
    return values;
}
fn expectZero(row: *const S.RowFor(E.Q)) !void {
    for (residuals(row)) |value| try std.testing.expect(value.isZero());
}
test "SHIFT Word16 authority all six modes amounts and ignored high bits have canonical lookup interfaces" {
    const words = [_]u64{ 0, 1, 255, 65535, 0x7fffffff, 0x80000000, 0xffffffff, 0x7fffffffffffffff, 0x8000000000000000, 0xffffffffffffffff, 0x0123456789abcdef };
    for (std.enums.values(Ops.Shift)) |op| for (words) |a| for (0..128) |amount| {
        const row = S.witness(op, a, @as(u64, @intCast(amount)) | 0xfedcba9800000000);
        try expectZero(&row);
        for (0..S.TABLE_QUERIES) |q| {
            const tuple = S.tableTupleFor(E.Q, &row, q);
            var native: Tables.Tuple = undefined;
            for (tuple, 0..) |v, i| native[i] = (try v.tryIntoM31()).v;
            _ = try WordTable.rowIndex(native);
        }
        for (0..S.RANGE_QUERIES) |q| try std.testing.expect((try S.rangeValueFor(E.Q, &row, q).tryIntoM31()).v < 65536);
    };
    var false_result = S.witness(.sll, 1, 1);
    false_result.payload[9] = E.q(3);

    var nonzero = false;
    for (residuals(&false_result)) |value| nonzero = nonzero or !value.isZero();
    try std.testing.expect(nonzero);
}
test "SHIFT direct quotient and sign ranges close genuine locally zero modular aliases" {
    var alias = S.witness(.sll, 1, 0);
    alias.payload[5] = E.Q.one();
    alias.quotient = E.q(1 << 25); // 64^-1 in M31; 64*q=1.
    try expectZero(&alias);
    try std.testing.expect(S.nativeResult(.sll, 1, 1) != 1);
    try std.testing.expectEqual(@as(u32, 1), (try S.rangeValueFor(E.Q, &alias, 5).tryIntoM31()).v);
    try std.testing.expect((try S.rangeValueFor(E.Q, &alias, 4).tryIntoM31()).v >= 65536);
    var sign_alias = S.witness(.sllw, 0, 0);
    sign_alias.sign[2] = E.Q.one();
    sign_alias.payload[11] = E.q(65535);
    sign_alias.payload[12] = E.q(65535);
    try expectZero(&sign_alias);
    try std.testing.expect((try S.rangeValueFor(E.Q, &sign_alias, 8).tryIntoM31()).v >= 65536);
}

test "SHIFT every dense secure residual is cubic and identical across sixteen base and secure lanes" {
    var samples: [5][S.CONSTRAINTS]E.Q = undefined;
    for (0..5) |t| {
        var values: [S.LOCAL_MAIN]E.Q = undefined;
        for (&values, 0..) |*v, i| {
            const x: u32 = @intCast(8 * i + 1);
            v.* = E.Q.fromU32Unchecked(x, x + 1, x + 2, x + 3).add(E.q(@intCast(t)).mul(E.Q.fromU32Unchecked(x + 4, x + 5, x + 6, x + 7)));
        }
        const row = S.rowFromColumnsFor(E.Q, &values);
        samples[t] = residuals(&row);
    }
    var cubic = false;
    for (0..S.CONSTRAINTS) |c| {
        var delta: [5]E.Q = undefined;
        for (&delta, 0..) |*v, i| v.* = samples[i][c];
        for (0..3) |order| for (0..4 - order) |i| {
            delta[i] = delta[i + 1].sub(delta[i]);
        };
        cubic = cubic or !delta[0].isZero();
        try std.testing.expect(delta[1].sub(delta[0]).isZero());
    }
    try std.testing.expect(cubic);
    inline for (.{ E.PackedBase, E.PackedSecure }) |F| {
        var packed_values: [S.LOCAL_MAIN]F = undefined;
        var scalar: [16][S.LOCAL_MAIN]E.Q = undefined;
        for (&packed_values, 0..) |*v, i| {
            var base: [16]@import("stwo_core").fields.m31.M31 = undefined;
            var secure_lanes: [16]E.Q = undefined;
            for (0..16) |lane| {
                const x: u32 = @intCast(1 + 4 * (16 * i + lane));
                base[lane] = .fromCanonical(x);
                secure_lanes[lane] = if (F == E.PackedBase) E.q(x) else E.Q.fromU32Unchecked(x, x + 1, x + 2, x + 3);
                scalar[lane][i] = secure_lanes[lane];
            }
            v.* = if (F == E.PackedBase) F.fromLanes(base) else F.fromLanes(secure_lanes);
        }
        const row = S.rowFromColumnsFor(F, &packed_values);
        var actual: [S.CONSTRAINTS]E.PackedSecure = undefined;
        var sink = E.SinkFor(F){ .values = &actual };
        S.emitFor(F, &row, &sink);
        try std.testing.expectEqual(S.CONSTRAINTS, sink.count);
        for (0..16) |lane| {
            const scalar_row = S.rowFromColumnsFor(E.Q, &scalar[lane]);
            for (actual, residuals(&scalar_row)) |got, expected| try std.testing.expect(got.lane(lane).eql(expected));
        }
    }
}

fn secure(x: u32) E.Q {
    return E.Q.fromU32Unchecked(x, x + 1, x + 2, x + 3);
}
fn packedFields(comptime F: type, comptime n: usize, scalar: *[16][n]E.Q, counter: *u32) [n]F {
    var result: [n]F = undefined;
    for (&result, 0..) |*value, i| {
        var base: [16]@import("stwo_core").fields.m31.M31 = undefined;
        var extension: [16]E.Q = undefined;
        for (0..16) |lane| {
            const x = counter.*;
            counter.* += 4;
            base[lane] = .fromCanonical(x);
            extension[lane] = if (F == E.PackedBase) E.q(x) else secure(x);
            scalar[lane][i] = extension[lane];
        }
        value.* = if (F == E.PackedBase) F.fromLanes(base) else F.fromLanes(extension);
    }
    return result;
}
test "SHIFT complete paired-table range and function polynomial preserves all38 secure SIMD residuals" {
    var ch = P.Challenges{ .shift = .{ .offset = secure(3), .coefficients = undefined }, .range16 = .{ .offset = secure(7), .coefficient = secure(11) }, .function = .{ .offset = secure(13), .coefficients = undefined } };
    for (&ch.shift.coefficients, 0..) |*v, i| v.* = secure(@intCast(17 + 4 * i));
    for (&ch.function.coefficients, 0..) |*v, i| v.* = secure(@intCast(41 + 4 * i));
    const claims = P.Claims{ .shift = secure(97), .range16 = secure(101), .function = secure(107) };
    inline for (.{ E.PackedBase, E.PackedSecure }) |F| {
        var counter: u32 = 113;
        var main_scalar: [16][P.MAIN]E.Q = undefined;
        var current_scalar: [16][P.INTERACTION]E.Q = undefined;
        var previous_scalar: [16][P.INTERACTION]E.Q = undefined;
        var flag_scalar: [16][2]E.Q = undefined;
        const main = packedFields(F, P.MAIN, &main_scalar, &counter);
        const current = packedFields(F, P.INTERACTION, &current_scalar, &counter);
        const previous = packedFields(F, P.INTERACTION, &previous_scalar, &counter);
        const flags = packedFields(F, 2, &flag_scalar, &counter);
        var actual: [P.CONSTRAINTS]E.PackedSecure = undefined;
        var sink = E.SinkFor(F){ .values = &actual };
        P.emitFor(F, &main, &current, &previous, flags[0], flags[1], claims, ch, &sink);
        try std.testing.expectEqual(P.CONSTRAINTS, sink.count);
        for (0..16) |lane| {
            var expected: [P.CONSTRAINTS]E.Q = undefined;
            var scalar_sink = E.Sink{ .values = &expected };
            P.emitFor(E.Q, &main_scalar[lane], &current_scalar[lane], &previous_scalar[lane], flag_scalar[lane][0], flag_scalar[lane][1], claims, ch, &scalar_sink);
            try std.testing.expectEqual(P.CONSTRAINTS, scalar_sink.count);
            for (actual, expected) |v, q| try std.testing.expect(v.lane(lane).eql(q));
        }
    }
}

test "Word16 fixed table enumerates both directions without a direction-index duplicate or modular integer overflow" {
    for (0..WordTable.SIZE) |row| {
        const tuple = WordTable.tupleAt(row);
        const left = @as(u64, tuple[0]) << @as(u6, @intCast(tuple[1]));
        const right = (@as(u64, tuple[0]) << 16) >> @as(u6, @intCast(tuple[1]));
        try std.testing.expect(left < @import("stwo_core").fields.m31.Modulus);
        try std.testing.expectEqual(@as(u32, @intCast(left & 65535)), tuple[2]);
        try std.testing.expectEqual(@as(u32, @intCast(left >> 16)), tuple[3]);
        try std.testing.expectEqual(@as(u32, @intCast(right >> 16)), tuple[4]);
        try std.testing.expectEqual(@as(u32, @intCast(right & 65535)), tuple[5]);
        try std.testing.expectEqual(row, try WordTable.rowIndex(tuple));
    }
    var forged = WordTable.tupleAt(17);
    forged[5] += 1;
    try std.testing.expectError(error.InvalidWordShiftTuple, WordTable.rowIndex(forged));
    try std.testing.expect(!std.mem.eql(u32, &Tables.Kind.byte_shift.tupleAt(9), &WordTable.tupleAt(17)));
}
