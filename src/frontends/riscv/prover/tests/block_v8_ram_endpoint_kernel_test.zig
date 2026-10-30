const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const K = @import("../block_v8_ram_endpoint_kernel_v1.zig");
fn q(v: u32) Q {
    return Q.fromBase(M.fromCanonical(v));
}
fn zero(values: anytype) bool {
    for (values) |v| if (!v.isZero()) return false;
    return true;
}
fn base(v: Q) !u32 {
    const limbs = v.toM31Array();
    if (!zero(limbs[1..])) return error.NonBaseEndpoint;
    return limbs[0].v;
}
fn ranges(row: [K.COLUMN_COUNT]Q) bool {
    for (K.range16_columns) |index| if ((base(row[index]) catch return false) > 65535) return false;
    for (K.byte_pairs) |pair| for (pair) |index| if ((base(row[index]) catch return false) > 255) return false;
    for (K.derivedRange16(Q, row)) |value| if ((base(value) catch return false) > 65535) return false;
    return true;
}
fn valid(row: [K.COLUMN_COUNT]Q, next: [K.COLUMN_COUNT]Q, edge: bool, policy: K.Policy) bool {
    return ranges(row) and zero(K.constraints(Q, row, next, Q.one(), if (edge) Q.one() else Q.zero(), Q.zero(), q(policy.max_local_clock)));
}
fn asTuple(values: [7]Q) ![7]M {
    var out: [7]M = undefined;
    for (&out, values) |*v, value| v.* = M.fromCanonical(try base(value));
    return out;
}
fn supplier(row: [K.COLUMN_COUNT]Q) !Q {
    const elements = @import("../../recursion/air/universal_challenges.zig").UniversalRelations.dummy().get(.memory_access);
    const initial = try asTuple(K.localTuple(Q, row, false));
    const final = try asTuple(K.localTuple(Q, row, true));
    return (try (try elements.combineBase(&initial)).inv()).sub(try (try elements.combineBase(&final)).inv());
}
test "RAM endpoints preserve local tuples and exact packed global transition limbs" {
    const policy = K.Policy{ .source_ordinal = 12345, .max_local_clock = (1 << 27) - 1 };
    for ([_]u32{ 0, 4, 65532, 65536, 262140, 0x3ffffffc }) |address| for ([_]u32{ 1, 4, 65535, 65536, (1 << 27) - 1 }) |clock| {
        const endpoint = K.Endpoint{ .address = address, .initial = 0xfedcba98, .final = 0x01234567, .last_clock = clock };
        const row = try K.construct(endpoint, null, policy);
        try std.testing.expect(valid(row, @splat(Q.zero()), false, policy));
        const tuple = try K.globalTuple(Q, row, policy);
        const expected = @import("../block_v5_word_memory_protocol_v1.zig").transitionTuple(.{ .space = 1, .address = address, .clock = try policy.globalClock(), .before = endpoint.initial, .after = endpoint.final });
        for (tuple, expected) |got, want| try std.testing.expect(got.eql(Q.fromBase(want)));
        try std.testing.expectEqual(address, try base(K.localTuple(Q, row, false)[1]));
        try std.testing.expectEqual(clock, try base(K.localTuple(Q, row, true)[2]));
    };
}
test "RAM endpoints reject duplicate or descending addresses and clock overflow" {
    const policy = K.Policy{ .source_ordinal = 0, .max_local_clock = 100 };
    const endpoint = K.Endpoint{ .address = 64, .initial = 1, .final = 2, .last_clock = 99 };
    const row = try K.construct(endpoint, 128, policy);
    const next = try K.construct(.{ .address = 128, .initial = 5, .final = 6, .last_clock = 100 }, null, policy);
    try std.testing.expect(valid(row, next, true, policy));
    try std.testing.expectError(error.UnorderedRamEndpoints, K.construct(endpoint, 64, policy));
    try std.testing.expectError(error.UnorderedRamEndpoints, K.construct(endpoint, 60, policy));
    try std.testing.expect(!zero(K.constraints(Q, row, row, Q.one(), Q.one(), Q.zero(), q(100))));
    var bad = endpoint;
    bad.last_clock = 0;
    try std.testing.expectError(error.InvalidRamEndpoint, K.construct(bad, null, policy));
    bad.last_clock = 101;
    try std.testing.expectError(error.InvalidRamEndpoint, K.construct(bad, null, policy));
}
test "RAM endpoint address carry requires the derived range request" {
    const policy = K.Policy{ .source_ordinal = 0, .max_local_clock = 100 };
    var row = try K.construct(.{ .address = 65532, .initial = 1, .final = 2, .last_clock = 10 }, null, policy);
    try std.testing.expect(valid(row, @splat(Q.zero()), false, policy));
    row[21] = Q.one();
    // Booleanity alone cannot bind a carry. The required derived low16
    // range request rejects this field-negative forged byte-address split.
    try std.testing.expect(zero(K.constraints(Q, row, @splat(Q.zero()), Q.one(), Q.zero(), Q.zero(), q(100))));
    try std.testing.expect(!ranges(row));
}
test "RAM endpoint inactive rows and fractional selectors are constrained" {
    const policy = K.Policy{ .source_ordinal = 0, .max_local_clock = 100 };
    const empty: [K.COLUMN_COUNT]Q = @splat(Q.zero());
    try std.testing.expect(zero(K.constraints(Q, empty, empty, Q.zero(), Q.zero(), Q.one(), q(100))));
    for (0..K.COLUMN_COUNT) |index| {
        var poisoned = empty;
        poisoned[index] = Q.one();
        try std.testing.expect(!zero(K.constraints(Q, poisoned, empty, Q.zero(), Q.zero(), Q.one(), q(100))));
    }
    const row = try K.construct(.{ .address = 0, .initial = 1, .final = 2, .last_clock = 10 }, null, policy);
    try std.testing.expect(!zero(K.constraints(Q, row, empty, q(2), Q.zero(), Q.zero(), q(100))));
}
test "RAM endpoint fractions telescope and per-source closure cannot be aggregated" {
    const policy = K.Policy{ .source_ordinal = 0, .max_local_clock = 100 };
    const a = try K.construct(.{ .address = 16, .initial = 7, .final = 9, .last_clock = 30 }, null, policy);
    const middle = try K.construct(.{ .address = 16, .initial = 7, .final = 8, .last_clock = 10 }, null, policy);
    const elements = @import("../../recursion/air/universal_challenges.zig").UniversalRelations.dummy().get(.memory_access);
    const consumed = try asTuple(K.localTuple(Q, middle, true));
    const emitted = try asTuple(K.localTuple(Q, a, true));
    const last_edge = (try (try elements.combineBase(&consumed)).inv()).neg().add(try (try elements.combineBase(&emitted)).inv());
    const native = (try supplier(middle)).neg().add(last_edge);
    try std.testing.expect(native.add(try supplier(a)).isZero());
    const b = try K.construct(.{ .address = 16, .initial = 11, .final = 13, .last_clock = 30 }, null, policy);
    const source_a = (try supplier(a)).neg();
    const source_b = (try supplier(b)).neg();
    const swapped_a = source_a.add(try supplier(b));
    const swapped_b = source_b.add(try supplier(a));
    try std.testing.expect(!swapped_a.isZero() and !swapped_b.isZero());
    try std.testing.expect(swapped_a.add(swapped_b).isZero());
}

test "RAM endpoint global clocks use ordered bounded cohort phases" {
    for ([_]u32{ 0, 1, 7, (1 << 20) - 1 }) |ordinal| {
        const policy = K.Policy{ .source_ordinal = ordinal, .max_local_clock = 1 };
        const global = try policy.globalClock();
        try std.testing.expectEqual(@as(u64, ordinal) * 4 + 3, global);
        try std.testing.expect(global > 0 and global % 4 != 0);
        try std.testing.expect(global <= 4 * (@as(u64, ordinal) + 1) - 1);
        try std.testing.expect(global != (@as(u64, ordinal) << 32) + 1);
    }
    try std.testing.expectError(error.InvalidRamEndpointPolicy, (K.Policy{ .source_ordinal = 1 << 20, .max_local_clock = 1 }).globalClock());
}
