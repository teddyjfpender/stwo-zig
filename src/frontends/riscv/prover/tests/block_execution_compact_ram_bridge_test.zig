const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const C = @import("../block_execution_compact_ram_bridge_v1.zig");
const Original = @import("../block_execution_integer_algebra_v1.zig");
const Constructor = @import("../block_execution_integer_bridge_v2.zig");
const Source = @import("../block_execution_access_bridge_v2.zig");
fn q(value: u32) Q {
    return Q.fromBase(M.fromCanonical(value));
}
fn pair(address: u32, clock: u32) Source.Pair(Q) {
    return .{ .active = Q.one(), .space = Q.one(), .source_address = q(address), .local_clock = q(clock), .consume_clock = Q.zero(), .before = .{ q(1), q(2), q(3), q(4) }, .after = .{ q(5), q(6), q(7), q(8) }, .pair_residuals = @splat(Q.zero()), .access_ordinal = 0 };
}
fn allZero(values: Original.Algebra(Q).Residuals) bool {
    for (values.values[0..values.len]) |value| if (!value.isZero()) return false;
    return true;
}
test "compact RAM bridge reconstructs original valid constraints and every transition limb" {
    const policy = try C.Policy.init(.{ .global_first_cycle = 100000001, .cycle_count = 1 << 19, .clock_frame = .leaf_local });
    for ([_]u32{ 0, 1, 255, 256, 65535, 0x3fffffff }) |address| for ([_]u32{ 1, 2, 3, 1025, 0x1fffff }) |clock| {
        const p = pair(address, clock);
        const compact = try C.construct(p, policy);
        const old = try Constructor.Witness.fromPair(p, policy.base_clock);
        const expanded = C.Algebra(Q).expand(compact);
        try std.testing.expect(allZero(C.Algebra(Q).constraints(p, compact, Original.clockBytes(Q, policy.base_clock))));
        try std.testing.expectEqualDeep(Constructor.transitionAtPoint(p, old), C.Algebra(Q).transitionAtPoint(p, compact));
        // Register-only bits are intentionally absent. Every other original
        // physical value is reconstructed exactly, not read from host hints.
        try std.testing.expectEqualDeep(old.columns()[0..43].*, expanded.columns()[0..43].*);
    };
}
test "compact RAM bridge preserves arbitrary extension-point original equations" {
    var rng = std.Random.DefaultPrng.init(0x173baec);
    for (0..32) |_| {
        var columns: [C.COLUMN_COUNT]Q = undefined;
        for (&columns) |*value| value.* = Q.fromU32Unchecked(rng.random().int(u32) % 2147483647, rng.random().int(u32) % 2147483647, rng.random().int(u32) % 2147483647, rng.random().int(u32) % 2147483647);
        var p = pair(19, 129);
        p.active = Q.fromU32Unchecked(7, 11, 13, 17);
        p.space = Q.fromU32Unchecked(2, 3, 5, 7);
        const base = Original.clockBytes(Q, 400000000);
        const expanded = C.Algebra(Q).expand(columns);
        const expected = Original.Algebra(Q).constraints(p, expanded, base);
        const actual = C.Algebra(Q).constraints(p, columns, base);
        try std.testing.expectEqualSlices(Q, expected.values[0..expected.len], actual.values[0..expected.len]);
        try std.testing.expectEqualDeep(p.active.mul(p.space.sub(Q.one())), actual.values[expected.len]);
    }
}
test "compact RAM bridge rejects malformed policy register substitution and retained-cell mutations" {
    const policy = try C.Policy.init(.{ .global_first_cycle = 1, .cycle_count = 4096, .clock_frame = .leaf_local });
    var forged = policy;
    forged.base_clock += 4;
    try std.testing.expectError(error.UntrustedCompactRamClock, C.construct(pair(19, 129), forged));
    try std.testing.expectError(error.CompactRamClockOutOfRange, C.Policy.init(.{ .global_first_cycle = 1 << 30, .cycle_count = 2, .clock_frame = .leaf_local }));
    var p = pair(19, 129);
    p.space = Q.zero();
    try std.testing.expectError(error.RegisterAccessInCompactRamBridge, C.construct(p, policy));
    p = pair(19, 129);
    const good = try C.construct(p, policy);
    const base = Original.clockBytes(Q, 0);
    for (0..C.COLUMN_COUNT) |index| {
        var changed = good;
        changed[index] = changed[index].add(Q.one());
        try std.testing.expect(!allZero(C.Algebra(Q).constraints(p, changed, base)));
    }
    p.space = Q.zero();
    try std.testing.expect(!allZero(C.Algebra(Q).constraints(p, good, base)));
}

test "compact RAM bridge retains byte-address inputs inactive rows and policy identity" {
    const policy = try C.Policy.init(.{ .global_first_cycle = 200001, .cycle_count = 4096, .clock_frame = .leaf_local });
    var p = pair(0x3ffffffc, 129);
    p.address_unit = .byte_address;
    const columns = try C.construct(p, policy);
    const old = try Constructor.Witness.fromPair(p, policy.base_clock);
    try std.testing.expect(allZero(C.Algebra(Q).constraints(p, columns, Original.clockBytes(Q, policy.base_clock))));
    try std.testing.expectEqualDeep(Constructor.transitionAtPoint(p, old), C.Algebra(Q).transitionAtPoint(p, columns));
    p.active = Q.zero();
    p.local_clock = Q.zero();
    p.space = Q.zero();
    const inactive = try C.construct(p, policy);
    for (inactive) |value| try std.testing.expect(value.isZero());
    try std.testing.expect(allZero(C.Algebra(Q).constraints(p, inactive, Original.clockBytes(Q, policy.base_clock))));
    var first = core.proof_suites.Blake3.Channel{};
    var second = first;
    try policy.mix(&first);
    const changed = try C.Policy.init(.{ .global_first_cycle = 200002, .cycle_count = 4096, .clock_frame = .leaf_local });
    try changed.mix(&second);
    try std.testing.expect(!std.meta.eql(first.digestBytes(), second.digestBytes()));
}
