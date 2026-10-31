//! Standalone diagnostic only: no CPU, register or RAM service claim.
const std = @import("std");
const F = @import("../word16/binary_fixture.zig");
const a = std.testing.allocator;
const core = @import("stwo_core");
const rv = @import("stwo_riscv_frontend").rv64_air;
const Q = core.fields.qm31.QM31;
const P = rv.word16_v1.binary_lookup;
fn nonpole() P.Challenges {
    // Deterministic native allocation-path oracle only, never a proof challenge.
    return .{ .and_ = .{ .offset = Q.one(), .coefficients = @splat(Q.zero()) }, .function = .{ .offset = Q.one(), .coefficients = @splat(Q.zero()) } };
}
test "Word16 diagnostic constructors and unpublished native interactions survive every allocation failure" {
    const Runner = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var f = try F.Fixture.init(allocator, false);
            defer f.deinit();
            const claims = try f.generate(nonpole());
            try std.testing.expect(claims[0].add(claims[3]).isZero());
            try std.testing.expect(claims[1].add(claims[2]).isZero());
        }
    };
    try std.testing.checkAllAllocationFailures(a, Runner.run, .{});
    var f = try F.Fixture.init(a, false);
    defer f.deinit();
    var pole = nonpole();
    pole.and_.offset = Q.zero();
    try std.testing.expectError(error.DivisionByZero, f.generate(pole));
    try std.testing.expectEqual(@as(usize, 0), f.inter.len);
    try std.testing.expectEqual(@as(usize, 0), f.expected_inter.len);
    _ = try f.generate(nonpole());
    try std.testing.expectError(error.InvalidBinaryFixturePhase, f.generate(nonpole()));
}
test "diagnostic Word16 BINARY closes public consumer and AND in one unequal-domain PCS proof" {
    const encoded = try F.produce(a, false);
    defer a.free(encoded.bytes);
    try F.verify(a, encoded, false);
    if (F.verify(a, encoded, true)) |_| return error.ExpectedPrefixRejection else |_| {}
    if (F.produce(a, true)) |forged| {
        a.free(forged.bytes);
        return error.ExpectedForgedBinaryRejection;
    } else |err| try std.testing.expectEqual(error.ConstraintsNotSatisfied, err);
    var noncanonical = encoded;
    noncanonical.claims[0].c0.a.v = core.fields.m31.Modulus;
    try std.testing.expectError(error.NonCanonicalWord16Claim, F.verify(a, noncanonical, false));
    for ([_]F.Attack{ .and_fact, .cross_family, .packed_alias }) |attack| {
        if (F.produceWithAttack(a, attack)) |forged| {
            a.free(forged.bytes);
            return error.ExpectedFalseFactRejection;
        } else |err| try std.testing.expectEqual(error.ConstraintsNotSatisfied, err);
    }
}
