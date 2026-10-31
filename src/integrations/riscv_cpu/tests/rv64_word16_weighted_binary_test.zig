const std = @import("std");
const core = @import("stwo_core");
const F = @import("../word16/weighted_binary_fixture.zig");
const a = std.testing.allocator;
test "weighted BINARY closes31 public queries with three facts and fresh expected receiver" {
    var owned = try F.produce(a, false, .none);
    defer owned.deinit(a);
    try F.verify(a, owned);
    var borrowed = try F.produce(a, true, .none);
    defer borrowed.deinit(a);
    try F.verify(a, borrowed);
    try std.testing.expectEqualSlices(u8, owned.bytes, borrowed.bytes);
}
test "weighted BINARY physical engine rejects missing truth wrong weight and balanced AND debt" {
    for ([_]F.Attack{ .weight, .missing_fact, .balanced_and_debt }) |attack| try std.testing.expectError(error.ConstraintsNotSatisfied, F.produce(a, false, attack));
}
test "weighted BINARY fresh receiver rejects balanced claims and noncanonical secure coordinates" {
    var proof = try F.produce(a, false, .none);
    defer proof.deinit(a);
    var forged = proof;
    forged.claims[1] = forged.claims[1].add(core.fields.qm31.QM31.one());
    forged.claims[2] = forged.claims[2].sub(core.fields.qm31.QM31.one());
    if (F.verify(a, forged)) |_| return error.AcceptedBalancedWeightedFunctionDebt else |_| {}
    forged = proof;
    forged.claims[0].c0.a.v = core.fields.m31.Modulus;
    try std.testing.expectError(error.NonCanonicalWord16Claim, F.verify(a, forged));
}
