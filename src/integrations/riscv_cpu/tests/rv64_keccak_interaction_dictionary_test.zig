const std = @import("std");
const core = @import("stwo_core");
const K = @import("stwo_riscv_frontend").rv64_air.crypto.keccak;
const F = @import("rv64_keccak_proof_test.zig");
const Oracle = @import("rv64_keccak_interaction_oracle.zig");
const M = core.fields.m31.M31;
const a = std.testing.allocator;
fn challenges(seed: u32) K.equations.Challenges {
    var channel = core.channel.blake2s.Blake2sChannel{};
    channel.mixU32s(&.{ 0x4b444943, seed });
    return K.equations.Challenges.draw(&channel);
}
test "Keccak inverse dictionary preserves old all-row prefix bytes for empty odd even and padded traces" {
    const cases = [_]struct { count: usize, log: u32 }{ .{ .count = 0, .log = 5 }, .{ .count = 1, .log = 5 }, .{ .count = 2, .log = 6 }, .{ .count = 3, .log = 7 }, .{ .count = 5, .log = 7 } };
    for (cases, 0..) |case, index| {
        const inputs = try a.alloc(K.trace.State, case.count);
        defer a.free(inputs);
        for (inputs, 0..) |*input, i| input.* = F.inputState(17 + i);
        const first = core.fields.m31.Modulus - @as(u32, @intCast(@max(1, case.count)));
        var old = try K.trace.Trace.initWithLog(a, inputs, first, case.log);
        defer old.deinit();
        var new = try K.trace.Trace.initWithLog(a, inputs, first, case.log);
        defer new.deinit();
        const ch = challenges(@intCast(index));
        const expected = try Oracle.generate(&old, ch);
        const actual = try K.interaction.generate(&new, ch);
        try std.testing.expect(expected.eql(actual));
        try std.testing.expectEqualSlices(M, old.interaction, new.interaction);
        try std.testing.expectError(error.KeccakInteractionAlreadyGenerated, K.interaction.generate(&new, ch));
    }
}
fn allocationRun(allocator: std.mem.Allocator) !void {
    const input = [_]K.trace.State{F.inputState(19)};
    var trace = try K.trace.Trace.init(allocator, &input, 1);
    defer trace.deinit();
    try trace.releaseMain();
    _ = try K.interaction.generate(&trace, challenges(37));
}
test "Keccak dictionary and IO batch allocation failures clean up after main release" {
    try std.testing.checkAllAllocationFailures(a, allocationRun, .{});
}
test "Keccak dictionary and active IO poles leave interaction unpublished and allow retry" {
    const input = [_]K.trace.State{F.inputState(19)};
    var trace = try K.trace.Trace.init(a, &input, 1);
    defer trace.deinit();
    const valid = challenges(37);
    var pole = valid;
    pole.chi.offset = core.fields.qm31.QM31.zero();
    pole.chi.coefficients = @splat(core.fields.qm31.QM31.zero());
    try std.testing.expectError(error.DivisionByZero, K.interaction.generate(&trace, pole));
    try std.testing.expectEqual(@as(usize, 0), trace.interaction.len);
    pole = valid;
    pole.io.offset = core.fields.qm31.QM31.zero();
    pole.io.coefficients = @splat(core.fields.qm31.QM31.zero());
    try std.testing.expectError(error.DivisionByZero, K.interaction.generate(&trace, pole));
    try std.testing.expectEqual(@as(usize, 0), trace.interaction.len);
    _ = try K.interaction.generate(&trace, valid);
}
test "Keccak dictionary native preflight rejects a malformed active tuple without publishing advice" {
    const input = [_]K.trace.State{F.inputState(19)};
    var trace = try K.trace.Trace.init(a, &input, 1);
    defer trace.deinit();
    trace.metadata[2].state_a[0] ^= 1;
    try std.testing.expectError(error.InvalidTuple, K.interaction.generate(&trace, challenges(37)));
    try std.testing.expectEqual(@as(usize, 0), trace.interaction.len);
}
