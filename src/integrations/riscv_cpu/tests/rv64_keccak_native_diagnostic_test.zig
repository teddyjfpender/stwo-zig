const std = @import("std");
const core = @import("stwo_core");
const rv = @import("stwo_riscv_frontend").rv64_air;
const K = rv.crypto.keccak;
const S = @import("../delegations/keccak/sources.zig");
const D = @import("../delegations/keccak/native.zig");
const F = @import("rv64_keccak_proof_test.zig");
const M = core.fields.m31.M31;
fn call() K.bridge.trace.Call {
    const before = F.inputState(17);
    return .{ .call_id = 1, .clock = 3, .pointer = 0x1ff8, .before = before, .after = F.reference(before), .previous_clocks = @splat(0) };
}
fn challenges() struct { k: K.equations.Challenges, b: K.bridge.equations.Challenges } {
    var channel = core.channel.blake2s.Blake2sChannel{};
    channel.mixU32s(&.{ 0x4b444941, 37 });
    const k = K.equations.Challenges.draw(&channel);
    return .{ .k = k, .b = .{ .io = k.io, .call = K.bridge.equations.CallChallenges.draw(&channel), .ram = rv.relations.Challenges.draw(&channel), .bytes = channel.drawSecureFelt() } };
}
test "native K diagnostic spans retired packed metadata and identifies all four corrupted families" {
    const a = std.testing.allocator;
    const calls = [_]K.bridge.trace.Call{call()};
    var trace = try S.Trace.init(a, &calls, 1, 5, 5);
    defer trace.deinit();
    var snapshot = try D.Snapshot.init(a, &trace);
    defer snapshot.deinit();
    try trace.releaseMain();
    const ch = challenges();
    const claims = try trace.generate(ch.k, ch.b);
    try std.testing.expectEqual(@as(usize, 0), trace.permutation.metadata.len);
    try std.testing.expectEqual(@as(usize, 0), trace.bridge.metadata.len);
    try std.testing.expect((try snapshot.inspect(&trace, ch.k, ch.b, claims)) == null);
    inline for (.{ "permutation", "chi", "xor5", "bridge" }) |name| {
        const data = @field(trace, name).interaction;
        const saved = data[0];
        data[0] = saved.add(M.one());
        const failure = (try snapshot.inspect(&trace, ch.k, ch.b, claims)) orelse return error.ExpectedNativeKFailure;
        try std.testing.expectEqualStrings(name, @tagName(failure.family));
        try std.testing.expectEqual(@as(usize, 0), failure.logical_row);
        try std.testing.expect(!failure.value.isZero());
        data[0] = saved;
    }
}
