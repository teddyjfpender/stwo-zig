//! The coordinator-only pool is supported; it must never enter a multi-lane
//! grinder whose worker-count assumption makes uninitialized jobs reachable.
const std = @import("std");
const core = @import("stwo_core");
const pow = @import("../../pcs/proof_of_work.zig");
const work = @import("../../work_pool.zig");
test "single-worker scoped PoW preserves BLAKE2s canonical nonce and transcript" {
    try check(core.channel.blake2s.Blake2sChannel);
}
test "single-worker scoped PoW preserves BLAKE3 canonical nonce and transcript" {
    try check(core.channel.blake3.Channel);
}
fn check(comptime Channel: type) !void {
    if (std.process.hasEnvVarConstant("STWO_ZIG_POW_WORKERS")) return error.SkipZigTest;
    var pool: work.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 1, .backing_allocator = std.testing.allocator });
    defer pool.deinit();
    var binding = try work.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    try std.testing.expectEqual(@as(usize, 1), pool.workerCount());
    for ([_]u32{ 0, 8, 12, 16 }) |bits| {
        var channel = Channel{};
        channel.mixU32s(&.{ 0x53494e47, bits, 17 });
        var reference = channel;
        const expected = reference.grind(bits);
        const actual = pow.grind(&channel, bits);
        try std.testing.expectEqual(expected, actual);
        try std.testing.expect(channel.verifyPowNonce(bits, actual));
        channel.mixU64(actual);
        reference.mixU64(expected);
        // The next challenge binds nonce selection and transcript continuation.
        try std.testing.expect(channel.drawSecureFelt().eql(reference.drawSecureFelt()));
    }
}
