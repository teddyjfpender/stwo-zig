const std = @import("std");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Continuation = @import("../block_v7_real_window_continuation_v2.zig");
test "bounded snapshot continuation matches original prefix replay endpoint" {
    const a = std.testing.allocator;
    const elf = @import("block_v7_keccak_execution_test_support.zig").elf();
    var original = try Capture.capture(a, &elf, &.{}, .{ .elf = Capture.sha(&elf), .input = Capture.sha(&.{}) }, .{ .skip_cycles = 6, .cycles = 3 }, .{});
    defer original.deinit();
    var actual = try Continuation.capture(a, &elf, Capture.sha(&elf), original.incoming, original.incoming.identity(), 3, .{ .chunk_cycles = 2 });
    defer actual.deinit(a);
    try std.testing.expectEqualDeep(original.outgoing, actual.outgoing);
    try std.testing.expectEqual(@as(u64, original.stats.keccak_calls), actual.stats.keccak_calls);
    var bad = original.incoming.identity();
    bad[0] ^= 1;
    try std.testing.expectError(error.InvalidV7ContinuationInput, Continuation.capture(a, &elf, Capture.sha(&elf), original.incoming, bad, 3, .{}));
    try std.testing.expectError(error.RealWindowPastCompletion, Continuation.capture(a, &elf, Capture.sha(&elf), original.incoming, original.incoming.identity(), 12, .{}));
}
