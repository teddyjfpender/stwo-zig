const std = @import("std");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Guest = @import("block_v7_keccak_execution_test_support.zig");
test "real window capsule replays exact chained Keccak with externally pinned incoming state" {
    const a = std.testing.allocator;
    const elf = Guest.elf();
    const pins: Capture.Pins = .{ .elf = Capture.sha(&elf), .input = Capture.sha(&.{}) };
    var captured = try Capture.capture(a, &elf, &.{}, pins, .{ .skip_cycles = 6, .cycles = 3 }, .{ .replay_chunk_cycles = 3 });
    defer captured.deinit();
    try std.testing.expectEqual(@as(usize, 1), captured.stats.keccak_calls);
    const expected = captured.incoming.identity();
    const encoded = try captured.incoming.encode(a);
    defer a.free(encoded);
    var decoded = try Capture.Snapshot.decode(a, encoded, expected, .{});
    defer decoded.deinit(a);
    try std.testing.expectEqualDeep(captured.incoming, decoded);
    try std.testing.expectError(error.InvalidRealWindowSnapshot, Capture.Snapshot.decode(a, encoded[0 .. encoded.len - 1], expected, .{}));
    try std.testing.expectError(error.RealWindowResourceLimit, Capture.Snapshot.decode(a, encoded, expected, .{ .max_snapshot_words = 1 }));
    encoded[152] ^= 1;
    try std.testing.expectError(error.UntrustedRealWindowIncomingState, Capture.Snapshot.decode(a, encoded, expected, .{}));
    encoded[152] ^= 1;
    try Capture.replay(a, &elf, &.{}, &captured, expected, .{});
    captured.incoming.cpu.regs[5] ^= 4;
    try std.testing.expectError(error.UntrustedRealWindowIncomingState, Capture.replay(a, &elf, &.{}, &captured, expected, .{}));
    captured.incoming.cpu.regs[5] ^= 4;
    captured.behavior[0] ^= 1;
    try std.testing.expectError(error.RealWindowReplayMismatch, Capture.replay(a, &elf, &.{}, &captured, expected, .{}));
}
test "real window capture rejects source substitution and explicit capacity limits" {
    const a = std.testing.allocator;
    const elf = Guest.elf();
    var pins: Capture.Pins = .{ .elf = Capture.sha(&elf), .input = Capture.sha(&.{}) };
    pins.elf[0] ^= 1;
    try std.testing.expectError(error.UntrustedRealWindowSource, Capture.capture(a, &elf, &.{}, pins, .{ .skip_cycles = 0, .cycles = 3 }, .{}));
    pins.elf[0] ^= 1;
    try std.testing.expectError(error.RealWindowResourceLimit, Capture.capture(a, &elf, &.{}, pins, .{ .skip_cycles = 4, .cycles = 3 }, .{ .max_skip_cycles = 3 }));
    try std.testing.expectError(error.RealWindowResourceLimit, Capture.capture(a, &elf, &.{}, pins, .{ .skip_cycles = 0, .cycles = 3 }, .{ .max_snapshot_words = 1 }));
    try std.testing.expectError(error.RealWindowPastCompletion, Capture.capture(a, &elf, &.{}, pins, .{ .skip_cycles = 16, .cycles = 3 }, .{}));
}
