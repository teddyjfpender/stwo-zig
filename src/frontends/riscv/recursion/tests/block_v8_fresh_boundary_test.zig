const std = @import("std");
const Fresh = @import("../block_v8_fresh_boundary_v1.zig").Fresh;
const Capture = @import("../../prover/block_v7_real_window_capture_v1.zig");
const Guest = @import("../../prover/tests/block_v7_keccak_execution_test_support.zig");
test "fresh boundary derives zero-prefix state and rejects retained later or changed states" {
    const a = std.testing.allocator;
    const elf = Guest.elf();
    const pins = Capture.Pins{ .elf = Capture.sha(&elf), .input = Capture.sha(&.{}) };
    const fresh = try Fresh.derive(a, &elf, &.{}, pins, .{});
    defer fresh.deinit();
    var captured = try Capture.capture(a, &elf, &.{}, pins, .{ .skip_cycles = 0, .cycles = 1 }, .{});
    defer captured.deinit();
    try std.testing.expectEqualDeep(captured.incoming.identity(), fresh.initialIdentity());
    var span = @import("../block_v8_window_chain_v1.zig").Span{ .elf = pins.elf, .program = fresh.programIdentity(), .incoming = captured.incoming.identity(), .outgoing = captured.outgoing.identity(), .begin = 0, .end = 1, .leaves = 1 };
    try fresh.requireStart(span);
    span.begin = 1;
    span.end = 2;
    try std.testing.expectError(error.UntrustedWindowChainInitialState, fresh.requireStart(span));
    span.begin = 0;
    span.incoming[0] ^= 1;
    try std.testing.expectError(error.UntrustedWindowChainInitialState, fresh.requireStart(span));
    var bad = pins;
    bad.input[0] ^= 1;
    try std.testing.expectError(error.UntrustedWindowChainSource, Fresh.derive(a, &elf, &.{}, bad, .{}));
}
