const std = @import("std");
const checkpoint = @import("../checkpoint.zig");
const Session = @import("../ethereum_services/session.zig").Session;
const Memory = @import("../memory.zig").Memory;
const Cpu = @import("../machine.zig").Cpu;

test "checkpoints: all service counters roundtrip through actual mutable and const session pointers" {
    var memory = Memory.init(std.testing.allocator, .{});
    defer memory.deinit();
    var session = try Session.initWithProfile(std.testing.allocator, Cpu.init(0x10000, 0x40000), &memory, .{}, .ethereum_services_v3);
    defer session.deinit();
    var expected = checkpoint.Counters{ .keccak = std.math.maxInt(u64), .add = 3, .double = 5, .sha256 = 7, .arith256_mod = 11, .bulk = 17, .sponge = 23 };
    for (&expected.curve, 0..) |*value, i| value.* = 29 + 13 * @as(u64, @intCast(i));
    expected.apply(&session);
    const readonly: *const Session = &session;
    try std.testing.expectEqualDeep(expected, checkpoint.Counters.of(readonly));
    const reset = checkpoint.Counters{};
    reset.apply(&session);
    try std.testing.expectEqualDeep(reset, checkpoint.Counters.of(readonly));
}
