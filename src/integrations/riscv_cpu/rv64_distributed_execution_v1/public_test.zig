const std = @import("std");
const P = @import("public.zig");
const Native = @import("native_fixture.zig");
const Rom = @import("stwo_riscv_frontend").rv64_air.word16_cpu.rom;
const a = std.testing.allocator;

test "two CPU shards bind exact genesis full64 values coverage PC adjacency and terminal output" {
    const native = try Native.Fixture.init(a); // VM/Memory already destroyed.
    var program = try Rom.Setup.init(a, .{ .base = Native.BASE, .words = &Native.WORDS });
    defer program.deinit();
    const expected = try Native.expected(&program);
    try expected.validate(&program, native.shards);
    try std.testing.expect(native.shards[0].public.register_clocks[1] != 0);
    var shards = native.shards;
    shards[0].cpu_log = 22;
    try std.testing.expectError(error.InvalidDistributedCpuGeometry, expected.validate(&program, shards));
    shards = native.shards;
    shards[1].first_step += 1;
    try std.testing.expectError(error.DistributedExecutionCoverageGap, expected.validate(&program, shards));
    shards = native.shards;
    shards[1].public.initial_pc += 4;
    try std.testing.expectError(error.DistributedExecutionAdjacencyMismatch, expected.validate(&program, shards));
    shards = native.shards;
    shards[1].public.initial_registers[1] +%= 2147483647;
    try std.testing.expectError(error.DistributedExecutionAdjacencyMismatch, expected.validate(&program, shards));
    var other = expected;
    other.initial_registers[1] +%= @as(u64, 1) << 48;
    try std.testing.expectError(error.DistributedExecutionGenesisMismatch, other.validate(&program, native.shards));
    other = expected;
    other.final_registers[5] ^= 1;
    try std.testing.expectError(error.DistributedExecutionTerminalMismatch, other.validate(&program, native.shards));
    other = expected;
    other.total_steps += 1;
    try std.testing.expectError(error.DistributedExecutionCoverageGap, other.validate(&program, native.shards));
    shards = native.shards;
    shards[1].public.register_clocks[1] = 13;
    try std.testing.expectError(error.InvalidWord16CpuClock, expected.validate(&program, shards));
    // Shared wrong intermediate values alone satisfy framing. The aggregate
    // MUST subsequently verify actual CPU proofs; this check is not authority.
    shards = native.shards;
    shards[0].public.final_registers[1] ^= 1;
    shards[1].public.initial_registers[1] ^= 1;
    try expected.validate(&program, shards);
    try std.testing.expect(!std.mem.eql(u8, &(try P.shardDigest(shards[0])), &(try P.shardDigest(native.shards[0]))));
}
