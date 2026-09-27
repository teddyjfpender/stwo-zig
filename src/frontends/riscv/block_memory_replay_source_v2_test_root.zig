const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Replay = @import("prover/block_memory_replay.zig").Replay;
const adapter = @import("prover/block_memory_replay_source_v2.zig");
const producer = @import("prover/block_memory_batch_produce_v2.zig");
const Access = @import("runner/state_chain.zig").Access;

test "real block replay feeds bounded two-pass memory first round" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var registers: [32]u32 = @splat(0);
    registers[5] = 7;
    var replay = try Replay.init(a, tmp.dir, registers, &.{}, 2);
    defer replay.deinit();
    const accesses = [_]Access{
        .{ .addr_space = 0, .addr = 5, .clk = 1, .clk_prev = 0, .value = 8 },
        .{ .addr_space = 0, .addr = 5, .clk = 5, .clk_prev = 1, .value = 9 },
        .{ .addr_space = 0, .addr = 5, .clk = 9, .clk_prev = 5, .value = 10 },
    };
    try replay.append(.{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 3 }, &accesses);
    var initial = try replay.finish();
    initial.deinit();
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var first = try producer.collectFirstPass(Cpu, a, adapter.sortedSource(&replay), 3, 2, 8, config);
    defer first.deinit();
    try std.testing.expectEqual(@as(usize, 2), first.claims.len);
    try std.testing.expectEqual(@as(u32, 2), first.claims[0].rows);
    try std.testing.expectEqual(@as(u32, 1), first.claims[1].rows);
    try std.testing.expectEqual(@as(usize, 1), first.plan.shards.len);
    try std.testing.expectEqual(@as(u64, 3), first.total_events);
    var touches = try replay.firstTouches();
    defer touches.deinit();
    const touch = (try touches.next()).?;
    try std.testing.expectEqual(@as(u32, 5), touch.address);
    try std.testing.expectEqual(@as(u32, 7), touch.value);
    try std.testing.expectEqual(@as(?@import("prover/block_memory_replay.zig").FirstTouch, null), try touches.next());
}
