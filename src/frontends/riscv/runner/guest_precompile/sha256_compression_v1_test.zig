const std = @import("std");
const subject = @import("sha256_compression_v1.zig");
const contract = @import("../../isa/sha256_compression_v1.zig");
const sha = @import("../../air/guest_precompile/sha256_compression.zig");
const caller = @import("../../air/guest_precompile/sha256_memory_caller.zig");
const Cpu = @import("../cpu.zig").Cpu;
const Memory = @import("../memory.zig").Memory;
const Layout = @import("../memory_state.zig").MemoryLayout;
const Trace = @import("../trace.zig").Trace;
const Tracker = @import("../state_chain.zig").StateChainTracker;
fn layout() Layout {
    return .{ .program_base = 0x1000, .program_end = 0x1100, .data_base = 0x2000, .data_end = 0x3000, .stack_bottom = 0x4000, .stack_top = 0x5000, .io_base = 0x6000, .io_end = 0x7000, .input_base = 0x6000, .input_end = 0x6100, .output_len_addr = 0x6200, .output_data_addr = 0x6204, .output_base = 0x6200, .output_end = 0x7000 };
}
fn transaction(a: std.mem.Allocator, recorded: bool) !void {
    var trace = Trace.init(a);
    defer trace.deinit();
    var memory = try Memory.initFallible(a);
    defer memory.deinit();
    var tracker = Tracker.init(a);
    defer tracker.deinit();
    var tape = subject.Tape{ .allocator = a, .limit = 2 };
    defer tape.deinit();
    var cpu = Cpu.init(0x1000, 0x4000);
    cpu.writeReg(3, 0x2000);
    cpu.writeReg(9, 0x2100);
    var addresses: [24]u32 = undefined;
    for (&addresses, 0..) |*address, i| address.* = if (i < 8) 0x2000 + @as(u32, @intCast(i * 4)) else 0x2100 + @as(u32, @intCast((i - 8) * 4));
    try memory.prepareAlignedWordWrites(&addresses);
    var block: [64]u8 = undefined;
    for (&block, 0..) |*byte, i| byte.* = @truncate(i * 71 + 3);
    for (addresses, 0..) |address, i| memory.writeU32AssumePrepared(address, if (i < 8) sha.initial_state[i] else std.mem.readInt(u32, block[(i - 8) * 4 ..][0..4], .little));
    const before_cpu = cpu;
    const execution = if (recorded) subject.executeWithRecordedClock(contract.encode(3, 9), 1, 0, 0, 0, &cpu, &memory, layout(), &tracker, &trace, &tape) else subject.execute(contract.encode(3, 9), 1, &cpu, &memory, layout(), &tracker, &tape);
    execution catch |err| {
        try std.testing.expectEqual(@as(usize, 0), trace.recordedExternalSteps());
        try std.testing.expectEqualDeep(before_cpu, cpu);
        try std.testing.expectEqual(@as(usize, 0), tape.len());
        try std.testing.expectEqual(@as(usize, 0), tracker.accesses.items.len);
        try std.testing.expectEqual(@as(u32, 0), tracker.mem_last_clk.count());
        for (addresses, 0..) |address, i| try std.testing.expectEqual(if (i < 8) sha.initial_state[i] else std.mem.readInt(u32, block[(i - 8) * 4 ..][0..4], .little), memory.readU32(address));
        return err;
    };
    const expected = sha.compress(sha.initial_state, block);
    try std.testing.expectEqual(@as(usize, 1), tape.len());
    try std.testing.expectEqual(@as(u32, 0x1004), cpu.pc);
    try std.testing.expectEqual(@as(usize, 26), tracker.accesses.items.len);
    for (addresses, 0..) |address, i| {
        try std.testing.expectEqual(if (i < 8) expected[i] else std.mem.readInt(u32, block[(i - 8) * 4 ..][0..4], .little), memory.readU32(address));
        try std.testing.expectEqual(@as(u32, 2), tracker.mem_last_clk.get(address).?);
    }
    _ = try caller.row(tape.entries.items[0].call);
    if (recorded) {
        try std.testing.expectEqual(@as(usize, 1), trace.recordedExternalSteps());
        try std.testing.expectError(error.ProfileClockCountMismatch, subject.executeWithRecordedClock(contract.encode(3, 9), 2, 0, 2, 1, &cpu, &memory, layout(), &tracker, &trace, &tape));
        try std.testing.expectEqual(@as(usize, 1), trace.recordedExternalSteps());
    }
    // Invalid overlap must leave the already committed first call intact.
    cpu.writeReg(9, 0x2000);
    try std.testing.expectError(error.OverlappingShaSpans, subject.execute(contract.encode(3, 9), 2, &cpu, &memory, layout(), &tracker, &tape));
    try std.testing.expectEqual(@as(usize, 1), tape.len());
    try std.testing.expectEqual(@as(u32, 0x1004), cpu.pc);
}
test "SHA transaction commits exact memory and is atomic at every allocation failure" {
    for ([_]bool{ false, true }) |recorded| {
        try transaction(std.testing.allocator, recorded);
        try std.testing.checkAllAllocationFailures(std.testing.allocator, transaction, .{recorded});
    }
}
