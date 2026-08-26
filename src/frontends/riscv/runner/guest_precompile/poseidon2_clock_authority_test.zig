//! Re-entrant allocation coverage for CUSTOM-0 clock publication.

const std = @import("std");
const custom0 = @import("../../isa/custom0.zig");
const subject = @import("poseidon2_v1.zig");
const call_buffer = @import("call_buffer.zig");
const Cpu = @import("../cpu.zig").Cpu;
const Memory = @import("../memory.zig").Memory;
const MemoryLayout = @import("../memory_state.zig").MemoryLayout;
const StateChainTracker = @import("../state_chain.zig").StateChainTracker;
const Trace = @import("../trace.zig").Trace;

test "Poseidon2 recorded-clock execution rejects a token staled during reserve" {
    var exec_trace = Trace.init(std.testing.allocator);
    defer exec_trace.deinit();
    var reentrant = ReentrantClockAllocator{
        .child = std.testing.allocator,
        .trace = &exec_trace,
    };
    var calls = try call_buffer.Builder.init(reentrant.allocator(), 1);
    defer calls.deinit();
    var rows = try subject.ExecutionRowsBuilder.init(reentrant.allocator(), 1);
    defer rows.deinit();
    var memory = try Memory.initFallible(std.testing.allocator);
    defer memory.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    var cpu = Cpu.init(0x1000, 0x4000);
    cpu.writeReg(5, 0x2000);
    const cpu_before = cpu;

    reentrant.armed = true;
    try std.testing.expectError(
        error.ProfileClockAuthorityMismatch,
        subject.executeWithRecordedClock(
            .rv32im_zkvm_poseidon2_v1,
            custom0.encodePoseidon2(5),
            1,
            0,
            &cpu,
            &memory,
            testLayout(),
            &tracker,
            &exec_trace,
            &calls,
            &rows,
        ),
    );
    reentrant.armed = false;

    try std.testing.expect(reentrant.fired);
    try std.testing.expectEqualDeep(cpu_before, cpu);
    try std.testing.expectEqual(@as(usize, 0), memory.initialized_words.count());
    try std.testing.expectEqual(@as(usize, 0), tracker.accesses.items.len);
    try std.testing.expectEqual(@as(usize, 0), calls.len());
    try std.testing.expectEqual(@as(usize, 0), rows.len());
    try exec_trace.validateClockRange(0, 1, 1);
}

fn testLayout() MemoryLayout {
    return .{
        .program_base = 0x1000,
        .program_end = 0x1100,
        .data_base = 0x2000,
        .data_end = 0x3000,
        .stack_bottom = 0x4000,
        .stack_top = 0x5000,
        .io_base = 0x6000,
        .io_end = 0x7000,
        .input_base = 0x6000,
        .input_end = 0x6100,
        .output_len_addr = 0x6200,
        .output_data_addr = 0x6204,
        .output_base = 0x6200,
        .output_end = 0x7000,
    };
}

const ReentrantClockAllocator = struct {
    child: std.mem.Allocator,
    trace: *Trace,
    armed: bool = false,
    fired: bool = false,

    fn allocator(self: *@This()) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn trigger(self: *@This()) void {
        if (!self.armed or self.fired) return;
        self.fired = true;
        const token = self.trace.prepareRecordedExternalRetirement(
            1,
            0,
            0,
            0,
        ) catch unreachable;
        self.trace.commitRecordedExternalRetirement(token);
    }

    fn alloc(
        context: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.trigger();
        return self.child.rawAlloc(len, alignment, return_address);
    }

    fn resize(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        return_address: usize,
    ) bool {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.trigger();
        return self.child.rawResize(memory, alignment, new_len, return_address);
    }

    fn remap(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        return_address: usize,
    ) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.trigger();
        return self.child.rawRemap(memory, alignment, new_len, return_address);
    }

    fn free(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.child.rawFree(memory, alignment, return_address);
    }

    const vtable = std.mem.Allocator.VTable{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };
};
