//! Captures live OAM-DMA source bytes from each completed scheduler step.

const std = @import("std");
const runner = @import("runner/mod.zig");
const machine = @import("runner/machine.zig");
const interrupt_service = @import("runner/interrupt_service.zig");
const dma = runner.dma;

pub const Capture = struct {
    state: dma.State,
    bytes: std.ArrayList(u8) = .empty,

    pub fn init(state: dma.State) Capture {
        return .{ .state = state };
    }

    pub fn deinit(self: *Capture, allocator: std.mem.Allocator) void {
        self.bytes.deinit(allocator);
        self.* = undefined;
    }

    pub fn observe(
        self: *Capture,
        allocator: std.mem.Allocator,
        result: machine.CartridgeStepResult,
        system: *const [runner.cartridge_memory.SYSTEM_SIZE]u8,
    ) !void {
        var destinations: [interrupt_service.MAX_CYCLES]u16 = undefined;
        var transfer_count: usize = 0;
        for (0..result.m_cycles) |cycle| {
            const access = accessAt(result, cycle);
            const page: ?u8 = if (access) |item|
                if (item.logical_address == dma.DMA_ADDRESS and
                    item.action == .write)
                    item.value
                else
                    null
            else
                null;
            const transfers = self.state.phase == .transfer;
            const event: dma.Event = if (transfers)
                if (page) |value|
                    .{ .transfer_and_write = .{
                        .source_byte = 0,
                        .page = value,
                    } }
                else
                    .{ .transfer = 0 }
            else if (page) |value|
                .{ .write_ff46 = value }
            else
                .tick;
            const transition = try dma.Transition.apply(self.state, event);
            if (transition.transfer) |transfer| {
                destinations[transfer_count] = transfer.destination_address;
                transfer_count += 1;
            }
            self.state = transition.after;
        }
        if (transfer_count != 0)
            for (0..result.m_cycles) |cycle|
                if (accessAt(result, cycle)) |access|
                    if (access.logical_address >= dma.OAM_START and
                        access.logical_address <
                            dma.OAM_START + dma.OAM_LENGTH)
                        return error.AmbiguousDmaSourceCapture;
        for (destinations[0..transfer_count]) |address|
            try self.bytes.append(allocator, system[address]);
    }

    pub fn finish(
        self: *Capture,
        allocator: std.mem.Allocator,
        live_state: dma.State,
    ) ![]u8 {
        if (!std.meta.eql(self.state, live_state))
            return error.LiveDmaStateMismatch;
        return self.bytes.toOwnedSlice(allocator);
    }
};

fn accessAt(
    result: machine.CartridgeStepResult,
    cycle: usize,
) ?runner.cartridge_memory.Access {
    if (result.instruction) |instruction|
        return instruction.accesses[cycle];
    if (result.event == .interrupt_service)
        return result.service.cycles[cycle].access;
    return null;
}

test "capture owns one live transfer byte" {
    var capture = Capture.init(.{
        .clock = 10,
        .page = 0xc0,
        .phase = .transfer,
    });
    defer capture.deinit(std.testing.allocator);
    var system =
        [_]u8{0} ** runner.cartridge_memory.SYSTEM_SIZE;
    system[dma.OAM_START] = 0x42;
    const result = machine.CartridgeStepResult{
        .before = undefined,
        .after = undefined,
        .event = .halt_idle,
        .m_cycles = 1,
    };
    try capture.observe(std.testing.allocator, result, &system);
    try std.testing.expectEqualSlices(u8, &.{0x42}, capture.bytes.items);
    const expected = capture.state;
    const owned = try capture.finish(std.testing.allocator, expected);
    defer std.testing.allocator.free(owned);
    try std.testing.expectEqualSlices(u8, &.{0x42}, owned);
}
