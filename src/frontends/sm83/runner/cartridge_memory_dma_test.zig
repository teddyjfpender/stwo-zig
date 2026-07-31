//! Live DMG OAM-DMA integration and mutation controls.

const std = @import("std");
const cartridge_mod = @import("../cartridge/mod.zig");
const header = cartridge_mod.header;
const memory_mod = @import("cartridge_memory.zig");
const dma = @import("dma.zig");
const live_dma = @import("live_dma.zig");
const machine_mod = @import("machine.zig");
const Fixture = @import("cartridge_memory_test_support.zig").Fixture(
    cartridge_mod,
    header,
    memory_mod.Memory,
    memory_mod.SYSTEM_SIZE,
);

const SOURCE_START: u16 = 0xc000;
const OAM_END: u16 = dma.OAM_START + dma.OAM_LENGTH;

test "live DMA copies exactly 160 bytes after warm-up and completion" {
    var fixture = try Fixture.init(std.testing.allocator, 0xff);
    defer fixture.deinit(std.testing.allocator);
    var expected: [dma.OAM_LENGTH]u8 = undefined;
    for (&expected, 0..) |*byte, index| {
        byte.* = pattern(index);
        fixture.system[SOURCE_START + @as(u16, @intCast(index))] = byte.*;
    }
    @memset(fixture.system[dma.OAM_START..OAM_END], 0xa5);
    fixture.system[dma.OAM_START - 1] = 0x31;
    fixture.system[OAM_END] = 0x73;

    var controller = try live_dma.Controller.init(.{});
    try fixture.memory.attachDma(&controller);
    defer fixture.memory.detachDma();
    const start = try fixture.memory.write(dma.DMA_ADDRESS, 0xc0);
    try std.testing.expectEqual(dma.CpuAccess.allowed, start.dma_class);
    fixture.memory.tickMcycle();
    try std.testing.expectEqual(dma.Phase.startup, controller.state.phase);

    fixture.memory.tickMcycle();
    try std.testing.expectEqual(dma.Phase.transfer, controller.state.phase);
    try std.testing.expectEqual(@as(u8, 0), controller.state.copied);
    try expectOamFilled(fixture.system, 0xa5);

    var positive_transfers: usize = 0;
    for (expected, 0..) |byte, index| {
        fixture.memory.tickMcycle();
        positive_transfers += 1;
        try std.testing.expectEqual(
            byte,
            fixture.system[dma.OAM_START + @as(u16, @intCast(index))],
        );
    }
    try std.testing.expectEqual(
        @as(usize, dma.TRANSFER_MCYCLES),
        positive_transfers,
    );
    try std.testing.expectEqual(dma.Phase.finishing, controller.state.phase);
    try std.testing.expectEqual(@as(u32, 162), controller.state.clock);
    try std.testing.expectEqual(@as(u8, 0x31), fixture.system[dma.OAM_START - 1]);
    try std.testing.expectEqual(@as(u8, 0x73), fixture.system[OAM_END]);

    fixture.memory.tickMcycle();
    try std.testing.expectEqual(dma.Phase.idle, controller.state.phase);
    try std.testing.expectEqual(@as(u32, 163), controller.state.clock);
    try expectOam(fixture.system, expected);
}

test "FF46 omission source destination and inactive mutations are detected" {
    var fixture = try Fixture.init(std.testing.allocator, 0xff);
    defer fixture.deinit(std.testing.allocator);
    var expected: [dma.OAM_LENGTH]u8 = undefined;
    for (&expected, 0..) |*byte, index| {
        byte.* = pattern(index);
        fixture.system[SOURCE_START + @as(u16, @intCast(index))] = byte.*;
    }
    @memset(fixture.system[dma.OAM_START..OAM_END], 0xa5);

    var controller = try live_dma.Controller.init(.{});
    try fixture.memory.attachDma(&controller);
    defer fixture.memory.detachDma();
    for (0..163) |_| fixture.memory.tickMcycle();
    try std.testing.expectEqual(dma.Phase.idle, controller.state.phase);
    try std.testing.expectError(
        error.OamMismatch,
        validateOam(fixture.system, expected),
    );
    try expectOamFilled(fixture.system, 0xa5);

    _ = try fixture.memory.write(dma.DMA_ADDRESS, 0xc0);
    fixture.memory.tickMcycle();
    for (0..162) |_| fixture.memory.tickMcycle();
    try validateOam(fixture.system, expected);

    expected[37] ^= 1;
    try std.testing.expectError(
        error.OamMismatch,
        validateOam(fixture.system, expected),
    );
    expected[37] ^= 1;
    std.mem.swap(
        u8,
        &fixture.system[dma.OAM_START + 41],
        &fixture.system[dma.OAM_START + 42],
    );
    try std.testing.expectError(
        error.OamMismatch,
        validateOam(fixture.system, expected),
    );
}

test "CPU blocking keeps IO HRAM and the other bus live" {
    var fixture = try Fixture.init(std.testing.allocator, 0xff);
    defer fixture.deinit(std.testing.allocator);
    for (0..dma.OAM_LENGTH) |index|
        fixture.system[SOURCE_START + @as(u16, @intCast(index))] =
            @intCast(0x40 + index);
    fixture.system[dma.OAM_START] = 0x77;
    fixture.system[0x8000] = 0x81;
    fixture.system[0xff10] = 0x92;
    fixture.system[0xff80] = 0xa3;

    var controller = try live_dma.Controller.init(.{});
    try fixture.memory.attachDma(&controller);
    defer fixture.memory.detachDma();
    _ = try fixture.memory.write(dma.DMA_ADDRESS, 0xc0);
    fixture.memory.tickMcycle();

    const warm_oam = try fixture.memory.read(dma.OAM_START);
    try std.testing.expectEqual(@as(u8, 0x77), warm_oam.value);
    try std.testing.expectEqual(dma.CpuAccess.allowed, warm_oam.access.dma_class);
    fixture.memory.tickMcycle();

    const blocked = try fixture.memory.read(0x1234);
    try std.testing.expectEqual(@as(u8, 0x40), blocked.value);
    try std.testing.expectEqual(
        dma.CpuAccess.blocked_source_bus,
        blocked.access.dma_class,
    );
    try std.testing.expectEqual(@as(u16, 0x1234), blocked.access.logical_address);
    try std.testing.expectEqual(
        memory_mod.Region.system,
        blocked.access.region,
    );
    fixture.memory.tickMcycle();
    try std.testing.expectEqual(@as(u8, 1), controller.state.copied);

    const vram = try fixture.memory.read(0x8000);
    try std.testing.expectEqual(@as(u8, 0x81), vram.value);
    try std.testing.expectEqual(dma.CpuAccess.allowed, vram.access.dma_class);
    fixture.memory.tickMcycle();
    const io = try fixture.memory.read(0xff10);
    try std.testing.expectEqual(@as(u8, 0x92), io.value);
    try std.testing.expectEqual(dma.CpuAccess.allowed, io.access.dma_class);
    fixture.memory.tickMcycle();
    const hram = try fixture.memory.read(0xff80);
    try std.testing.expectEqual(@as(u8, 0xa3), hram.value);
    try std.testing.expectEqual(dma.CpuAccess.allowed, hram.access.dma_class);
    fixture.memory.tickMcycle();

    const oam = try fixture.memory.read(dma.OAM_START);
    try std.testing.expectEqual(@as(u8, 0xff), oam.value);
    try std.testing.expectEqual(
        dma.CpuAccess.blocked_oam,
        oam.access.dma_class,
    );
    fixture.memory.tickMcycle();
    fixture.system[dma.OAM_START + 0x20] = 0x5c;
    const dropped = try fixture.memory.write(
        dma.OAM_START + 0x20,
        0x16,
    );
    try std.testing.expectEqual(
        dma.CpuAccess.blocked_oam,
        dropped.dma_class,
    );
    try std.testing.expectEqual(
        @as(u8, 0x5c),
        fixture.system[dma.OAM_START + 0x20],
    );
    fixture.memory.tickMcycle();
}

test "fresh destination-zero OAM writes are blocked" {
    var fixture = try Fixture.init(std.testing.allocator, 0xff);
    defer fixture.deinit(std.testing.allocator);
    fixture.system[dma.OAM_START] = 0x77;
    var controller = try live_dma.Controller.init(.{});
    try fixture.memory.attachDma(&controller);
    defer fixture.memory.detachDma();

    _ = try fixture.memory.write(dma.DMA_ADDRESS, 0xc0);
    fixture.memory.tickMcycle();
    const write = try fixture.memory.write(dma.OAM_START, 0x11);
    try std.testing.expectEqual(
        dma.CpuAccess.blocked_oam,
        write.dma_class,
    );
    try std.testing.expectEqual(@as(u8, 0x77), fixture.system[dma.OAM_START]);
    fixture.memory.tickMcycle();
}

test "blocked source writes preserve DMG redirect and OAM AND behavior" {
    var fixture = try Fixture.init(std.testing.allocator, 0xff);
    defer fixture.deinit(std.testing.allocator);
    fixture.system[SOURCE_START] = 0xf3;
    var controller = try live_dma.Controller.init(.{});
    try fixture.memory.attachDma(&controller);

    _ = try fixture.memory.write(dma.DMA_ADDRESS, 0xc0);
    fixture.memory.tickMcycle();
    fixture.memory.tickMcycle();
    const corrupted = try fixture.memory.write(0x1234, 0x0f);
    try std.testing.expectEqual(
        dma.CpuAccess.blocked_source_bus,
        corrupted.dma_class,
    );
    try std.testing.expectEqual(@as(u8, 0x03), fixture.system[dma.OAM_START]);
    try std.testing.expectEqual(@as(u8, 0xf3), fixture.system[SOURCE_START]);
    fixture.memory.tickMcycle();
    fixture.memory.detachDma();

    fixture.rom[0x1200] = 0x91;
    controller = try live_dma.Controller.init(.{});
    try fixture.memory.attachDma(&controller);
    defer fixture.memory.detachDma();
    _ = try fixture.memory.write(dma.DMA_ADDRESS, 0x12);
    fixture.memory.tickMcycle();
    fixture.memory.tickMcycle();
    const redirected = try fixture.memory.write(0xc123, 0x0a);
    try std.testing.expectEqual(
        dma.CpuAccess.blocked_source_bus,
        redirected.dma_class,
    );
    try std.testing.expectEqual(
        memory_mod.Region.mapper_control,
        redirected.region,
    );
    try std.testing.expect(fixture.memory.mapper.ram_enabled);
    try std.testing.expectEqual(@as(u8, 0x91), fixture.system[dma.OAM_START]);
    fixture.memory.tickMcycle();
}

test "restart copies the old source before installing the new FF46 page" {
    var fixture = try Fixture.init(std.testing.allocator, 0xff);
    defer fixture.deinit(std.testing.allocator);
    fixture.system[0xc000] = 0x11;
    fixture.system[0xc001] = 0x22;
    fixture.system[0xd000] = 0x33;
    var controller = try live_dma.Controller.init(.{});
    try fixture.memory.attachDma(&controller);
    defer fixture.memory.detachDma();

    _ = try fixture.memory.write(dma.DMA_ADDRESS, 0xc0);
    fixture.memory.tickMcycle();
    fixture.memory.tickMcycle();
    fixture.memory.tickMcycle();
    const restart = try fixture.memory.write(dma.DMA_ADDRESS, 0xd0);
    try std.testing.expectEqual(dma.CpuAccess.allowed, restart.dma_class);
    try std.testing.expectEqual(@as(u8, 0x11), fixture.system[dma.OAM_START]);
    try std.testing.expectEqual(@as(u8, 0x22), fixture.system[dma.OAM_START + 1]);
    try std.testing.expectEqual(dma.Phase.startup, controller.state.phase);
    try std.testing.expect(controller.state.restarting);
    try std.testing.expectEqual(@as(u8, 0xd0), controller.state.page);
    try std.testing.expectEqual(
        @as(u8, 0xd0),
        fixture.system[dma.DMA_ADDRESS],
    );
    fixture.memory.tickMcycle();

    fixture.memory.tickMcycle();
    try std.testing.expectEqual(dma.Phase.transfer, controller.state.phase);
    try std.testing.expect(controller.state.restarting);
    fixture.memory.tickMcycle();
    try std.testing.expectEqual(@as(u8, 0x33), fixture.system[dma.OAM_START]);
    try std.testing.expect(!controller.state.restarting);
}

test "CartridgeMachine owns and advances live DMA without a side attachment" {
    var fixture = try Fixture.init(std.testing.allocator, 0xff);
    defer fixture.deinit(std.testing.allocator);
    const start: u16 = 0x0200;
    const program = [_]u8{
        0x3e, 0xc0, // LD A,C0
        0xe0, 0x46, // LDH (46),A
        0x00, // NOP
    };
    @memcpy(fixture.rom[start .. start + program.len], &program);
    var machine = try machine_mod.CartridgeMachine.init(
        &fixture.memory,
        .{ .pc = start },
    );
    _ = try machine.step();
    _ = try machine.step();
    try std.testing.expectEqual(dma.Phase.startup, machine.dma.state.phase);
    try std.testing.expectEqual(@as(u8, 0xc0), machine.dma.state.page);
    try std.testing.expectEqual(@as(?*live_dma.Controller, null), fixture.memory.dma);

    _ = try machine.step();
    try std.testing.expectEqual(dma.Phase.transfer, machine.dma.state.phase);
    try std.testing.expectEqual(@as(u8, 0), machine.dma.state.copied);
}

test "CartridgeMachine fails closed on active DMA HALT and STOP" {
    var fixture = try Fixture.init(std.testing.allocator, 0xff);
    defer fixture.deinit(std.testing.allocator);
    var halted = try machine_mod.CartridgeMachine.init(
        &fixture.memory,
        .{ .halted = true },
    );
    halted.dma.state = .{
        .clock = 7,
        .page = 0xc0,
        .copied = 1,
        .phase = .transfer,
    };
    const before = halted.dma.state;
    try std.testing.expectError(
        error.UnsupportedActiveDmaHalt,
        halted.step(),
    );
    try std.testing.expectEqualDeep(before, halted.dma.state);
    try std.testing.expectEqual(
        @as(?*live_dma.Controller, null),
        fixture.memory.dma,
    );

    var stopped = try machine_mod.CartridgeMachine.init(
        &fixture.memory,
        .{ .stopped = true },
    );
    stopped.dma.state = before;
    try std.testing.expectError(error.Stopped, stopped.step());
    try std.testing.expectEqualDeep(before, stopped.dma.state);
}

fn pattern(index: usize) u8 {
    return @truncate(index * 37 + 11);
}

fn validateOam(
    system: *const [memory_mod.SYSTEM_SIZE]u8,
    expected: [dma.OAM_LENGTH]u8,
) error{OamMismatch}!void {
    for (expected, 0..) |byte, index|
        if (system[dma.OAM_START + @as(u16, @intCast(index))] != byte)
            return error.OamMismatch;
}

fn expectOam(
    system: *const [memory_mod.SYSTEM_SIZE]u8,
    expected: [dma.OAM_LENGTH]u8,
) !void {
    try validateOam(system, expected);
}

fn expectOamFilled(
    system: *const [memory_mod.SYSTEM_SIZE]u8,
    value: u8,
) !void {
    for (system[dma.OAM_START..OAM_END]) |byte|
        try std.testing.expectEqual(value, byte);
}
