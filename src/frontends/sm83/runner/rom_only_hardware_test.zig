const std = @import("std");
const machine = @import("machine.zig");
const runner = @import("mod.zig");

const IF: u16 = 0xff0f;

fn activePpu() runner.ppu_mmio.State {
    return .{
        .timing = .{
            .lcd_enabled = true,
            .line = 10,
            .dot = 0,
            .lyc = 0,
        },
        .lcdc = 0x91,
        .interrupt_flags = 0xe1,
    };
}

test "ROM-only HALT advances the attached PPU by four dots" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    var rom = [_]u8{0} ** runner.rom_only_memory.ROM_SIZE;
    try memory.installRomOnly(&rom);
    memory.write(IF, 0xe1);

    var ppu = activePpu();
    try memory.attachPpu(&ppu);
    defer memory.detachPpu();
    var scheduler = try machine.Machine.restore(
        &memory,
        .{ .halted = true },
        .{ .div_counter = 0xabcc },
        false,
    );
    const result = try scheduler.step();

    try std.testing.expectEqual(machine.SchedulerEvent.halt_idle, result.event);
    try std.testing.expectEqual(@as(u16, 4), ppu.timing.dot);
    try std.testing.expectEqual(@as(u16, 0xabd0), scheduler.timer.div_counter);

    // Activity control: the same restored transition without attachment must
    // leave the independent PPU checkpoint unchanged.
    memory.detachPpu();
    const before = ppu;
    _ = try scheduler.step();
    try std.testing.expectEqualDeep(before, ppu);
    try memory.attachPpu(&ppu);
}

test "ROM-only CPU writes cannot mutate the committed cartridge bytes" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    var rom = [_]u8{0} ** runner.rom_only_memory.ROM_SIZE;
    rom[0x0100] = 0x3e; // LD A,d8
    rom[0x0101] = 0x42;
    rom[0x0102] = 0xea; // LD (0100),A
    rom[0x0103] = 0x00;
    rom[0x0104] = 0x01;
    try memory.installRomOnly(&rom);
    var scheduler = try machine.Machine.restore(
        &memory,
        .{ .pc = 0x0100 },
        .{},
        false,
    );

    _ = try scheduler.step();
    _ = try scheduler.step();
    try std.testing.expectEqual(@as(u8, 0x3e), memory.read(0x0100));
}
