const std = @import("std");
const runner = @import("mod.zig");
const cartridge_mod = @import("../cartridge/mod.zig");

test "cartridge runner preserves mapper metadata across a bank switch" {
    const header = cartridge_mod.header;
    const allocator = std.testing.allocator;
    const rom = try allocator.create([header.ROM_SIZE]u8);
    defer allocator.destroy(rom);
    const sram = try allocator.create([header.RAM_SIZE]u8);
    defer allocator.destroy(sram);
    const system = try allocator.create([runner.cartridge_memory.SYSTEM_SIZE]u8);
    defer allocator.destroy(system);
    @memset(rom, 0);
    @memset(sram, 0);
    @memset(system, 0);

    rom[0] = 0x3e; // LD A,2
    rom[1] = 2;
    rom[2] = 0xea; // LD (0x2000),A
    rom[3] = 0;
    rom[4] = 0x20;
    rom[0x8000] = 0x00; // Bank 2 NOP.
    rom[header.CARTRIDGE_TYPE_OFFSET] =
        header.CARTRIDGE_TYPE_MBC3_RAM_BATTERY;
    rom[header.ROM_SIZE_CODE_OFFSET] = header.ROM_SIZE_CODE_1_MIB;
    rom[header.RAM_SIZE_CODE_OFFSET] = header.RAM_SIZE_CODE_32_KIB;
    rom[header.HEADER_CHECKSUM_OFFSET] = header.headerChecksum(rom);
    std.mem.writeInt(
        u16,
        rom[header.GLOBAL_CHECKSUM_OFFSET..header.HEADER_END][0..2],
        header.globalChecksum(rom),
        .big,
    );

    const cartridge = try cartridge_mod.Cartridge.init(rom);
    var memory = runner.cartridge_memory.Memory.init(
        cartridge,
        sram,
        system,
        .{},
        0xff,
    );
    var state = runner.Cpu{};
    _ = try runner.stepCartridge(&state, &memory);
    const bank_switch = try runner.stepCartridge(&state, &memory);
    const control = bank_switch.accesses[3].?;
    try std.testing.expectEqual(
        runner.cartridge_memory.Region.mapper_control,
        control.region,
    );
    try std.testing.expectEqual(@as(u7, 0), control.mapper_before.rom_bank_register);
    try std.testing.expectEqual(@as(u7, 2), control.mapper_after.rom_bank_register);
    state.pc = 0x4000;
    const banked = try runner.stepCartridge(&state, &memory);
    try std.testing.expectEqual(
        @as(?runner.cartridge_memory.PhysicalOffset, 0x8000),
        banked.accesses[0].?.physical_offset,
    );
    try std.testing.expectEqual(@as(u8, 0), banked.instruction.cycles[0].value);
}

test "cartridge CPU load observes hardware IF read mask" {
    const header = cartridge_mod.header;
    const allocator = std.testing.allocator;
    const rom = try allocator.create([header.ROM_SIZE]u8);
    defer allocator.destroy(rom);
    const sram = try allocator.create([header.RAM_SIZE]u8);
    defer allocator.destroy(sram);
    const system = try allocator.create([runner.cartridge_memory.SYSTEM_SIZE]u8);
    defer allocator.destroy(system);
    @memset(rom, 0);
    @memset(sram, 0);
    @memset(system, 0);

    rom[0] = 0xfa; // LD A,(FF0F)
    rom[1] = 0x0f;
    rom[2] = 0xff;
    rom[header.CARTRIDGE_TYPE_OFFSET] =
        header.CARTRIDGE_TYPE_MBC3_RAM_BATTERY;
    rom[header.ROM_SIZE_CODE_OFFSET] = header.ROM_SIZE_CODE_1_MIB;
    rom[header.RAM_SIZE_CODE_OFFSET] = header.RAM_SIZE_CODE_32_KIB;
    rom[header.HEADER_CHECKSUM_OFFSET] = header.headerChecksum(rom);
    std.mem.writeInt(
        u16,
        rom[header.GLOBAL_CHECKSUM_OFFSET..header.HEADER_END][0..2],
        header.globalChecksum(rom),
        .big,
    );

    const cartridge = try cartridge_mod.Cartridge.init(rom);
    var memory = runner.cartridge_memory.Memory.init(
        cartridge,
        sram,
        system,
        .{},
        0,
    );
    system[runner.cartridge_memory.INTERRUPT_FLAGS] = 0;
    var state = runner.Cpu{};
    const trace = try runner.stepCartridge(&state, &memory);

    try std.testing.expectEqual(@as(u8, 0xe0), state.a);
    try std.testing.expectEqual(@as(u8, 0xe0), trace.instruction.cycles[3].value);
    try std.testing.expectEqual(
        @as(u8, 0xe0),
        trace.accesses[3].?.value,
    );
    try std.testing.expectEqual(
        @as(u8, 0),
        system[runner.cartridge_memory.INTERRUPT_FLAGS],
    );
}
