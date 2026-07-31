const std = @import("std");
const cartridge = @import("../cartridge/mod.zig");
const memory = @import("cartridge_memory.zig");
const ppu_mmio = @import("ppu_mmio.zig");
const ppu_timing = @import("ppu_timing.zig");

test "detached PPU registers retain ordinary system compatibility" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    fixture.system[ppu_mmio.LCDC_ADDRESS] = 0x12;
    fixture.system[ppu_mmio.STAT_ADDRESS] = 0x34;

    const read = try fixture.memory.read(ppu_mmio.LCDC_ADDRESS);
    try std.testing.expectEqual(@as(u8, 0x12), read.value);
    try std.testing.expectEqual(memory.Region.system, read.access.region);
    const write = try fixture.memory.write(ppu_mmio.STAT_ADDRESS, 0x56);
    try std.testing.expectEqual(memory.Region.system, write.region);
    fixture.memory.tickMcycle();
    try std.testing.expectEqual(
        @as(u8, 0x56),
        fixture.system[ppu_mmio.STAT_ADDRESS],
    );
}

test "attached PPU routes all registers without hidden ticks" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    fixture.system[memory.INTERRUPT_FLAGS] = 0x04;
    var invalid = ppu_mmio.State{ .lcdc = 0x80 };
    try std.testing.expectError(
        error.LcdcEnableMismatch,
        fixture.memory.attachPpu(&invalid),
    );
    try std.testing.expect(fixture.memory.ppu == null);

    var ppu = ppu_mmio.State{};
    try fixture.memory.attachPpu(&ppu);
    try std.testing.expectEqual(@as(u8, 0x04), ppu.interrupt_flags);
    const mapper = fixture.memory.mapper;
    for ([_]struct { address: u16, value: u8 }{
        .{ .address = ppu_mmio.LCDC_ADDRESS, .value = 0 },
        .{ .address = ppu_mmio.STAT_ADDRESS, .value = 0x80 },
        .{ .address = ppu_mmio.SCY_ADDRESS, .value = 0 },
        .{ .address = ppu_mmio.SCX_ADDRESS, .value = 0 },
        .{ .address = ppu_mmio.LY_ADDRESS, .value = 0 },
        .{ .address = ppu_mmio.LYC_ADDRESS, .value = 0 },
        .{ .address = ppu_mmio.WY_ADDRESS, .value = 0 },
    }) |case| {
        const read = try fixture.memory.read(case.address);
        try std.testing.expectEqual(case.value, read.value);
        try expectMetadata(
            read.access,
            case.address,
            .read,
            case.value,
            mapper,
        );
    }

    for ([_]struct { address: u16, value: u8 }{
        .{ .address = ppu_mmio.LCDC_ADDRESS, .value = 0x91 },
        .{ .address = ppu_mmio.STAT_ADDRESS, .value = 0x78 },
        .{ .address = ppu_mmio.SCY_ADDRESS, .value = 0x42 },
        .{ .address = ppu_mmio.SCX_ADDRESS, .value = 0x43 },
        .{ .address = ppu_mmio.LY_ADDRESS, .value = 0xa5 },
        .{ .address = ppu_mmio.LYC_ADDRESS, .value = 0x22 },
        .{ .address = ppu_mmio.WY_ADDRESS, .value = 0x4a },
    }) |case| {
        const before_dot = ppu.timing.dot;
        const access = try fixture.memory.write(case.address, case.value);
        try expectMetadata(access, case.address, .write, case.value, mapper);
        try std.testing.expectEqual(before_dot, ppu.timing.dot);
    }
    try std.testing.expectEqual(@as(u8, 0x91), ppu.lcdc);
    try std.testing.expectEqual(@as(u8, 0x42), ppu.scy);
    try std.testing.expectEqual(@as(u8, 0x43), ppu.scx);
    try std.testing.expectEqual(@as(u8, 0x22), ppu.timing.lyc);
    try std.testing.expectEqual(@as(u8, 0x4a), ppu.wy);
    try std.testing.expectEqual(@as(u16, 0), ppu.timing.dot);

    fixture.memory.tickMcycle();
    try std.testing.expectEqual(@as(u16, 4), ppu.timing.dot);
    try std.testing.expectEqual(
        ppu.timing.readStat(),
        fixture.system[ppu_mmio.STAT_ADDRESS],
    );
    const scy = try fixture.memory.read(ppu_mmio.SCY_ADDRESS);
    try expectMetadata(
        scy.access,
        ppu_mmio.SCY_ADDRESS,
        .read,
        0x42,
        mapper,
    );

    fixture.memory.detachPpu();
    try std.testing.expect(fixture.memory.ppu == null);
    const detached = try fixture.memory.read(ppu_mmio.LCDC_ADDRESS);
    try std.testing.expectEqual(memory.Region.system, detached.access.region);
    try std.testing.expectEqual(@as(u8, 0x91), detached.value);
}

test "PPU ticks OR VBlank and STAT into memory-owned IF" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    fixture.system[memory.INTERRUPT_FLAGS] = 0x04;
    var ppu = ppu_mmio.State{
        .timing = .{
            .lcd_enabled = true,
            .line = 144,
            .dot = 0,
            .lyc = 0xff,
            .stat_enable = 0x4,
        },
        .lcdc = 0x80,
        .interrupt_flags = 0xff,
    };
    try fixture.memory.attachPpu(&ppu);
    try std.testing.expectEqual(@as(u8, 0x04), ppu.interrupt_flags);

    fixture.memory.tickMcycle();
    try std.testing.expectEqual(@as(u8, 144), ppu.timing.line);
    try std.testing.expectEqual(@as(u16, 4), ppu.timing.dot);
    try std.testing.expectEqual(
        @as(u8, 0x04 |
            ppu_timing.VBLANK_INTERRUPT |
            ppu_timing.STAT_INTERRUPT),
        fixture.system[memory.INTERRUPT_FLAGS],
    );

    const replace = try fixture.memory.write(
        memory.INTERRUPT_FLAGS,
        0x10,
    );
    try std.testing.expectEqual(memory.Region.system, replace.region);
    try std.testing.expectEqual(@as(u8, 0x10), ppu.interrupt_flags);
    try std.testing.expectEqual(
        @as(u8, 0x10),
        fixture.system[memory.INTERRUPT_FLAGS],
    );
}

fn expectMetadata(
    access: memory.Access,
    address: u16,
    action: memory.Action,
    value: u8,
    mapper: cartridge.mbc3.State,
) !void {
    try std.testing.expectEqual(address, access.logical_address);
    try std.testing.expectEqual(action, access.action);
    try std.testing.expectEqual(memory.Region.ppu_mmio, access.region);
    try std.testing.expectEqual(@as(?memory.PhysicalOffset, null), access.physical_offset);
    try std.testing.expectEqualDeep(mapper, access.mapper_before);
    try std.testing.expectEqualDeep(mapper, access.mapper_after);
    try std.testing.expectEqual(value, access.value);
}

const Fixture = struct {
    rom: *[cartridge.header.ROM_SIZE]u8,
    sram: *[cartridge.header.RAM_SIZE]u8,
    system: *[memory.SYSTEM_SIZE]u8,
    memory: memory.Memory,

    fn init() !Fixture {
        const allocator = std.testing.allocator;
        const rom = try allocator.create([cartridge.header.ROM_SIZE]u8);
        errdefer allocator.destroy(rom);
        const sram = try allocator.create([cartridge.header.RAM_SIZE]u8);
        errdefer allocator.destroy(sram);
        const system = try allocator.create([memory.SYSTEM_SIZE]u8);
        errdefer allocator.destroy(system);
        @memset(rom, 0);
        @memset(sram, 0);
        @memset(system, 0);
        rom[cartridge.header.CARTRIDGE_TYPE_OFFSET] =
            cartridge.header.CARTRIDGE_TYPE_MBC3_RAM_BATTERY;
        rom[cartridge.header.ROM_SIZE_CODE_OFFSET] =
            cartridge.header.ROM_SIZE_CODE_1_MIB;
        rom[cartridge.header.RAM_SIZE_CODE_OFFSET] =
            cartridge.header.RAM_SIZE_CODE_32_KIB;
        rom[cartridge.header.HEADER_CHECKSUM_OFFSET] =
            cartridge.header.headerChecksum(rom);
        std.mem.writeInt(
            u16,
            rom[cartridge.header.GLOBAL_CHECKSUM_OFFSET..cartridge.header.HEADER_END][0..2],
            cartridge.header.globalChecksum(rom),
            .big,
        );
        const cart = try cartridge.Cartridge.init(rom);
        return .{
            .rom = rom,
            .sram = sram,
            .system = system,
            .memory = memory.Memory.init(cart, sram, system, .{}, 0),
        };
    }

    fn deinit(self: *Fixture) void {
        const allocator = std.testing.allocator;
        allocator.destroy(self.system);
        allocator.destroy(self.sram);
        allocator.destroy(self.rom);
        self.* = undefined;
    }
};
