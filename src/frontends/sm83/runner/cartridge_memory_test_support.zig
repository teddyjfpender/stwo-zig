//! Shared allocation fixture for focused cartridge-memory tests.

const std = @import("std");

pub fn Fixture(
    comptime cartridge_mod: type,
    comptime header: type,
    comptime Memory: type,
    comptime system_size: usize,
) type {
    return struct {
        const Self = @This();

        rom: *[header.ROM_SIZE]u8,
        sram: *[header.RAM_SIZE]u8,
        system: *[system_size]u8,
        memory: Memory,

        pub fn init(
            allocator: std.mem.Allocator,
            data_bus: u8,
        ) !Self {
            const rom = try allocator.create([header.ROM_SIZE]u8);
            errdefer allocator.destroy(rom);
            const sram = try allocator.create([header.RAM_SIZE]u8);
            errdefer allocator.destroy(sram);
            const system = try allocator.create([system_size]u8);
            errdefer allocator.destroy(system);
            @memset(sram, 0);
            @memset(system, 0);
            for (0..header.ROM_BANK_COUNT) |bank| {
                @memset(
                    rom[bank * header.ROM_BANK_SIZE .. (bank + 1) * header.ROM_BANK_SIZE],
                    @intCast(bank),
                );
            }
            rom[header.CARTRIDGE_TYPE_OFFSET] =
                header.CARTRIDGE_TYPE_MBC3_RAM_BATTERY;
            rom[header.ROM_SIZE_CODE_OFFSET] = header.ROM_SIZE_CODE_1_MIB;
            rom[header.RAM_SIZE_CODE_OFFSET] = header.RAM_SIZE_CODE_32_KIB;
            rom[header.HEADER_CHECKSUM_OFFSET] =
                header.headerChecksum(rom);
            std.mem.writeInt(
                u16,
                rom[header.GLOBAL_CHECKSUM_OFFSET..header.HEADER_END][0..2],
                header.globalChecksum(rom),
                .big,
            );
            const cartridge = try cartridge_mod.Cartridge.init(rom);
            return .{
                .rom = rom,
                .sram = sram,
                .system = system,
                .memory = Memory.init(
                    cartridge,
                    sram,
                    system,
                    .{},
                    data_bus,
                ),
            };
        }

        pub fn deinit(
            self: *Self,
            allocator: std.mem.Allocator,
        ) void {
            allocator.destroy(self.system);
            allocator.destroy(self.sram);
            allocator.destroy(self.rom);
            self.* = undefined;
        }
    };
}
