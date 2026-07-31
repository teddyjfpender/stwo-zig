//! Fail-closed validation for the RTC-free Pokémon Red/Blue cartridge shape.

const std = @import("std");

pub const HEADER_END: usize = 0x150;
pub const CARTRIDGE_TYPE_OFFSET: usize = 0x147;
pub const ROM_SIZE_CODE_OFFSET: usize = 0x148;
pub const RAM_SIZE_CODE_OFFSET: usize = 0x149;
pub const HEADER_CHECKSUM_OFFSET: usize = 0x14d;
pub const GLOBAL_CHECKSUM_OFFSET: usize = 0x14e;

pub const CARTRIDGE_TYPE_MBC3_RAM_BATTERY: u8 = 0x13;
pub const ROM_SIZE_CODE_1_MIB: u8 = 0x05;
pub const RAM_SIZE_CODE_32_KIB: u8 = 0x03;
pub const ROM_SIZE: usize = 1024 * 1024;
pub const RAM_SIZE: usize = 32 * 1024;
pub const ROM_BANK_SIZE: usize = 16 * 1024;
pub const RAM_BANK_SIZE: usize = 8 * 1024;
pub const ROM_BANK_COUNT: usize = ROM_SIZE / ROM_BANK_SIZE;
pub const RAM_BANK_COUNT: usize = RAM_SIZE / RAM_BANK_SIZE;

pub const ValidationError = error{
    InvalidRomLength,
    UnsupportedCartridgeType,
    UnsupportedRomSize,
    UnsupportedRamSize,
    HeaderChecksumMismatch,
    GlobalChecksumMismatch,
};

pub const Header = struct {
    cartridge_type: u8,
    rom_size_code: u8,
    ram_size_code: u8,
    header_checksum: u8,
    global_checksum: u16,

    pub fn parse(rom: []const u8) ValidationError!Header {
        if (rom.len != ROM_SIZE) return error.InvalidRomLength;
        const fixed = rom[0..ROM_SIZE];
        if (fixed[CARTRIDGE_TYPE_OFFSET] != CARTRIDGE_TYPE_MBC3_RAM_BATTERY)
            return error.UnsupportedCartridgeType;
        if (fixed[ROM_SIZE_CODE_OFFSET] != ROM_SIZE_CODE_1_MIB)
            return error.UnsupportedRomSize;
        if (fixed[RAM_SIZE_CODE_OFFSET] != RAM_SIZE_CODE_32_KIB)
            return error.UnsupportedRamSize;

        const stored_header_checksum = fixed[HEADER_CHECKSUM_OFFSET];
        if (headerChecksum(fixed) != stored_header_checksum)
            return error.HeaderChecksumMismatch;
        const stored_global_checksum = std.mem.readInt(
            u16,
            fixed[GLOBAL_CHECKSUM_OFFSET..HEADER_END][0..2],
            .big,
        );
        if (globalChecksum(fixed) != stored_global_checksum)
            return error.GlobalChecksumMismatch;

        return .{
            .cartridge_type = fixed[CARTRIDGE_TYPE_OFFSET],
            .rom_size_code = fixed[ROM_SIZE_CODE_OFFSET],
            .ram_size_code = fixed[RAM_SIZE_CODE_OFFSET],
            .header_checksum = stored_header_checksum,
            .global_checksum = stored_global_checksum,
        };
    }
};

pub fn headerChecksum(rom: *const [ROM_SIZE]u8) u8 {
    var checksum: u8 = 0;
    for (rom[0x134..HEADER_CHECKSUM_OFFSET]) |byte| {
        checksum -%= byte;
        checksum -%= 1;
    }
    return checksum;
}

pub fn globalChecksum(rom: *const [ROM_SIZE]u8) u16 {
    var checksum: u16 = 0;
    for (rom, 0..) |byte, offset| {
        if (offset == GLOBAL_CHECKSUM_OFFSET or
            offset == GLOBAL_CHECKSUM_OFFSET + 1)
            continue;
        checksum +%= byte;
    }
    return checksum;
}

fn validRom() [ROM_SIZE]u8 {
    var rom = [_]u8{0} ** ROM_SIZE;
    rom[CARTRIDGE_TYPE_OFFSET] = CARTRIDGE_TYPE_MBC3_RAM_BATTERY;
    rom[ROM_SIZE_CODE_OFFSET] = ROM_SIZE_CODE_1_MIB;
    rom[RAM_SIZE_CODE_OFFSET] = RAM_SIZE_CODE_32_KIB;
    rom[HEADER_CHECKSUM_OFFSET] = headerChecksum(&rom);
    const checksum = globalChecksum(&rom);
    std.mem.writeInt(
        u16,
        rom[GLOBAL_CHECKSUM_OFFSET..HEADER_END][0..2],
        checksum,
        .big,
    );
    return rom;
}

test "header accepts exactly the RTC-free 1 MiB ROM and 32 KiB RAM shape" {
    const rom = validRom();
    const parsed = try Header.parse(&rom);
    try std.testing.expectEqual(
        CARTRIDGE_TYPE_MBC3_RAM_BATTERY,
        parsed.cartridge_type,
    );
    try std.testing.expectEqual(ROM_SIZE_CODE_1_MIB, parsed.rom_size_code);
    try std.testing.expectEqual(RAM_SIZE_CODE_32_KIB, parsed.ram_size_code);
    try std.testing.expectEqual(headerChecksum(&rom), parsed.header_checksum);
    try std.testing.expectEqual(globalChecksum(&rom), parsed.global_checksum);
    try std.testing.expectEqual(@as(usize, 64), ROM_BANK_COUNT);
    try std.testing.expectEqual(@as(usize, 4), RAM_BANK_COUNT);
}

test "header rejects length and unsupported hardware before checksums" {
    var rom = validRom();
    try std.testing.expectError(
        error.InvalidRomLength,
        Header.parse(rom[0 .. ROM_SIZE - 1]),
    );

    rom[CARTRIDGE_TYPE_OFFSET] = 0x10;
    try std.testing.expectError(
        error.UnsupportedCartridgeType,
        Header.parse(&rom),
    );
    rom[CARTRIDGE_TYPE_OFFSET] = CARTRIDGE_TYPE_MBC3_RAM_BATTERY;

    rom[ROM_SIZE_CODE_OFFSET] = 0x04;
    try std.testing.expectError(error.UnsupportedRomSize, Header.parse(&rom));
    rom[ROM_SIZE_CODE_OFFSET] = ROM_SIZE_CODE_1_MIB;

    rom[RAM_SIZE_CODE_OFFSET] = 0x02;
    try std.testing.expectError(error.UnsupportedRamSize, Header.parse(&rom));
}

test "header and global checksum mutations fail closed independently" {
    var header_mutation = validRom();
    header_mutation[0x134] +%= 1;
    try std.testing.expectError(
        error.HeaderChecksumMismatch,
        Header.parse(&header_mutation),
    );

    var global_mutation = validRom();
    global_mutation[0x200] = 1;
    try std.testing.expectError(
        error.GlobalChecksumMismatch,
        Header.parse(&global_mutation),
    );
}
