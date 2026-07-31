//! Immutable 32 KiB ROM-only cartridge mapping for hardware conformance ROMs.
//!
//! This is deliberately separate from the Pokémon MBC3 cartridge validator:
//! accepting a published ROM-only test artifact must neither rewrite that ROM
//! nor weaken the production MBC3 header contract.

const std = @import("std");
const address_space = @import("cartridge_address_space.zig");

pub const ROM_SIZE: usize = 32 * 1024;
pub const ROM_END: u16 = 0x7fff;
pub const ECHO_START = address_space.ECHO_START;
pub const ECHO_END = address_space.ECHO_END;
pub const ECHO_DELTA = address_space.ECHO_DELTA;
pub const UNUSABLE_START = address_space.UNUSABLE_START;
pub const UNUSABLE_END = address_space.UNUSABLE_END;

const CARTRIDGE_TYPE: usize = 0x147;
const ROM_SIZE_CODE: usize = 0x148;
const RAM_SIZE_CODE: usize = 0x149;

pub const InstallError = error{
    InvalidRomLength,
    UnsupportedCartridgeType,
    UnsupportedRomSize,
    UnsupportedRamSize,
};

/// Installed mapping marker. ROM bytes are copied into the owning flat-memory
/// image, so this value borrows no caller storage and adds no allocation.
pub const Mapping = struct {
    pub fn install(
        bytes: *[65536]u8,
        rom: []const u8,
    ) InstallError!Mapping {
        if (rom.len != ROM_SIZE) return error.InvalidRomLength;
        if (rom[CARTRIDGE_TYPE] != 0) return error.UnsupportedCartridgeType;
        if (rom[ROM_SIZE_CODE] != 0) return error.UnsupportedRomSize;
        if (rom[RAM_SIZE_CODE] != 0) return error.UnsupportedRamSize;
        @memcpy(bytes[0..ROM_SIZE], rom);
        return .{};
    }

    /// Returns `null` when the ordinary system-memory path owns the address.
    pub fn read(self: Mapping, bytes: *const [65536]u8, address: u16) ?u8 {
        _ = self;
        if (address <= ROM_END) return bytes[address];
        if (address_space.isEcho(address))
            return bytes[address_space.echoTarget(address)];
        if (address_space.isUnusable(address)) return 0xff;
        return null;
    }

    /// Returns whether the cartridge/alias mapping consumed the write.
    pub fn write(
        self: Mapping,
        bytes: *[65536]u8,
        address: u16,
        value: u8,
    ) bool {
        _ = self;
        if (address <= ROM_END or address_space.isUnusable(address))
            return true;
        if (address_space.isEcho(address)) {
            bytes[address_space.echoTarget(address)] = value;
            return true;
        }
        return false;
    }
};

test "ROM-only mapping validates the published header and owns its copy" {
    var bytes = [_]u8{0} ** 65536;
    var rom = [_]u8{0} ** ROM_SIZE;
    rom[0x1234] = 0x56;
    const mapping = try Mapping.install(&bytes, &rom);
    rom[0x1234] = 0xaa;
    try std.testing.expectEqual(@as(?u8, 0x56), mapping.read(&bytes, 0x1234));

    var invalid = rom;
    invalid[CARTRIDGE_TYPE] = 0x13;
    try std.testing.expectError(
        error.UnsupportedCartridgeType,
        Mapping.install(&bytes, &invalid),
    );
    invalid[CARTRIDGE_TYPE] = 0;
    invalid[ROM_SIZE_CODE] = 5;
    try std.testing.expectError(
        error.UnsupportedRomSize,
        Mapping.install(&bytes, &invalid),
    );
    invalid[ROM_SIZE_CODE] = 0;
    invalid[RAM_SIZE_CODE] = 3;
    try std.testing.expectError(
        error.UnsupportedRamSize,
        Mapping.install(&bytes, &invalid),
    );
    try std.testing.expectError(
        error.InvalidRomLength,
        Mapping.install(&bytes, rom[0 .. rom.len - 1]),
    );
}

test "ROM-only writes are immutable and echo and unusable ranges are exact" {
    var bytes = [_]u8{0} ** 65536;
    var rom = [_]u8{0} ** ROM_SIZE;
    rom[0x1234] = 0x56;
    const mapping = try Mapping.install(&bytes, &rom);

    try std.testing.expect(mapping.write(&bytes, 0x1234, 0xaa));
    try std.testing.expectEqual(@as(?u8, 0x56), mapping.read(&bytes, 0x1234));
    try std.testing.expect(mapping.write(&bytes, 0xe123, 0x42));
    try std.testing.expectEqual(@as(u8, 0x42), bytes[0xc123]);
    try std.testing.expectEqual(@as(?u8, 0x42), mapping.read(&bytes, 0xe123));
    try std.testing.expect(mapping.write(&bytes, UNUSABLE_START, 0x11));
    try std.testing.expectEqual(
        @as(?u8, 0xff),
        mapping.read(&bytes, UNUSABLE_END),
    );
    try std.testing.expect(!mapping.write(&bytes, 0xc000, 0x33));
    try std.testing.expectEqual(@as(?u8, null), mapping.read(&bytes, 0xc000));
}
