//! Canonical MBC3 cartridge, echo, and unusable address classifiers.

const std = @import("std");
const mbc3 = @import("../cartridge/mbc3.zig");

pub const ECHO_START: u16 = 0xe000;
pub const ECHO_END: u16 = 0xfdff;
pub const ECHO_DELTA: u16 = 0x2000;
pub const UNUSABLE_START: u16 = 0xfea0;
pub const UNUSABLE_END: u16 = 0xfeff;

pub fn isCartridge(address: u16) bool {
    return address <= mbc3.ROM_SWITCHED_END or
        (address >= mbc3.RAM_START and address <= mbc3.RAM_END);
}

pub fn isEcho(address: u16) bool {
    return address >= ECHO_START and address <= ECHO_END;
}

pub fn isUnusable(address: u16) bool {
    return address >= UNUSABLE_START and address <= UNUSABLE_END;
}

pub fn echoTarget(address: u16) u16 {
    std.debug.assert(isEcho(address));
    return address - ECHO_DELTA;
}
