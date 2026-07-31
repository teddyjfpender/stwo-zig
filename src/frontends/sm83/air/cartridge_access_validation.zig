//! Host-side cartridge-access metadata validation.

const std = @import("std");
const cartridge = @import("../cartridge/mod.zig");
const runner = @import("../runner/mod.zig");

const mbc3 = cartridge.mbc3;
const memory = runner.cartridge_memory;

pub const JOYPAD_ADDRESS_MASK: u16 = 0xffff;
pub const JOYPAD_ADDRESS_VALUE: u16 = runner.joypad.P1_ADDRESS;
pub const TIMER_ADDRESS_MASK: u16 = 0xfffc;
pub const TIMER_ADDRESS_VALUE: u16 = 0xff04;
pub const PPU_BASE_ADDRESS_MASK: u16 = 0xfff8;
pub const PPU_BASE_ADDRESS_VALUE: u16 = 0xff40;
pub const PPU_WY_ADDRESS_MASK: u16 = 0xffff;
pub const PPU_WY_ADDRESS_VALUE: u16 = runner.ppu_mmio.WY_ADDRESS;

pub fn isValid(access: memory.Access) bool {
    if (access.logical_address <= mbc3.ROM_SWITCHED_END) {
        if (access.action == .read) {
            const target = mbc3.resolveRead(
                access.mapper_before,
                access.logical_address,
            ) catch return false;
            return switch (target) {
                .rom => |offset| access.region == .cartridge_rom and
                    access.physical_offset == offset and
                    std.meta.eql(access.mapper_before, access.mapper_after),
                else => false,
            };
        }
        const next = mbc3.transition(
            access.mapper_before,
            access.logical_address,
            access.value,
        ) catch return false;
        return access.region == .mapper_control and
            access.physical_offset == null and
            std.meta.eql(next, access.mapper_after);
    }
    if (access.logical_address >= mbc3.RAM_START and
        access.logical_address <= mbc3.RAM_END)
    {
        if (access.action == .read) {
            const target = mbc3.resolveRead(
                access.mapper_before,
                access.logical_address,
            ) catch return false;
            return switch (target) {
                .ram => |offset| access.region == .cartridge_ram and
                    access.physical_offset == offset,
                .open_bus => access.region == .cartridge_open_bus and
                    access.physical_offset == null,
                else => false,
            } and std.meta.eql(access.mapper_before, access.mapper_after);
        }
        const target = mbc3.resolveWrite(
            access.mapper_before,
            access.logical_address,
        ) catch return false;
        return switch (target) {
            .ram => |offset| access.region == .cartridge_ram and
                access.physical_offset == offset,
            .ignored => access.region == .cartridge_ram_ignored and
                access.physical_offset == null,
            else => false,
        } and std.meta.eql(access.mapper_before, access.mapper_after);
    }
    if (access.logical_address >= memory.UNUSABLE_START and
        access.logical_address <= memory.UNUSABLE_END)
        return false;
    if (access.logical_address >= memory.ECHO_START and
        access.logical_address <= memory.ECHO_END)
    {
        return access.region == .system_echo and
            access.physical_offset ==
                access.logical_address - memory.ECHO_DELTA and
            std.meta.eql(access.mapper_before, access.mapper_after);
    }
    if (matchesAddress(
        access.logical_address,
        JOYPAD_ADDRESS_MASK,
        JOYPAD_ADDRESS_VALUE,
    ))
        return access.region == .joypad_mmio and
            access.physical_offset == null and
            std.meta.eql(access.mapper_before, access.mapper_after);
    if (matchesAddress(
        access.logical_address,
        TIMER_ADDRESS_MASK,
        TIMER_ADDRESS_VALUE,
    ))
        return access.region == .timer_mmio and
            access.physical_offset == null and
            std.meta.eql(access.mapper_before, access.mapper_after);
    if (isPpuAddress(access.logical_address))
        return access.region == .ppu_mmio and
            access.physical_offset == null and
            std.meta.eql(access.mapper_before, access.mapper_after);
    if (runner.apu_mmio.isAddress(access.logical_address))
        return access.region == .apu_mmio and
            access.physical_offset == null and
            std.meta.eql(access.mapper_before, access.mapper_after);
    return access.region == .system and access.physical_offset == null and
        std.meta.eql(access.mapper_before, access.mapper_after);
}

pub fn matchesAddress(address: u16, mask: u16, value: u16) bool {
    return address & mask == value;
}

pub fn isPpuAddress(address: u16) bool {
    return switch (address) {
        runner.ppu_mmio.LCDC_ADDRESS,
        runner.ppu_mmio.STAT_ADDRESS,
        runner.ppu_mmio.SCY_ADDRESS,
        runner.ppu_mmio.SCX_ADDRESS,
        runner.ppu_mmio.LY_ADDRESS,
        runner.ppu_mmio.LYC_ADDRESS,
        runner.ppu_mmio.WY_ADDRESS,
        => true,
        else => false,
    };
}

pub fn isApuAddress(address: u16) bool {
    return runner.apu_mmio.isAddress(address);
}

pub fn addressMismatch(
    comptime S: type,
    bits: [16]S,
    comptime mask: u16,
    comptime expected: u16,
) S {
    var result = S.zero();
    inline for (0..16) |index| {
        if (mask >> index & 1 == 0) continue;
        result = result.add(
            if (expected >> index & 1 == 1)
                S.one().sub(bits[index])
            else
                bits[index],
        );
    }
    return result;
}

pub fn addressMismatchU16(address: u16, mask: u16, expected: u16) u32 {
    return @popCount((address ^ expected) & mask);
}
