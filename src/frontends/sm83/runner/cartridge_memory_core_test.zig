//! Focused core address-space tests kept separate from the live devices.

const std = @import("std");
const cartridge_mod = @import("../cartridge/mod.zig");
const header = cartridge_mod.header;
const mbc3 = cartridge_mod.mbc3;
const memory_mod = @import("cartridge_memory.zig");
const Memory = memory_mod.Memory;
const PhysicalOffset = memory_mod.PhysicalOffset;
const Region = memory_mod.Region;
const Fixture = @import("cartridge_memory_test_support.zig").Fixture(
    cartridge_mod,
    header,
    Memory,
    memory_mod.SYSTEM_SIZE,
);

test "ROM reads resolve physical banks and control writes never mutate ROM" {
    var fixture = try Fixture.init(std.testing.allocator, 0xff);
    defer fixture.deinit(std.testing.allocator);
    fixture.system[0x4000] = 0xa5;
    const fixed = try fixture.memory.read(0x3fff);
    try std.testing.expectEqual(@as(u8, 0), fixed.value);
    try expectAccess(
        fixed.access,
        0x3fff,
        .read,
        .cartridge_rom,
        0x3fff,
        .{},
        .{},
        0,
    );

    const reset_banked = try fixture.memory.read(0x4000);
    try std.testing.expectEqual(@as(u8, 1), reset_banked.value);
    try std.testing.expectEqual(
        @as(?PhysicalOffset, 0x4000),
        reset_banked.access.physical_offset,
    );

    const bank_write = try fixture.memory.write(0x2000, 2);
    try std.testing.expectEqual(Region.mapper_control, bank_write.region);
    try std.testing.expectEqual(
        @as(?PhysicalOffset, null),
        bank_write.physical_offset,
    );
    try std.testing.expectEqual(
        @as(u7, 0),
        bank_write.mapper_before.rom_bank_register,
    );
    try std.testing.expectEqual(
        @as(u7, 2),
        bank_write.mapper_after.rom_bank_register,
    );
    try std.testing.expectEqual(@as(u8, 2), fixture.memory.data_bus);

    const banked = try fixture.memory.read(0x4000);
    try std.testing.expectEqual(@as(u8, 2), banked.value);
    try std.testing.expectEqual(
        @as(?PhysicalOffset, 0x8000),
        banked.access.physical_offset,
    );
    try std.testing.expectEqual(@as(u8, 2), fixture.rom[0x8000]);
    try std.testing.expectEqual(@as(u8, 0xa5), fixture.system[0x4000]);
}

test "ROM register keeps seven bits then aliases across the 64 physical banks" {
    var fixture = try Fixture.init(std.testing.allocator, 0);
    defer fixture.deinit(std.testing.allocator);

    _ = try fixture.memory.write(0x3fff, 0x40);
    const aliased_zero = try fixture.memory.read(0x4000);
    try std.testing.expectEqual(@as(u8, 0), aliased_zero.value);
    try std.testing.expectEqual(
        @as(?PhysicalOffset, 0),
        aliased_zero.access.physical_offset,
    );

    _ = try fixture.memory.write(0x2000, 0x80);
    const truncated_zero = try fixture.memory.read(0x4000);
    try std.testing.expectEqual(@as(u8, 1), truncated_zero.value);
    try std.testing.expectEqual(
        @as(?PhysicalOffset, header.ROM_BANK_SIZE),
        truncated_zero.access.physical_offset,
    );

    _ = try fixture.memory.write(0x2000, 0xff);
    const last = try fixture.memory.read(0x7fff);
    try std.testing.expectEqual(@as(u8, 63), last.value);
    try std.testing.expectEqual(
        @as(?PhysicalOffset, header.ROM_SIZE - 1),
        last.access.physical_offset,
    );
}

test "disabled SRAM uses the bus latch and ignores storage writes" {
    var fixture = try Fixture.init(std.testing.allocator, 0x5a);
    defer fixture.deinit(std.testing.allocator);
    fixture.sram[0] = 0x33;
    fixture.system[mbc3.RAM_START] = 0x44;

    const open = try fixture.memory.read(mbc3.RAM_START);
    try std.testing.expectEqual(@as(u8, 0x5a), open.value);
    try std.testing.expectEqual(Region.cartridge_open_bus, open.access.region);
    try std.testing.expectEqual(
        @as(?PhysicalOffset, null),
        open.access.physical_offset,
    );

    const ignored = try fixture.memory.write(mbc3.RAM_START, 0x91);
    try std.testing.expectEqual(
        Region.cartridge_ram_ignored,
        ignored.region,
    );
    try std.testing.expectEqual(@as(u8, 0x33), fixture.sram[0]);
    try std.testing.expectEqual(
        @as(u8, 0x44),
        fixture.system[mbc3.RAM_START],
    );
    try std.testing.expectEqual(@as(u8, 0x91), fixture.memory.data_bus);

    const driven_open = try fixture.memory.read(mbc3.RAM_START);
    try std.testing.expectEqual(@as(u8, 0x91), driven_open.value);
}

test "enabled SRAM resolves all four banks and low-two-bit aliases" {
    var fixture = try Fixture.init(std.testing.allocator, 0);
    defer fixture.deinit(std.testing.allocator);
    const enabled = try fixture.memory.write(0x1fff, 0xfa);
    try std.testing.expect(enabled.mapper_after.ram_enabled);

    _ = try fixture.memory.write(0x5fff, 7);
    const write = try fixture.memory.write(mbc3.RAM_END, 0xc7);
    try std.testing.expectEqual(Region.cartridge_ram, write.region);
    try std.testing.expectEqual(
        @as(?PhysicalOffset, header.RAM_SIZE - 1),
        write.physical_offset,
    );
    try std.testing.expectEqual(
        @as(u8, 0xc7),
        fixture.sram[header.RAM_SIZE - 1],
    );

    const read = try fixture.memory.read(mbc3.RAM_END);
    try std.testing.expectEqual(@as(u8, 0xc7), read.value);
    try std.testing.expectEqual(
        write.physical_offset,
        read.access.physical_offset,
    );
    try std.testing.expectEqualDeep(
        write.mapper_after,
        read.access.mapper_before,
    );
    try std.testing.expectEqualDeep(
        read.access.mapper_before,
        read.access.mapper_after,
    );
}

test "system accesses preserve mapper state and expose no cartridge offset" {
    var fixture = try Fixture.init(std.testing.allocator, 0);
    defer fixture.deinit(std.testing.allocator);
    _ = try fixture.memory.write(0x2000, 3);
    const mapper = fixture.memory.mapper;

    const write = try fixture.memory.write(0x8000, 0x81);
    try expectAccess(
        write,
        0x8000,
        .write,
        .system,
        null,
        mapper,
        mapper,
        0x81,
    );
    const read = try fixture.memory.read(0x8000);
    try std.testing.expectEqual(@as(u8, 0x81), read.value);
    try std.testing.expectEqual(Region.system, read.access.region);
    try std.testing.expectEqual(
        @as(?PhysicalOffset, null),
        read.access.physical_offset,
    );
    try std.testing.expectEqualDeep(mapper, fixture.memory.mapper);
}

test "IF CPU reads synthesize high bits while writes store only low five" {
    var fixture = try Fixture.init(std.testing.allocator, 0);
    defer fixture.deinit(std.testing.allocator);

    const clear = try fixture.memory.write(memory_mod.INTERRUPT_FLAGS, 0);
    try std.testing.expectEqual(@as(u8, 0), clear.value);
    try std.testing.expectEqual(
        @as(u8, 0),
        fixture.system[memory_mod.INTERRUPT_FLAGS],
    );
    const cleared = try fixture.memory.read(memory_mod.INTERRUPT_FLAGS);
    try std.testing.expectEqual(@as(u8, 0xe0), cleared.value);
    try std.testing.expectEqual(@as(u8, 0xe0), cleared.access.value);
    try std.testing.expectEqual(@as(u8, 0xe0), fixture.memory.data_bus);

    const set = try fixture.memory.write(
        memory_mod.INTERRUPT_FLAGS,
        0xff,
    );
    try std.testing.expectEqual(@as(u8, 0xff), set.value);
    try std.testing.expectEqual(
        @as(u8, 0x1f),
        fixture.system[memory_mod.INTERRUPT_FLAGS],
    );
    try std.testing.expectEqual(
        @as(u8, 0xff),
        (try fixture.memory.read(memory_mod.INTERRUPT_FLAGS)).value,
    );

    // A corrupted backing byte cannot leak non-hardware high bits.
    fixture.system[memory_mod.INTERRUPT_FLAGS] = 0x40;
    try std.testing.expectEqual(
        @as(u8, 0xe0),
        (try fixture.memory.read(memory_mod.INTERRUPT_FLAGS)).value,
    );
}

test "all RTC-free MBC3 RAM selector bytes alias transactionally" {
    var fixture = try Fixture.init(std.testing.allocator, 0x6d);
    defer fixture.deinit(std.testing.allocator);

    for (0..256) |raw_selector| {
        const value: u8 = @intCast(raw_selector);
        const access = try fixture.memory.write(0x4000, value);
        try std.testing.expectEqual(
            @as(u3, @truncate(value)),
            fixture.memory.mapper.ram_bank_register,
        );
        try std.testing.expectEqual(
            @as(u2, @truncate(value)),
            fixture.memory.mapper.selectedRamBank(),
        );
        try std.testing.expectEqualDeep(
            access.mapper_after,
            fixture.memory.mapper,
        );
        try std.testing.expectEqual(value, fixture.memory.data_bus);
    }
}

test "access sequence carries exact mapper boundaries for later AIR replay" {
    var fixture = try Fixture.init(std.testing.allocator, 0);
    defer fixture.deinit(std.testing.allocator);

    const enable = try fixture.memory.write(0x0000, 0x0a);
    const select_ram = try fixture.memory.write(0x4000, 2);
    const store = try fixture.memory.write(0xa123, 0x55);
    const load = try fixture.memory.read(0xa123);
    const select_rom = try fixture.memory.write(0x2000, 5);
    const fetch = try fixture.memory.read(0x4123);
    const latch = try fixture.memory.write(0x6000, 1);

    try std.testing.expectEqualDeep(enable.mapper_after, select_ram.mapper_before);
    try std.testing.expectEqualDeep(select_ram.mapper_after, store.mapper_before);
    try std.testing.expectEqualDeep(store.mapper_after, load.access.mapper_before);
    try std.testing.expectEqualDeep(load.access.mapper_after, select_rom.mapper_before);
    try std.testing.expectEqualDeep(select_rom.mapper_after, fetch.access.mapper_before);
    try std.testing.expectEqualDeep(fetch.access.mapper_after, latch.mapper_before);
    try std.testing.expectEqualDeep(latch.mapper_before, latch.mapper_after);
    try std.testing.expectEqual(
        @as(?PhysicalOffset, 2 * header.RAM_BANK_SIZE + 0x123),
        store.physical_offset,
    );
    try std.testing.expectEqual(store.physical_offset, load.access.physical_offset);
    try std.testing.expectEqual(
        @as(?PhysicalOffset, 5 * header.ROM_BANK_SIZE + 0x123),
        fetch.access.physical_offset,
    );
    try std.testing.expectEqual(@as(u8, 5), fetch.value);
}

fn expectAccess(
    actual: memory_mod.Access,
    logical_address: u16,
    action: memory_mod.Action,
    region: Region,
    physical_offset: ?PhysicalOffset,
    mapper_before: mbc3.State,
    mapper_after: mbc3.State,
    value: u8,
) !void {
    try std.testing.expectEqual(logical_address, actual.logical_address);
    try std.testing.expectEqual(action, actual.action);
    try std.testing.expectEqual(region, actual.region);
    try std.testing.expectEqual(physical_offset, actual.physical_offset);
    try std.testing.expectEqualDeep(mapper_before, actual.mapper_before);
    try std.testing.expectEqualDeep(mapper_after, actual.mapper_after);
    try std.testing.expectEqual(value, actual.value);
}
