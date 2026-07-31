const std = @import("std");
const sameboy = @import("sameboy.zig");
const cartridge = @import("../cartridge/mod.zig");
const runner = @import("../runner/mod.zig");

const Fixture = struct {
    rom: []u8,
    checkpoint: []u8,

    fn deinit(self: Fixture, allocator: std.mem.Allocator) void {
        allocator.free(self.checkpoint);
        allocator.free(self.rom);
    }
};

test "strict SameBoy native plus BESS checkpoint imports one canonical state" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);

    var checkpoint = try sameboy.import(
        allocator,
        fixture.checkpoint,
        fixture.rom,
    );
    defer checkpoint.deinit();

    try std.testing.expectEqual(@as(u16, 0x4560), checkpoint.cpu.pc);
    try std.testing.expectEqual(@as(u16, 0xdff0), checkpoint.cpu.sp);
    try std.testing.expectEqual(@as(u16, 0x12b0), checkpoint.cpu.af());
    try std.testing.expect(checkpoint.cpu.ime);
    try std.testing.expect(checkpoint.cpu.ime_enable_pending);
    try std.testing.expect(checkpoint.halt_bug);
    try std.testing.expectEqual(@as(u16, 0x9abc), checkpoint.timer.div_counter);
    try std.testing.expectEqual(
        @import("../runner/timer.zig").ReloadState.reloading,
        checkpoint.timer.reload_state,
    );
    try std.testing.expectEqual(@as(u7, 3), checkpoint.mapper.rom_bank_register);
    try std.testing.expectEqual(@as(u3, 2), checkpoint.mapper.ram_bank_register);
    try std.testing.expect(checkpoint.mapper.ram_enabled);
    try std.testing.expectEqual(@as(u8, 0x44), checkpoint.system[0xc000]);
    try std.testing.expectEqual(@as(u8, 0x44), checkpoint.system[0xe000]);
    try std.testing.expectEqual(@as(u8, 0x55), checkpoint.system[0x8000]);
    try std.testing.expectEqual(@as(u8, 0x66), checkpoint.system[0xfe00]);
    try std.testing.expectEqual(@as(u8, 0x77), checkpoint.system[0xff80]);
    try std.testing.expectEqual(@as(u8, 0x88), checkpoint.sram[0]);

    const timer = try checkpoint.toTimer();
    try std.testing.expectEqual(@as(u16, 0x9abc), timer.div_counter);
    const joypad = try checkpoint.toJoypad(0);
    try std.testing.expectEqual(@as(u8, 0xcf), joypad.readP1());
    const apu = try checkpoint.toApuMmio();
    try std.testing.expect(apu.enabled);
    try std.testing.expectEqual(@as(u8, 0xf0), try apu.read(0xff26));
    try std.testing.expectEqual(@as(u8, 0x37), try apu.read(0xff25));
    const ppu = try checkpoint.toPpuMmio();
    try std.testing.expectEqual(@as(u8, 42), ppu.timing.line);
    try std.testing.expectEqual(
        @as(i32, 232),
        @as(i32, checkpoint.ppu.cycles_for_line) +
            @divTrunc(checkpoint.timer.display_cycles, 2),
    );
    try std.testing.expectEqual(@as(u16, 228), ppu.timing.dot);
    try std.testing.expectEqual(
        checkpoint.system[runner.ppu_mmio.SCY_ADDRESS],
        ppu.scy,
    );
    try std.testing.expectEqual(
        checkpoint.system[runner.ppu_mmio.SCX_ADDRESS],
        ppu.scx,
    );
    try std.testing.expectEqual(
        checkpoint.system[runner.ppu_mmio.WY_ADDRESS],
        ppu.wy,
    );
    const dma = try checkpoint.toDma(123);
    try std.testing.expectEqual(@as(u32, 123), dma.clock);
    try std.testing.expectEqual(@import("../runner/dma.zig").Phase.idle, dma.phase);

    checkpoint.system[0xff05] ^= 1;
    try std.testing.expectError(
        error.TimerImageMismatch,
        checkpoint.toTimer(),
    );
    checkpoint.system[0xff05] ^= 1;
    try std.testing.expectError(
        error.InvalidLineBits,
        checkpoint.toJoypad(1),
    );
    checkpoint.system[0xff41] ^= 1;
    try std.testing.expectError(
        error.PpuImageMismatch,
        checkpoint.toPpuMmio(),
    );
    checkpoint.system[0xff41] ^= 1;
    checkpoint.timer.display_cycles += 1;
    try std.testing.expectError(
        error.UnrepresentablePpuState,
        checkpoint.toPpuMmio(),
    );
    checkpoint.timer.display_cycles -= 1;
    checkpoint.dma.hdma_on = true;
    try std.testing.expectError(
        error.UnrepresentableDmaState,
        checkpoint.toDma(123),
    );
}

test "checkpoint parser rejects native header section and hidden-state mutations" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);

    const Mutation = struct {
        offset: usize,
        value: u8,
        expected: sameboy.ImportError,
    };
    const mutations = [_]Mutation{
        .{
            .offset = 0,
            .value = 0,
            .expected = error.InvalidNativeMagic,
        },
        .{
            .offset = 4,
            .value = 14,
            .expected = error.UnsupportedNativeVersion,
        },
        .{
            .offset = 8,
            .value = 151,
            .expected = error.InvalidNativeSectionSize,
        },
        .{
            .offset = 12,
            .value = 0xbf,
            .expected = error.InvalidNativeCpu,
        },
        .{
            .offset = 12 + 25,
            .value = 2,
            .expected = error.InvalidNativeBoolean,
        },
        .{
            .offset = 556 + 18,
            .value = 3,
            .expected = error.InvalidNativeTimer,
        },
        .{
            .offset = 624,
            .value = 2,
            .expected = error.InvalidNativeBoolean,
        },
        .{
            .offset = 624 + 92,
            .value = 3,
            .expected = error.InvalidNativeBoolean,
        },
        .{
            .offset = 168 + 8,
            .value = 0xa2,
            .expected = error.InvalidNativeDma,
        },
        .{
            .offset = 768 + 301,
            .value = 154,
            .expected = error.InvalidNativePpu,
        },
    };
    for (mutations) |mutation| {
        const original = fixture.checkpoint[mutation.offset];
        fixture.checkpoint[mutation.offset] = mutation.value;
        try std.testing.expectError(
            mutation.expected,
            sameboy.import(allocator, fixture.checkpoint, fixture.rom),
        );
        fixture.checkpoint[mutation.offset] = original;
    }

    try std.testing.expectError(
        error.InvalidCheckpointSize,
        sameboy.import(
            allocator,
            fixture.checkpoint[0 .. fixture.checkpoint.len - 1],
            fixture.rom,
        ),
    );
    try std.testing.expectError(
        error.InvalidCheckpointSize,
        sameboy.import(
            allocator,
            fixture.checkpoint[sameboy.BESS_OFFSET..],
            fixture.rom,
        ),
    );
}

test "checkpoint parser rejects BESS structure buffer and overlap mutations" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);

    const name_offset = sameboy.BESS_OFFSET;
    const info_offset = name_offset + 8 + 14;
    const core_offset = info_offset + 8 + 18;
    const core_payload = core_offset + 8;
    const xoam_offset = core_payload + 0xd0;
    const mbc_offset = xoam_offset + 8 + 0x60;

    fixture.checkpoint[info_offset..][0..4].* = "NAME".*;
    try std.testing.expectError(
        error.DuplicateBessBlock,
        sameboy.import(allocator, fixture.checkpoint, fixture.rom),
    );
    fixture.checkpoint[info_offset..][0..4].* = "INFO".*;

    fixture.checkpoint[info_offset..][0..4].* = "FAIL".*;
    try std.testing.expectError(
        error.UnknownBessBlock,
        sameboy.import(allocator, fixture.checkpoint, fixture.rom),
    );
    fixture.checkpoint[info_offset..][0..4].* = "INFO".*;

    fixture.checkpoint[core_payload + 152] = 0xff;
    try std.testing.expectError(
        error.InvalidBessBuffer,
        sameboy.import(allocator, fixture.checkpoint, fixture.rom),
    );
    fixture.checkpoint[core_payload + 152] = 0x00;

    fixture.checkpoint[core_payload + 8] ^= 1;
    try std.testing.expectError(
        error.NativeBessCpuMismatch,
        sameboy.import(allocator, fixture.checkpoint, fixture.rom),
    );
    fixture.checkpoint[core_payload + 8] ^= 1;

    fixture.checkpoint[core_payload + 24 + 0x0f] ^= 1;
    try std.testing.expectError(
        error.NativeBessIoMismatch,
        sameboy.import(allocator, fixture.checkpoint, fixture.rom),
    );
    fixture.checkpoint[core_payload + 24 + 0x0f] ^= 1;

    fixture.checkpoint[mbc_offset + 8 + 5] ^= 1;
    try std.testing.expectError(
        error.NativeBessMapperMismatch,
        sameboy.import(allocator, fixture.checkpoint, fixture.rom),
    );
    fixture.checkpoint[mbc_offset + 8 + 5] ^= 1;

    fixture.checkpoint[fixture.checkpoint.len - 1] = 0;
    try std.testing.expectError(
        error.MissingBessFooter,
        sameboy.import(allocator, fixture.checkpoint, fixture.rom),
    );
}

test "checkpoint parser binds BESS INFO to the exact validated ROM" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);

    const info_payload = sameboy.BESS_OFFSET + 8 + 14 + 8;
    fixture.checkpoint[info_payload] ^= 1;
    try std.testing.expectError(
        error.RomIdentityMismatch,
        sameboy.import(allocator, fixture.checkpoint, fixture.rom),
    );
}

test "checkpoint mapper imports all RTC-free SameBoy bank aliases" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);

    const native_mbc_offset = 8 + (4 + 152) + (4 + 24) + 4;
    const bess_mbc_offset = sameboy.BESS_OFFSET +
        (8 + 14) + (8 + 18) + (8 + 0xd0) + (8 + 0x60) + 8;
    const native_mbc = fixture.checkpoint[native_mbc_offset..][0..96];
    const bess_mbc = fixture.checkpoint[bess_mbc_offset..][0..9];

    for (0x40..0x80) |raw_bank| {
        writeU16(native_mbc, 0, @intCast(raw_bank));
        native_mbc[14] = @intCast(raw_bank);
        bess_mbc[5] = @intCast(raw_bank);
        var checkpoint = try sameboy.import(
            allocator,
            fixture.checkpoint,
            fixture.rom,
        );
        defer checkpoint.deinit();
        try std.testing.expectEqual(
            @as(u7, @intCast(raw_bank)),
            checkpoint.mapper.rom_bank_register,
        );
        try std.testing.expectEqual(
            @as(u6, @truncate(raw_bank)),
            checkpoint.mapper.selectedRomBank(),
        );
    }

    writeU16(native_mbc, 0, 3);
    native_mbc[14] = 3;
    bess_mbc[5] = 3;
    for (0..256) |raw_selector| {
        const packed_selector: u8 = @intCast(raw_selector & 0x0f);
        native_mbc[4] = packed_selector & 0x07;
        native_mbc[15] = packed_selector;
        bess_mbc[8] = packed_selector;
        var checkpoint = try sameboy.import(
            allocator,
            fixture.checkpoint,
            fixture.rom,
        );
        defer checkpoint.deinit();
        try std.testing.expectEqual(
            @as(u3, @truncate(raw_selector)),
            checkpoint.mapper.ram_bank_register,
        );
        try std.testing.expectEqual(
            @as(u2, @truncate(raw_selector)),
            checkpoint.mapper.selectedRamBank(),
        );
    }

    writeU16(native_mbc, 0, 0x80);
    native_mbc[14] = 0x80;
    bess_mbc[5] = 0x80;
    try std.testing.expectError(
        error.InvalidMbc3State,
        sameboy.import(allocator, fixture.checkpoint, fixture.rom),
    );
}

test "pinned SameBoy APU projection binds native status and phase" {
    const corpus_root = std.posix.getenv("SM83_POKEMON_CORPUS") orelse
        return error.SkipZigTest;
    var directory = try std.fs.cwd().openDir(corpus_root, .{});
    defer directory.close();
    const allocator = std.testing.allocator;
    const rom = try directory.readFileAlloc(
        allocator,
        "pokered_rogue_e2e.gbc",
        cartridge.header.ROM_SIZE,
    );
    defer allocator.free(rom);
    const bytes = try directory.readFileAlloc(
        allocator,
        "build/traces/battle-seed-1/boundary-000000.s1",
        sameboy.CHECKPOINT_SIZE,
    );
    defer allocator.free(bytes);
    var checkpoint = try sameboy.import(allocator, bytes, rom);
    defer checkpoint.deinit();

    const apu = try checkpoint.toApuMmio();
    try std.testing.expectEqual(
        checkpoint.system[0xff25],
        try apu.read(0xff25),
    );
    try std.testing.expectEqual(
        expectedNr52(checkpoint.apu.raw),
        try apu.read(0xff26),
    );

    const saved_global_enable = checkpoint.apu.raw[0];
    checkpoint.apu.raw[0] = 2;
    try std.testing.expectError(error.InvalidState, checkpoint.toApuMmio());
    checkpoint.apu.raw[0] = saved_global_enable;
    checkpoint.apu.raw[70] = 2;
    try std.testing.expectError(error.InvalidState, checkpoint.toApuMmio());
}

fn makeFixture(allocator: std.mem.Allocator) !Fixture {
    const rom = try allocator.alloc(u8, cartridge.header.ROM_SIZE);
    errdefer allocator.free(rom);
    @memset(rom, 0);
    @memcpy(rom[0x134..0x144], "SYNTHETIC STATE\x00");
    rom[cartridge.header.CARTRIDGE_TYPE_OFFSET] =
        cartridge.header.CARTRIDGE_TYPE_MBC3_RAM_BATTERY;
    rom[cartridge.header.ROM_SIZE_CODE_OFFSET] =
        cartridge.header.ROM_SIZE_CODE_1_MIB;
    rom[cartridge.header.RAM_SIZE_CODE_OFFSET] =
        cartridge.header.RAM_SIZE_CODE_32_KIB;
    rom[cartridge.header.HEADER_CHECKSUM_OFFSET] =
        cartridge.header.headerChecksum(
            @ptrCast(rom.ptr),
        );
    const global_checksum = cartridge.header.globalChecksum(
        @ptrCast(rom.ptr),
    );
    std.mem.writeInt(
        u16,
        rom[cartridge.header.GLOBAL_CHECKSUM_OFFSET..][0..2],
        global_checksum,
        .big,
    );

    const bytes = try allocator.alloc(u8, sameboy.CHECKPOINT_SIZE);
    errdefer allocator.free(bytes);
    @memset(bytes, 0);
    writeU32(bytes, 0, 0x53414d45);
    writeU32(bytes, 4, sameboy.NATIVE_STRUCT_VERSION);

    const section_sizes = [_]usize{
        152, 24, 96, 256, 64, 104, 32, 464, 32_680,
    };
    var cursor: usize = 8;
    var starts: [section_sizes.len]usize = undefined;
    for (section_sizes, 0..) |size, index| {
        writeU32(bytes, cursor, @intCast(size));
        cursor += 4;
        starts[index] = cursor;
        cursor += size;
    }
    try std.testing.expectEqual(sameboy.SRAM_OFFSET, cursor);
    @memset(bytes[cursor .. cursor + cartridge.header.RAM_SIZE], 0x88);
    cursor += cartridge.header.RAM_SIZE;
    @memset(bytes[cursor .. cursor + 0x2000], 0x44);
    cursor += 0x2000;
    @memset(bytes[cursor .. cursor + 0x2000], 0x55);
    cursor += 0x2000;
    try std.testing.expectEqual(sameboy.BESS_OFFSET, cursor);

    const core = bytes[starts[0] .. starts[0] + section_sizes[0]];
    writeU16(core, 0, 0x12b0);
    writeU16(core, 2, 0x3456);
    writeU16(core, 4, 0x789a);
    writeU16(core, 6, 0xbcde);
    writeU16(core, 8, 0xdff0);
    writeU16(core, 10, 0x4560);
    core[12] = 1;
    core[13] = 0x05;
    core[14] = 1;
    writeU32(core, 16, 0x002);
    core[24] = 1;
    core[25] = 1;
    core[26] = 1;
    writeU32(core, 128, 0x2000);
    writeU16(core, 138, 0xabcd);
    core[140] = 0x5a;

    const dma = bytes[starts[1] .. starts[1] + section_sizes[1]];
    dma[8] = 0xa1;
    const mbc = bytes[starts[2] .. starts[2] + section_sizes[2]];
    writeU16(mbc, 0, 3);
    mbc[4] = 2;
    writeU32(mbc, 8, cartridge.header.RAM_SIZE);
    mbc[12] = 1;
    mbc[14] = 3;
    mbc[15] = 2;

    const hram = bytes[starts[3] .. starts[3] + section_sizes[3]];
    @memset(hram[0..0x7f], 0x77);
    const io = hram[0x7f .. 0x7f + 0x80];
    io[0x00] = 0xcf;
    io[0x05] = 0x22;
    io[0x06] = 0x33;
    io[0x07] = 0x05;
    io[0x0f] = 0x04;
    io[0x40] = 0x91;
    io[0x41] = 0x83;
    io[0x44] = 42;
    io[0x50] = 1;

    const timing = bytes[starts[4] .. starts[4] + section_sizes[4]];
    writeI32(timing, 0, 286);
    writeI32(timing, 4, 2);
    writeI32(timing, 8, -4);
    writeI32(timing, 12, 1);
    writeU16(timing, 16, 0x9abc);
    timing[18] = 1;
    timing[46] = 8;
    timing[47] = 3;

    const apu = bytes[starts[5] .. starts[5] + section_sizes[5]];
    apu[0] = 1;
    io[0x24] = 0x77;
    io[0x25] = 0x37;

    const video = bytes[starts[7] .. starts[7] + section_sizes[7]];
    writeU32(video, 0, 0x2000);
    @memset(video[5 .. 5 + 0xa0], 0x66);
    video[293] = 20;
    video[301] = 42;
    writeU16(video, 302, 42);
    writeU16(video, 374, 89);
    video[422] = 3;
    video[425] = 42;
    video[436] = 80;
    writeU32(video, 452, 1234);

    cursor = sameboy.BESS_OFFSET;
    cursor = writeBlock(bytes, cursor, "NAME", "SameBoy v1.0.3");
    var info: [0x12]u8 = undefined;
    @memcpy(info[0..0x10], rom[0x134..0x144]);
    @memcpy(info[0x10..0x12], rom[0x14e..0x150]);
    cursor = writeBlock(bytes, cursor, "INFO", &info);

    var bess_core = [_]u8{0} ** 0xd0;
    writeU16(&bess_core, 0, 1);
    writeU16(&bess_core, 2, 1);
    @memcpy(bess_core[4..8], "GDB ");
    writeU16(&bess_core, 8, 0x4560);
    writeU16(&bess_core, 10, 0x12b0);
    writeU16(&bess_core, 12, 0x3456);
    writeU16(&bess_core, 14, 0x789a);
    writeU16(&bess_core, 16, 0xbcde);
    writeU16(&bess_core, 18, 0xdff0);
    bess_core[20] = 1;
    bess_core[21] = 0x05;
    @memcpy(bess_core[24 .. 24 + 0x80], io);
    bess_core[24 + 0x04] = 0x9a;
    writeDescriptor(&bess_core, 152, 0x2000, sameboy.WRAM_OFFSET);
    writeDescriptor(&bess_core, 160, 0x2000, sameboy.VRAM_OFFSET);
    writeDescriptor(
        &bess_core,
        168,
        cartridge.header.RAM_SIZE,
        sameboy.SRAM_OFFSET,
    );
    writeDescriptor(&bess_core, 176, 0xa0, 773);
    writeDescriptor(&bess_core, 184, 0x7f, 296);
    cursor = writeBlock(bytes, cursor, "CORE", &bess_core);
    const xoam = [_]u8{0} ** 0x60;
    cursor = writeBlock(bytes, cursor, "XOAM", &xoam);
    const mbc_pairs = [_]u8{
        0x00, 0x00, 0x0a,
        0x00, 0x20, 0x03,
        0x00, 0x40, 0x02,
    };
    cursor = writeBlock(bytes, cursor, "MBC ", &mbc_pairs);
    cursor = writeBlock(bytes, cursor, "END ", &.{});
    writeU32(bytes, cursor, sameboy.BESS_OFFSET);
    @memcpy(bytes[cursor + 4 .. cursor + 8], "BESS");
    cursor += 8;
    try std.testing.expectEqual(bytes.len, cursor);
    return .{ .rom = rom, .checkpoint = bytes };
}

fn writeBlock(
    bytes: []u8,
    offset: usize,
    magic: *const [4]u8,
    payload: []const u8,
) usize {
    @memcpy(bytes[offset .. offset + 4], magic);
    writeU32(bytes, offset + 4, @intCast(payload.len));
    @memcpy(bytes[offset + 8 .. offset + 8 + payload.len], payload);
    return offset + 8 + payload.len;
}

fn writeDescriptor(
    bytes: []u8,
    offset: usize,
    size: usize,
    file_offset: usize,
) void {
    writeU32(bytes, offset, @intCast(size));
    writeU32(bytes, offset + 4, @intCast(file_offset));
}

fn writeU16(bytes: []u8, offset: usize, value: u16) void {
    std.mem.writeInt(u16, bytes[offset..][0..2], value, .little);
}

fn writeU32(bytes: []u8, offset: usize, value: u32) void {
    std.mem.writeInt(u32, bytes[offset..][0..4], value, .little);
}

fn writeI32(bytes: []u8, offset: usize, value: i32) void {
    std.mem.writeInt(i32, bytes[offset..][0..4], value, .little);
}

fn expectedNr52(native: [104]u8) u8 {
    var status: u4 = 0;
    for (0..4) |channel|
        status |= @as(u4, @intFromBool(native[8 + channel] != 0)) <<
            @intCast(channel);
    return 0x70 | (@as(u8, @intFromBool(native[0] != 0)) << 7) |
        @as(u8, status);
}
