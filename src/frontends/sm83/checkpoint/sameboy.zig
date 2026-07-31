//! Fail-closed SameBoy native-state plus BESS checkpoint ingestion.
//!
//! Authority:
//! - SameBoy commit `213a12ce93d66b105a113debd9396306066a7cfc`
//! - `Core/gb.h`, `Core/save_state.c`, and `BESS.md` at that revision
//!
//! BESS 1.0 is deliberately insufficient on its own for a proof checkpoint:
//! it omits the divider low byte, timer reload phase, delayed IME and HALT-bug
//! latches, in-flight DMA, and exact PPU timing. This importer therefore
//! accepts only the pinned little-endian SameBoy native layout (structure
//! version 15) followed by its BESS 1.1 appendix. Overlapping native and BESS
//! fields are cross-checked. Generic BESS and best-effort restoration are
//! rejected.

const std = @import("std");
const cartridge = @import("../cartridge/mod.zig");
const runner = @import("../runner/mod.zig");
const apu_mmio = @import("../runner/apu_mmio.zig");
const projection = @import("projection.zig");

pub const SAMEBOY_COMMIT =
    "213a12ce93d66b105a113debd9396306066a7cfc";
pub const SAMEBOY_VERSION = "1.0.3";
pub const NATIVE_STRUCT_VERSION: u32 = 15;
pub const CHECKPOINT_SIZE: usize = 83_469;
pub const BESS_OFFSET: usize = 83_068;
pub const SRAM_OFFSET: usize = 33_916;
pub const WRAM_OFFSET: usize = 66_684;
pub const VRAM_OFFSET: usize = 74_876;

const NATIVE_MAGIC: u32 = 0x53414d45;
const NATIVE_HEADER_SIZE: usize = 8;
const WRAM_SIZE: usize = 0x2000;
const VRAM_SIZE: usize = 0x2000;
const OAM_SIZE: usize = 0xa0;
const HRAM_SIZE: usize = 0x7f;
const IO_SIZE: usize = 0x80;
const XOAM_SIZE: usize = 0x60;
const BESS_CORE_SIZE: usize = 0xd0;
const BESS_INFO_SIZE: usize = 0x12;
const BESS_MBC3_SIZE: usize = 9;

const IO_DIV: usize = 0x04;
const IO_TIMA: usize = 0x05;
const IO_TMA: usize = 0x06;
const IO_TAC: usize = 0x07;
const IO_IF: usize = 0x0f;
const IO_LCDC: usize = 0x40;
const IO_KEY1: usize = 0x4d;
const IO_BANK: usize = 0x50;

const SectionSpec = struct {
    name: []const u8,
    size: usize,
};

const native_sections = [_]SectionSpec{
    .{ .name = "core_state", .size = 152 },
    .{ .name = "dma", .size = 24 },
    .{ .name = "mbc", .size = 96 },
    .{ .name = "hram", .size = 256 },
    .{ .name = "timing", .size = 64 },
    .{ .name = "apu", .size = 104 },
    .{ .name = "rtc", .size = 32 },
    .{ .name = "video", .size = 464 },
    .{ .name = "accessory", .size = 32_680 },
};

pub const ImportError =
    std.mem.Allocator.Error ||
    cartridge.header.ValidationError ||
    error{
        InvalidCheckpointSize,
        InvalidNativeMagic,
        UnsupportedNativeVersion,
        InvalidNativeSectionSize,
        InvalidNativeSectionLayout,
        InvalidNativeBoolean,
        InvalidNativeCpu,
        InvalidNativeModel,
        InvalidNativeMemoryShape,
        InvalidNativeTimer,
        InvalidNativeDma,
        InvalidNativePpu,
        MissingBessFooter,
        InvalidBessOffset,
        TruncatedBessBlock,
        DuplicateBessBlock,
        UnexpectedBessBlock,
        UnknownBessBlock,
        InvalidBessBlockSize,
        MissingBessBlock,
        TrailingBessData,
        UnsupportedBessVersion,
        UnsupportedBessModel,
        InvalidBessBuffer,
        RomIdentityMismatch,
        NativeBessCpuMismatch,
        NativeBessIoMismatch,
        NativeBessMemoryMismatch,
        InvalidMbc3State,
        NativeBessMapperMismatch,
    };

pub const ProjectionError = projection.Error;
pub const TimerState = projection.TimerState;
pub const DmaState = projection.DmaState;
pub const ApuState = projection.ApuState;
pub const PpuState = projection.PpuState;

pub const Checkpoint = struct {
    allocator: std.mem.Allocator,
    cpu: runner.Cpu,
    interrupt_enable: u8,
    interrupt_flags: u8,
    halt_bug: bool,
    just_halted: bool,
    address_bus: u16,
    data_bus: u8,
    mapper: cartridge.mbc3.State,
    timer: TimerState,
    dma: DmaState,
    apu: ApuState,
    ppu: PpuState,
    /// Canonical cartridge-machine backing image. Cartridge ROM/RAM windows
    /// remain zero because they are owned by the separate ROM and SRAM inputs.
    system: *[runner.cartridge_memory.SYSTEM_SIZE]u8,
    sram: *[cartridge.header.RAM_SIZE]u8,

    pub fn deinit(self: *Checkpoint) void {
        self.allocator.destroy(self.system);
        self.allocator.destroy(self.sram);
        self.* = undefined;
    }

    /// Projects the native timer into the runner's complete timer boundary.
    /// The raw IO backing is checked explicitly so a caller cannot start from
    /// a parsed device state that disagrees with committed system memory.
    pub fn toTimer(self: *const Checkpoint) ProjectionError!runner.timer.Timer {
        return projection.toTimer(self.timer, self.system);
    }

    /// SameBoy does not serialize host key state. The caller must supply the
    /// committed pressed-key mask; it is accepted only when it reproduces the
    /// saved internal P1 lines exactly.
    pub fn toJoypad(
        self: *const Checkpoint,
        pressed: u8,
    ) ProjectionError!runner.joypad.State {
        return projection.toJoypad(self.timer, self.system, pressed);
    }

    /// Projects the exact CPU-visible APU latches from SameBoy's retained
    /// native state. Status and wave RAM phase are never reconstructed from
    /// IO bytes alone.
    pub fn toApuMmio(
        self: *const Checkpoint,
    ) ProjectionError!apu_mmio.State {
        return projection.toApuMmio(self.apu, self.system);
    }

    /// Projects only checkpoints whose exact SameBoy position agrees with the
    /// frontend's fixed-line PPU model. Rendering/FIFO state is retained in
    /// `ppu.raw`, but it is never silently approximated here.
    pub fn toPpuMmio(
        self: *const Checkpoint,
    ) ProjectionError!runner.ppu_mmio.State {
        return projection.toPpuMmio(
            self.timer,
            self.ppu,
            self.system,
            self.interrupt_flags,
        );
    }

    /// The save state has no absolute proof clock, so callers provide it.
    /// In-flight SameBoy DMA is accepted only at a phase represented exactly
    /// by the current M-cycle model; otherwise restoration fails closed.
    pub fn toDma(
        self: *const Checkpoint,
        initial_mcycle: u32,
    ) ProjectionError!runner.dma.State {
        return projection.toDma(self.dma, self.system, initial_mcycle);
    }
};

const NativeViews = struct {
    core: []const u8,
    dma: []const u8,
    mbc: []const u8,
    hram: []const u8,
    timing: []const u8,
    apu: []const u8,
    video: []const u8,
    sram: []const u8,
    wram: []const u8,
    vram: []const u8,
};

const BessViews = struct {
    info: []const u8,
    core: []const u8,
    xoam: []const u8,
    mbc: []const u8,
};

pub fn import(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    rom: []const u8,
) ImportError!Checkpoint {
    _ = try cartridge.Cartridge.init(rom);
    const native = try parseNative(bytes);
    const bess = try parseBess(bytes);
    try validateNative(native);
    try validateBess(bytes, rom, native, bess);

    const cpu = try parseCpu(native.core);
    const mapper = try parseMapper(native.mbc, bess.mbc);
    const timer = try parseTimer(native.timing, native.hram);
    const dma = try parseDma(native.dma);
    const apu = try parseApu(native.apu);
    const ppu = try parsePpu(native.video);

    const system =
        try allocator.create([runner.cartridge_memory.SYSTEM_SIZE]u8);
    errdefer allocator.destroy(system);
    const sram = try allocator.create([cartridge.header.RAM_SIZE]u8);
    errdefer allocator.destroy(sram);
    @memset(system, 0);
    @memcpy(sram, native.sram);

    @memcpy(system[0x8000..0xa000], native.vram);
    @memcpy(system[0xc000..0xe000], native.wram);
    @memcpy(system[0xe000..0xfe00], native.wram[0..0x1e00]);
    @memcpy(system[0xfe00..0xfea0], native.video[5 .. 5 + OAM_SIZE]);
    @memcpy(
        system[0xff00..0xff80],
        native.hram[HRAM_SIZE .. HRAM_SIZE + IO_SIZE],
    );
    @memcpy(system[0xff80..0xffff], native.hram[0..HRAM_SIZE]);
    system[0xff04] = @truncate(timer.div_counter >> 8);
    system[0xffff] = native.core[13];

    return .{
        .allocator = allocator,
        .cpu = cpu,
        .interrupt_enable = native.core[13],
        .interrupt_flags = native.hram[HRAM_SIZE + IO_IF],
        .halt_bug = try readBool(native.core, 26),
        .just_halted = try readBool(native.core, 27),
        .address_bus = readU16(native.core, 138),
        .data_bus = native.core[140],
        .mapper = mapper,
        .timer = timer,
        .dma = dma,
        .apu = apu,
        .ppu = ppu,
        .system = system,
        .sram = sram,
    };
}

fn parseNative(bytes: []const u8) ImportError!NativeViews {
    if (bytes.len != CHECKPOINT_SIZE)
        return error.InvalidCheckpointSize;
    if (readU32(bytes, 0) != NATIVE_MAGIC)
        return error.InvalidNativeMagic;
    if (readU32(bytes, 4) != NATIVE_STRUCT_VERSION)
        return error.UnsupportedNativeVersion;

    var cursor: usize = NATIVE_HEADER_SIZE;
    var sections: [native_sections.len][]const u8 = undefined;
    for (native_sections, 0..) |spec, index| {
        if (cursor + 4 > BESS_OFFSET)
            return error.InvalidNativeSectionLayout;
        const encoded_size: usize = @intCast(readU32(bytes, cursor));
        cursor += 4;
        if (encoded_size != spec.size)
            return error.InvalidNativeSectionSize;
        if (cursor + encoded_size > BESS_OFFSET)
            return error.InvalidNativeSectionLayout;
        sections[index] = bytes[cursor .. cursor + encoded_size];
        cursor += encoded_size;
    }
    if (cursor != SRAM_OFFSET)
        return error.InvalidNativeSectionLayout;
    const sram = bytes[cursor .. cursor + cartridge.header.RAM_SIZE];
    cursor += cartridge.header.RAM_SIZE;
    if (cursor != WRAM_OFFSET)
        return error.InvalidNativeSectionLayout;
    const wram = bytes[cursor .. cursor + WRAM_SIZE];
    cursor += WRAM_SIZE;
    if (cursor != VRAM_OFFSET)
        return error.InvalidNativeSectionLayout;
    const vram = bytes[cursor .. cursor + VRAM_SIZE];
    cursor += VRAM_SIZE;
    if (cursor != BESS_OFFSET)
        return error.InvalidNativeSectionLayout;

    return .{
        .core = sections[0],
        .dma = sections[1],
        .mbc = sections[2],
        .hram = sections[3],
        .timing = sections[4],
        .apu = sections[5],
        .video = sections[7],
        .sram = sram,
        .wram = wram,
        .vram = vram,
    };
}

const BessStage = enum {
    name,
    info,
    core,
    xoam,
    mbc,
    end,
    done,
};

fn parseBess(bytes: []const u8) ImportError!BessViews {
    const footer = bytes[bytes.len - 8 ..];
    if (!std.mem.eql(u8, footer[4..8], "BESS"))
        return error.MissingBessFooter;
    if (readU32(footer, 0) != BESS_OFFSET)
        return error.InvalidBessOffset;

    var stage: BessStage = .name;
    var cursor: usize = BESS_OFFSET;
    const footer_offset = bytes.len - 8;
    var info: ?[]const u8 = null;
    var core: ?[]const u8 = null;
    var xoam: ?[]const u8 = null;
    var mbc: ?[]const u8 = null;
    var seen_name = false;
    var seen_info = false;
    var seen_core = false;
    var seen_xoam = false;
    var seen_mbc = false;
    var seen_end = false;

    while (cursor < footer_offset) {
        if (cursor + 8 > footer_offset)
            return error.TruncatedBessBlock;
        const magic = bytes[cursor .. cursor + 4];
        const size: usize = @intCast(readU32(bytes, cursor + 4));
        cursor += 8;
        if (size > footer_offset - cursor)
            return error.TruncatedBessBlock;
        const payload = bytes[cursor .. cursor + size];
        cursor += size;

        if (std.mem.eql(u8, magic, "NAME")) {
            if (seen_name) return error.DuplicateBessBlock;
            if (stage != .name) return error.UnexpectedBessBlock;
            seen_name = true;
            if (!std.mem.eql(u8, payload, "SameBoy v" ++ SAMEBOY_VERSION))
                return error.InvalidBessBlockSize;
            stage = .info;
        } else if (std.mem.eql(u8, magic, "INFO")) {
            if (seen_info) return error.DuplicateBessBlock;
            if (stage != .info) return error.UnexpectedBessBlock;
            seen_info = true;
            if (size != BESS_INFO_SIZE)
                return error.InvalidBessBlockSize;
            info = payload;
            stage = .core;
        } else if (std.mem.eql(u8, magic, "CORE")) {
            if (seen_core) return error.DuplicateBessBlock;
            if (stage != .core) return error.UnexpectedBessBlock;
            seen_core = true;
            if (size != BESS_CORE_SIZE)
                return error.InvalidBessBlockSize;
            core = payload;
            stage = .xoam;
        } else if (std.mem.eql(u8, magic, "XOAM")) {
            if (seen_xoam) return error.DuplicateBessBlock;
            if (stage != .xoam) return error.UnexpectedBessBlock;
            seen_xoam = true;
            if (size != XOAM_SIZE)
                return error.InvalidBessBlockSize;
            xoam = payload;
            stage = .mbc;
        } else if (std.mem.eql(u8, magic, "MBC ")) {
            if (seen_mbc) return error.DuplicateBessBlock;
            if (stage != .mbc) return error.UnexpectedBessBlock;
            seen_mbc = true;
            if (size != BESS_MBC3_SIZE)
                return error.InvalidBessBlockSize;
            mbc = payload;
            stage = .end;
        } else if (std.mem.eql(u8, magic, "END ")) {
            if (seen_end) return error.DuplicateBessBlock;
            if (stage != .end) return error.UnexpectedBessBlock;
            seen_end = true;
            if (size != 0) return error.InvalidBessBlockSize;
            stage = .done;
            if (cursor != footer_offset)
                return error.TrailingBessData;
            break;
        } else {
            return error.UnknownBessBlock;
        }
    }
    if (stage != .done or
        !seen_name or !seen_info or !seen_core or
        !seen_xoam or !seen_mbc or !seen_end)
    {
        return error.MissingBessBlock;
    }
    return .{
        .info = info.?,
        .core = core.?,
        .xoam = xoam.?,
        .mbc = mbc.?,
    };
}

fn validateNative(native: NativeViews) ImportError!void {
    if (readU32(native.core, 16) != 0x002 or
        try readBool(native.core, 20) or
        try readBool(native.core, 21))
    {
        return error.InvalidNativeModel;
    }
    _ = try readBool(native.core, 22);
    _ = try readBool(native.core, 23);
    if (!try readBool(native.core, 24))
        return error.InvalidNativeModel;
    _ = try readBool(native.core, 25);
    _ = try readBool(native.core, 26);
    _ = try readBool(native.core, 27);
    if (readU32(native.core, 128) != WRAM_SIZE)
        return error.InvalidNativeMemoryShape;
    if (native.core[0] & 0x0f != 0)
        return error.InvalidNativeCpu;

    for ([_]usize{ 0, 1, 15, 18, 19 }) |offset|
        _ = try readBool(native.dma, offset);
    if (native.dma[8] > 0xa1)
        return error.InvalidNativeDma;

    if (readU32(native.mbc, 8) != cartridge.header.RAM_SIZE)
        return error.InvalidNativeMemoryShape;
    _ = try readBool(native.mbc, 12);
    if (readU32(native.video, 0) != VRAM_SIZE or
        try readBool(native.video, 4))
    {
        return error.InvalidNativeMemoryShape;
    }
    for ([_]usize{ 294, 297, 298, 299, 300, 423, 427, 428 }) |offset|
        _ = try readBool(native.video, offset);
    if (native.video[301] >= 154 or
        native.video[425] >= 154 or
        native.video[422] > 3)
    {
        return error.InvalidNativePpu;
    }
    if (native.timing[18] > 2 or native.timing[46] > 48)
        return error.InvalidNativeTimer;
}

fn validateBess(
    bytes: []const u8,
    rom: []const u8,
    native: NativeViews,
    bess: BessViews,
) ImportError!void {
    if (!std.mem.eql(u8, bess.info[0..0x10], rom[0x134..0x144]) or
        !std.mem.eql(u8, bess.info[0x10..0x12], rom[0x14e..0x150]))
    {
        return error.RomIdentityMismatch;
    }
    if (readU16(bess.core, 0) != 1 or readU16(bess.core, 2) != 1)
        return error.UnsupportedBessVersion;
    if (!std.mem.eql(u8, bess.core[4..8], "GDB "))
        return error.UnsupportedBessModel;

    const native_cpu = try parseCpu(native.core);
    if (readU16(bess.core, 8) != native_cpu.pc or
        readU16(bess.core, 10) != native_cpu.af() or
        readU16(bess.core, 12) != native_cpu.bc() or
        readU16(bess.core, 14) != native_cpu.de() or
        readU16(bess.core, 16) != native_cpu.hl() or
        readU16(bess.core, 18) != native_cpu.sp or
        (bess.core[20] != 0) != native_cpu.ime or
        bess.core[21] != native.core[13])
    {
        return error.NativeBessCpuMismatch;
    }
    const execution_mode: u8 = if (native_cpu.halted)
        1
    else if (native_cpu.stopped)
        2
    else
        0;
    if (bess.core[22] != execution_mode or bess.core[23] != 0)
        return error.NativeBessCpuMismatch;

    const native_io = native.hram[HRAM_SIZE .. HRAM_SIZE + IO_SIZE];
    const bess_io = bess.core[24 .. 24 + IO_SIZE];
    for (native_io, bess_io, 0..) |native_byte, bess_byte, index| {
        const expected = switch (index) {
            IO_DIV => @as(u8, @truncate(readU16(native.timing, 16) >> 8)),
            IO_BANK => @as(u8, @intFromBool(try readBool(native.core, 24))),
            IO_KEY1 => native_byte |
                (@as(u8, @intFromBool(try readBool(native.core, 21))) << 7),
            else => native_byte,
        };
        if (bess_byte != expected)
            return error.NativeBessIoMismatch;
    }

    const descriptors = [_]struct {
        offset: usize,
        size: usize,
        file_offset: usize,
    }{
        .{ .offset = 152, .size = WRAM_SIZE, .file_offset = WRAM_OFFSET },
        .{ .offset = 160, .size = VRAM_SIZE, .file_offset = VRAM_OFFSET },
        .{
            .offset = 168,
            .size = cartridge.header.RAM_SIZE,
            .file_offset = SRAM_OFFSET,
        },
        .{ .offset = 176, .size = OAM_SIZE, .file_offset = 773 },
        .{ .offset = 184, .size = HRAM_SIZE, .file_offset = 296 },
    };
    for (descriptors) |descriptor| {
        if (readU32(bess.core, descriptor.offset) != descriptor.size or
            readU32(bess.core, descriptor.offset + 4) !=
                descriptor.file_offset)
        {
            return error.InvalidBessBuffer;
        }
        if (descriptor.file_offset + descriptor.size > BESS_OFFSET)
            return error.InvalidBessBuffer;
    }
    for ([_]usize{ 192, 200 }) |offset| {
        if (readU32(bess.core, offset) != 0 or
            readU32(bess.core, offset + 4) != 0)
        {
            return error.InvalidBessBuffer;
        }
    }
    if (!std.mem.eql(
        u8,
        bytes[773 .. 773 + OAM_SIZE],
        native.video[5 .. 5 + OAM_SIZE],
    ) or
        !std.mem.eql(
            u8,
            bytes[296 .. 296 + HRAM_SIZE],
            native.hram[0..HRAM_SIZE],
        ))
    {
        return error.NativeBessMemoryMismatch;
    }
    if (!std.mem.allEqual(u8, bess.xoam, 0))
        return error.NativeBessMemoryMismatch;
}

fn parseCpu(core: []const u8) ImportError!runner.Cpu {
    const af = readU16(core, 0);
    if (af & 0x000f != 0) return error.InvalidNativeCpu;
    var cpu = runner.Cpu{
        .sp = readU16(core, 8),
        .pc = readU16(core, 10),
        .ime = try readBool(core, 12),
        .ime_enable_pending = try readBool(core, 25),
        .halted = try readBool(core, 22),
        .stopped = try readBool(core, 23),
    };
    cpu.setAf(af);
    cpu.setBc(readU16(core, 2));
    cpu.setDe(readU16(core, 4));
    cpu.setHl(readU16(core, 6));
    return cpu;
}

fn parseMapper(
    native_mbc: []const u8,
    bess_mbc: []const u8,
) ImportError!cartridge.mbc3.State {
    const raw_rom_bank = native_mbc[14];
    const packed_ram = native_mbc[15];
    const raw_ram_bank = packed_ram & 0x07;
    const rtc_mapped = packed_ram & 0x08 != 0;
    if (raw_rom_bank > 0x7f)
        return error.InvalidMbc3State;
    const enabled = try readBool(native_mbc, 12);
    const expected_effective: u16 =
        if (raw_rom_bank == 0) 1 else raw_rom_bank;
    if (readU16(native_mbc, 0) != expected_effective or
        readU16(native_mbc, 2) != 0 or
        native_mbc[4] != raw_ram_bank)
    {
        return error.InvalidMbc3State;
    }

    const expected_pairs = [_]u8{
        0x00, 0x00, if (enabled) 0x0a else 0x00,
        0x00, 0x20, raw_rom_bank,
        0x00, 0x40,
        raw_ram_bank |
            (@as(u8, @intFromBool(rtc_mapped)) << 3),
    };
    if (!std.mem.eql(u8, bess_mbc, &expected_pairs))
        return error.NativeBessMapperMismatch;
    return .{
        .rom_bank_register = @intCast(raw_rom_bank),
        .ram_bank_register = @intCast(raw_ram_bank),
        .ram_enabled = enabled,
    };
}

fn parseTimer(
    timing: []const u8,
    hram: []const u8,
) ImportError!TimerState {
    const reload_state: runner.timer.ReloadState = switch (timing[18]) {
        0 => .running,
        1 => .reloading,
        2 => .reloaded,
        else => return error.InvalidNativeTimer,
    };
    var raw: [64]u8 = undefined;
    @memcpy(&raw, timing);
    const io = hram[HRAM_SIZE .. HRAM_SIZE + IO_SIZE];
    return .{
        .display_cycles = readI32(timing, 0),
        .display_state = readI32(timing, 4),
        .div_cycles = readI32(timing, 8),
        .div_state = readI32(timing, 12),
        .div_counter = readU16(timing, 16),
        .reload_state = reload_state,
        .tima = io[IO_TIMA],
        .tma = io[IO_TMA],
        .tac = @truncate(io[IO_TAC]),
        .joypad_switching_delay = timing[46],
        .joypad_switch_value = timing[47],
        .raw = raw,
    };
}

fn parseDma(dma: []const u8) ImportError!DmaState {
    var raw: [24]u8 = undefined;
    @memcpy(&raw, dma);
    return .{
        .hdma_on = try readBool(dma, 0),
        .hdma_on_hblank = try readBool(dma, 1),
        .hdma_steps_left = dma[2],
        .hdma_current_src = readU16(dma, 4),
        .hdma_current_dest = readU16(dma, 6),
        .current_dest = dma[8],
        .last_read = dma[9],
        .current_src = readU16(dma, 10),
        .cycles = readU16(dma, 12),
        .cycles_modulo = @bitCast(dma[14]),
        .ppu_vram_conflict = try readBool(dma, 15),
        .ppu_vram_conflict_addr = readU16(dma, 16),
        .allow_hdma_on_wake = try readBool(dma, 18),
        .restarting = try readBool(dma, 19),
        .raw = raw,
    };
}

fn parseApu(apu: []const u8) ImportError!ApuState {
    if (apu.len != apu_mmio.SAMEBOY_NATIVE_SIZE)
        return error.InvalidNativeSectionSize;
    for ([_]usize{
        0,   8,  9,  10, 11, 22, 23, 33, 38, 47, 52, 56, 64,
        70,  71, 80, 84, 86, 87, 88, 95, 96, 97, 98, 99, 100,
        101,
    }) |offset| _ = try readBool(apu, offset);
    if (apu[92] > 2) return error.InvalidNativeBoolean;
    var raw: [apu_mmio.SAMEBOY_NATIVE_SIZE]u8 = undefined;
    @memcpy(&raw, apu);
    return .{ .raw = raw };
}

fn parsePpu(video: []const u8) ImportError!PpuState {
    var raw: [464]u8 = undefined;
    @memcpy(&raw, video);
    return .{
        .position_in_line = video[293],
        .stat_interrupt_line = try readBool(video, 294),
        .current_line = video[301],
        .ly_for_comparison = readU16(video, 302),
        .cycles_for_line = readU16(video, 374),
        .mode_for_interrupt = video[422],
        .lyc_interrupt_line = try readBool(video, 423),
        .current_lcd_line = video[425],
        .oam_ppu_blocked = try readBool(video, 427),
        .vram_ppu_blocked = try readBool(video, 428),
        .lcd_x = video[436],
        .frame_parity_ticks = readU32(video, 452),
        .raw = raw,
    };
}

fn readBool(bytes: []const u8, offset: usize) ImportError!bool {
    return switch (bytes[offset]) {
        0 => false,
        1 => true,
        else => error.InvalidNativeBoolean,
    };
}

fn readU16(bytes: []const u8, offset: usize) u16 {
    return std.mem.readInt(u16, bytes[offset..][0..2], .little);
}

fn readU32(bytes: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, bytes[offset..][0..4], .little);
}

fn readI32(bytes: []const u8, offset: usize) i32 {
    return std.mem.readInt(i32, bytes[offset..][0..4], .little);
}
