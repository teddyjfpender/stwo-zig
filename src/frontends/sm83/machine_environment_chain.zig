//! Continuity validation for independently verified v7 machine segments.
//!
//! Actions and relation claims are segment-local. A proof-chain verifier only
//! joins the public ROM identity and complete adjacent machine endpoints.

const std = @import("std");
const statement = @import("machine_environment_statement.zig");

pub const Error = error{
    RomDigestMismatch,
    CpuBoundaryMismatch,
    McycleBoundaryMismatch,
    MapperBoundaryMismatch,
    SystemDigestMismatch,
    SramDigestMismatch,
    JoypadBoundaryMismatch,
    TimerBoundaryMismatch,
    HaltBugBoundaryMismatch,
    PpuBoundaryMismatch,
    ApuBoundaryMismatch,
    DmaBoundaryMismatch,
};

/// Joins two separately verified v7 statements at their public endpoint.
pub fn validate(
    previous: statement.ExecutionStatement,
    next: statement.ExecutionStatement,
) Error!void {
    const previous_base = previous.base.base;
    const next_base = next.base.base;

    if (!std.mem.eql(
        u8,
        &previous_base.rom_digest,
        &next_base.rom_digest,
    )) return error.RomDigestMismatch;
    if (!std.meta.eql(previous_base.final.cpu, next_base.initial.cpu))
        return error.CpuBoundaryMismatch;
    if (previous_base.final.mcycle != next_base.initial.mcycle)
        return error.McycleBoundaryMismatch;
    if (!std.meta.eql(
        previous_base.final_mapper,
        next_base.initial_mapper,
    )) return error.MapperBoundaryMismatch;
    if (!std.mem.eql(
        u8,
        &previous_base.final_system_digest,
        &next_base.initial_system_digest,
    )) return error.SystemDigestMismatch;
    if (!std.mem.eql(
        u8,
        &previous_base.final_sram_digest,
        &next_base.initial_sram_digest,
    )) return error.SramDigestMismatch;
    if (!std.meta.eql(previous.base.final_joypad, next.base.initial_joypad))
        return error.JoypadBoundaryMismatch;
    if (!std.meta.eql(previous.base.final_timer, next.base.initial_timer))
        return error.TimerBoundaryMismatch;
    if (previous.final_halt_bug != next.initial_halt_bug)
        return error.HaltBugBoundaryMismatch;
    if (!std.meta.eql(previous.final_ppu, next.initial_ppu))
        return error.PpuBoundaryMismatch;
    if (!std.meta.eql(previous.final_apu, next.initial_apu))
        return error.ApuBoundaryMismatch;
    if (!std.meta.eql(previous.final_dma, next.initial_dma))
        return error.DmaBoundaryMismatch;
}

fn segment(
    initial_mcycle: u32,
    final_mcycle: u32,
) statement.ExecutionStatement {
    var result = std.mem.zeroInit(statement.ExecutionStatement, .{
        .initial_apu = .{},
        .final_apu = .{},
    });
    result.version = statement.VERSION;
    result.base.version = 3;
    result.base.base.log_size = 4;
    result.base.base.initial = .{
        .cpu = .{ .a = 0x12, .pc = 0x4567, .sp = 0xdffe },
        .mcycle = initial_mcycle,
    };
    result.base.base.final = .{
        .cpu = .{ .a = 0x34, .pc = 0x5678, .sp = 0xdffc },
        .mcycle = final_mcycle,
    };
    result.base.base.initial_mapper = .{
        .rom_bank_register = 2,
        .ram_bank_register = 1,
        .ram_enabled = true,
    };
    result.base.base.final_mapper = .{
        .rom_bank_register = 3,
        .ram_bank_register = 2,
        .ram_enabled = true,
    };
    result.base.base.rom_digest = [_]u8{0x11} ** 32;
    result.base.base.initial_system_digest = [_]u8{0x22} ** 32;
    result.base.base.final_system_digest = [_]u8{0x33} ** 32;
    result.base.base.initial_sram_digest = [_]u8{0x44} ** 32;
    result.base.base.final_sram_digest = [_]u8{0x55} ** 32;
    result.base.initial_joypad = .{};
    result.base.final_joypad = .{};
    result.base.joypad_log_size = 4;
    result.base.initial_timer = .{ .div_counter = 4, .tima = 5 };
    result.base.final_timer = .{ .div_counter = 8, .tima = 6 };
    result.base.timer_log_size = 4;
    result.base.intermediate_observation_log_size = 4;
    result.base.intermediate_observation_schedule_claim.count = 1;
    result.initial_halt_bug = false;
    result.final_halt_bug = true;
    result.initial_ppu = .{
        .lcdc = 1,
        .scy = 2,
        .scx = 3,
        .wy = 4,
    };
    result.final_ppu = .{
        .lcdc = 2,
        .scy = 5,
        .scx = 6,
        .wy = 7,
    };
    result.initial_apu = .{
        .enabled = true,
        .channel_status = 3,
        .wave_access = .{ .current_byte = 4 },
    };
    result.final_apu = .{
        .enabled = true,
        .channel_status = 2,
        .wave_access = .{ .current_byte = 5 },
    };
    result.initial_dma = .{ .clock = initial_mcycle, .page = 0x12 };
    result.final_dma = .{ .clock = final_mcycle, .page = 0x34 };
    result.ppu_log_size = 4;
    result.apu_log_size = 4;
    result.dma_log_size = 4;
    return result;
}

fn honestPair() [2]statement.ExecutionStatement {
    const previous = segment(100, 116);
    var next = segment(116, 132);
    next.base.base.initial = previous.base.base.final;
    next.base.base.initial_mapper = previous.base.base.final_mapper;
    next.base.base.initial_system_digest =
        previous.base.base.final_system_digest;
    next.base.base.initial_sram_digest =
        previous.base.base.final_sram_digest;
    next.base.initial_joypad = previous.base.final_joypad;
    next.base.initial_timer = previous.base.final_timer;
    next.initial_halt_bug = previous.final_halt_bug;
    next.initial_ppu = previous.final_ppu;
    next.initial_apu = previous.final_apu;
    next.initial_dma = previous.final_dma;
    return .{ previous, next };
}

test "v7 machine environment statements chain complete endpoints" {
    const pair = honestPair();
    try statement.validateShape(pair[0]);
    try statement.validateShape(pair[1]);
    try validate(pair[0], pair[1]);
}

test "v7 machine environment chain rejects every endpoint mutation" {
    const Leg = enum {
        rom,
        cpu,
        mcycle,
        mapper,
        system_digest,
        sram_digest,
        joypad,
        timer,
        halt_bug,
        ppu,
        ppu_scy,
        ppu_scx,
        ppu_wy,
        apu_register,
        apu_enabled,
        apu_status,
        apu_status_known,
        apu_wave_mode,
        apu_wave_current,
        dma,
    };
    const Case = struct {
        leg: Leg,
        expected: Error,
    };
    const cases = [_]Case{
        .{ .leg = .rom, .expected = error.RomDigestMismatch },
        .{ .leg = .cpu, .expected = error.CpuBoundaryMismatch },
        .{ .leg = .mcycle, .expected = error.McycleBoundaryMismatch },
        .{ .leg = .mapper, .expected = error.MapperBoundaryMismatch },
        .{
            .leg = .system_digest,
            .expected = error.SystemDigestMismatch,
        },
        .{ .leg = .sram_digest, .expected = error.SramDigestMismatch },
        .{ .leg = .joypad, .expected = error.JoypadBoundaryMismatch },
        .{ .leg = .timer, .expected = error.TimerBoundaryMismatch },
        .{ .leg = .halt_bug, .expected = error.HaltBugBoundaryMismatch },
        .{ .leg = .ppu, .expected = error.PpuBoundaryMismatch },
        .{ .leg = .ppu_scy, .expected = error.PpuBoundaryMismatch },
        .{ .leg = .ppu_scx, .expected = error.PpuBoundaryMismatch },
        .{ .leg = .ppu_wy, .expected = error.PpuBoundaryMismatch },
        .{ .leg = .apu_register, .expected = error.ApuBoundaryMismatch },
        .{ .leg = .apu_enabled, .expected = error.ApuBoundaryMismatch },
        .{ .leg = .apu_status, .expected = error.ApuBoundaryMismatch },
        .{ .leg = .apu_status_known, .expected = error.ApuBoundaryMismatch },
        .{ .leg = .apu_wave_mode, .expected = error.ApuBoundaryMismatch },
        .{ .leg = .apu_wave_current, .expected = error.ApuBoundaryMismatch },
        .{ .leg = .dma, .expected = error.DmaBoundaryMismatch },
    };

    const pair = honestPair();
    for (cases) |case| {
        var changed = pair[1];
        switch (case.leg) {
            .rom => changed.base.base.rom_digest[0] ^= 1,
            .cpu => changed.base.base.initial.cpu.a ^= 1,
            .mcycle => {
                changed.base.base.initial.mcycle -= 1;
                changed.initial_dma.clock -= 1;
            },
            .mapper => changed.base.base.initial_mapper.rom_bank_register +%= 1,
            .system_digest => changed.base.base.initial_system_digest[0] ^= 1,
            .sram_digest => changed.base.base.initial_sram_digest[0] ^= 1,
            .joypad => _ = changed.base.initial_joypad.setPressed(1),
            .timer => changed.base.initial_timer.tima ^= 1,
            .halt_bug => changed.initial_halt_bug =
                !changed.initial_halt_bug,
            .ppu => changed.initial_ppu.timing.lyc ^= 1,
            .ppu_scy => changed.initial_ppu.scy ^= 1,
            .ppu_scx => changed.initial_ppu.scx ^= 1,
            .ppu_wy => changed.initial_ppu.wy ^= 1,
            .apu_register => changed.initial_apu.registers[0] ^= 1,
            .apu_enabled => {
                changed.initial_apu.enabled = false;
                changed.initial_apu.channel_status = 0;
                changed.initial_apu.wave_access = .inactive;
            },
            .apu_status => changed.initial_apu.channel_status.? ^= 1,
            .apu_status_known => changed.initial_apu.channel_status = null,
            .apu_wave_mode => changed.initial_apu.wave_access = .blocked,
            .apu_wave_current => changed.initial_apu.wave_access.current_byte ^= 1,
            .dma => changed.initial_dma.page ^= 1,
        }
        try statement.validateShape(changed);
        try changed.base.initial_joypad.validate();
        try changed.initial_ppu.validate();
        try changed.initial_apu.validate();
        try changed.initial_dma.validate();
        try std.testing.expectError(
            case.expected,
            validate(pair[0], changed),
        );
    }
}
