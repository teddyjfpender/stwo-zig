//! Public v7 machine-environment statement.
//!
//! The complete v3 environment statement remains the transcript prefix.
//! This extension commits only the scheduler, PPU, APU, and DMA data not
//! already owned by v3. CPU, timer, mapper, IF, and IE remain single-sourced
//! by the v3 statement and its authenticated memory images.

const std = @import("std");
const channel_blake2s = @import("stwo_core").channel.blake2s;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const environment_statement = @import("environment_statement.zig");
const action_schedule = @import("action_schedule.zig");
const cartridge = @import("cartridge/mod.zig");
const action_lookup = @import("air/joypad_action_lookup.zig");
const dma_execution_lookup = @import("air/dma_execution_lookup.zig");
const intermediate_observation =
    @import("air/intermediate_ram_observation_lookup.zig");
const interrupt_service_memory_lookup =
    @import("air/interrupt_service_memory_lookup.zig");
const mmio_lookup = @import("air/joypad_mmio_lookup.zig");
const memory_lookup = @import("air/cartridge_memory_lookup.zig");
const ppu_binding = @import("air/ppu_binding.zig");
const ppu_execution_policy = @import("ppu_execution_policy.zig");
const ppu_mmio_lookup = @import("air/ppu_mmio_lookup.zig");
const ram_observation = @import("ram_observation.zig");
const rom_lookup = @import("air/cartridge_rom_lookup.zig");
const scheduler_memory_lookup =
    @import("air/scheduler_memory_lookup.zig");
const timer_mmio_lookup = @import("air/timer_mmio_lookup.zig");
const apu_execution_lookup = @import("air/apu_execution_lookup.zig");
const machine = @import("runner/machine.zig");
const apu = @import("runner/apu_mmio.zig");
const dma = @import("runner/dma.zig");
const ppu_mmio = @import("runner/ppu_mmio.zig");
const timer = @import("runner/timer.zig");

pub const Channel = channel_blake2s.Blake2sChannel;
pub const DOMAIN_TAG: u32 = 0x534d_4506;
pub const VERSION: u32 = 7;
pub const ENDPOINT_ENCODED_SIZE: usize = 76;
pub const Digest = [std.crypto.hash.sha2.Sha256.digest_length]u8;

const ENDPOINT_DOMAIN = "stwo-zig/sm83/machine-endpoint/v7\x00";

pub const ExecutionStatement = struct {
    base: environment_statement.ExecutionStatement,
    version: u32,
    initial_halt_bug: bool,
    final_halt_bug: bool,
    initial_ppu: ppu_binding.State,
    final_ppu: ppu_binding.State,
    initial_apu: apu.State,
    final_apu: apu.State,
    initial_dma: dma.State,
    final_dma: dma.State,
    expected_service_count: u32,
    ppu_log_size: u32,
    apu_log_size: u32,
    dma_log_size: u32,
    scheduler_memory_lookup_claims: scheduler_memory_lookup.Claims,
    interrupt_service_memory_lookup_claims: interrupt_service_memory_lookup.Claims,
    ppu_mmio_lookup_claims: ppu_mmio_lookup.Claims,
    ppu_if_memory_claim: QM31,
    ppu_execution_policy_claims: ppu_execution_policy.Claims,
    dma_execution_lookup_claims: dma_execution_lookup.Claims,
    dma_memory_claims: [2]QM31,
    apu_execution_lookup_claims: apu_execution_lookup.Claims,
};

pub fn init(
    base: environment_statement.ExecutionStatement,
    initial_machine: machine.MachineState,
    final_machine: machine.MachineState,
    initial_ppu: ppu_binding.State,
    final_ppu: ppu_binding.State,
    initial_apu: apu.State,
    final_apu: apu.State,
    initial_dma: dma.State,
    final_dma: dma.State,
    expected_service_count: u32,
    ppu_log_size: u32,
    apu_log_size: u32,
    dma_log_size: u32,
    initial_images: memory_lookup.Images,
    final_images: memory_lookup.Images,
) !ExecutionStatement {
    try validateMachineProjection(
        .initial,
        base,
        initial_machine,
        initial_images,
    );
    try validateMachineProjection(
        .final,
        base,
        final_machine,
        final_images,
    );
    const statement = ExecutionStatement{
        .base = base,
        .version = VERSION,
        .initial_halt_bug = initial_machine.halt_bug,
        .final_halt_bug = final_machine.halt_bug,
        .initial_ppu = initial_ppu,
        .final_ppu = final_ppu,
        .initial_apu = initial_apu,
        .final_apu = final_apu,
        .initial_dma = initial_dma,
        .final_dma = final_dma,
        .expected_service_count = expected_service_count,
        .ppu_log_size = ppu_log_size,
        .apu_log_size = apu_log_size,
        .dma_log_size = dma_log_size,
        .scheduler_memory_lookup_claims = .{
            .samples = [_]QM31{QM31.zero()} **
                scheduler_memory_lookup.N_SAMPLES,
        },
        .interrupt_service_memory_lookup_claims = .{
            .operations = [_]QM31{QM31.zero()} **
                interrupt_service_memory_lookup.N_OPERATIONS,
            .service_count = 0,
        },
        .ppu_mmio_lookup_claims = .{
            .execution = [_][ppu_mmio_lookup.N_EXECUTION_SUMS]QM31{
                [_]QM31{QM31.zero()} **
                    ppu_mmio_lookup.N_EXECUTION_SUMS,
            } ** ppu_mmio_lookup.N_RELATIONS,
            .ppu = [_]QM31{QM31.zero()} **
                ppu_mmio_lookup.N_RELATIONS,
        },
        .ppu_if_memory_claim = QM31.zero(),
        .ppu_execution_policy_claims = .{
            .dma = QM31.zero(),
            .ppu = QM31.zero(),
        },
        .dma_execution_lookup_claims = .{
            .execution = [_]QM31{QM31.zero()} **
                dma_execution_lookup.N_EXECUTION_SUMS,
            .dma = QM31.zero(),
            .execution_count = 0,
            .dma_count = 0,
        },
        .dma_memory_claims = .{ QM31.zero(), QM31.zero() },
        .apu_execution_lookup_claims = .{
            .execution = [_]QM31{QM31.zero()} **
                apu_execution_lookup.N_EXECUTION_SUMS,
            .apu = QM31.zero(),
            .execution_count = 0,
            .apu_count = 0,
        },
    };
    try validateShape(statement);
    try validatePpuImageEndpoints(
        statement.initial_ppu,
        statement.final_ppu,
        initial_images,
        final_images,
    );
    try validateDmaImageEndpoints(
        statement.initial_dma,
        statement.final_dma,
        initial_images,
        final_images,
    );
    try validateApuImageEndpoints(
        statement.initial_apu,
        statement.final_apu,
        initial_images,
        final_images,
    );
    return statement;
}

pub fn validate(
    statement: ExecutionStatement,
    rom: cartridge.Cartridge,
    initial_images: memory_lookup.Images,
    final_images: memory_lookup.Images,
    actions: []const action_schedule.Action,
    observation_regions: []const ram_observation.Region,
    intermediate_observations: []const intermediate_observation.Sample,
) !void {
    try environment_statement.validate(
        statement.base,
        rom,
        initial_images,
        final_images,
        actions,
        observation_regions,
        intermediate_observations,
    );
    try validateShape(statement);
    try validatePpuImageEndpoints(
        statement.initial_ppu,
        statement.final_ppu,
        initial_images,
        final_images,
    );
    try validateDmaImageEndpoints(
        statement.initial_dma,
        statement.final_dma,
        initial_images,
        final_images,
    );
    try validateApuImageEndpoints(
        statement.initial_apu,
        statement.final_apu,
        initial_images,
        final_images,
    );
}

pub fn validateShape(statement: ExecutionStatement) !void {
    if (statement.version != VERSION)
        return error.InvalidMachineEnvironmentVersion;
    try environment_statement.validateShape(statement.base);
    try statement.initial_ppu.validate();
    try statement.final_ppu.validate();
    try statement.initial_apu.validate();
    try statement.final_apu.validate();
    try statement.initial_dma.validate();
    try statement.final_dma.validate();
    try validateLogSize(statement.ppu_log_size, error.InvalidPpuLogSize);
    try validateLogSize(statement.apu_log_size, error.InvalidApuLogSize);
    try validateLogSize(statement.dma_log_size, error.InvalidDmaLogSize);
    const base = statement.base.base;
    const row_count = @as(usize, 1) << @intCast(base.log_size);
    if (statement.expected_service_count > row_count)
        return error.TooManyInterruptServices;
    if (statement.initial_dma.clock != base.initial.mcycle)
        return error.InitialDmaClockMismatch;
    if (statement.final_dma.clock != base.final.mcycle)
        return error.FinalDmaClockMismatch;
}

/// Preserves every v3 public field as an exact transcript prefix.
pub fn mixPublic(
    channel: *Channel,
    statement: ExecutionStatement,
) void {
    environment_statement.mixPublic(channel, statement.base);
    channel.mixU32s(&.{
        DOMAIN_TAG,
        statement.version,
        statement.expected_service_count,
        statement.ppu_log_size,
        statement.apu_log_size,
        statement.dma_log_size,
    });
    mixEndpoint(
        channel,
        statement.initial_halt_bug,
        statement.initial_ppu,
        statement.initial_apu,
        statement.initial_dma,
    );
    mixEndpoint(
        channel,
        statement.final_halt_bug,
        statement.final_ppu,
        statement.final_apu,
        statement.final_dma,
    );
}

/// Mixes every v7 post-relation claim after the exact v3 claim prefix.
pub fn mixLookupClaims(
    channel: *Channel,
    statement: ExecutionStatement,
) void {
    environment_statement.mixLookupClaims(channel, statement.base);
    channel.mixFelts(
        &statement.scheduler_memory_lookup_claims.samples,
    );
    channel.mixFelts(
        &statement.interrupt_service_memory_lookup_claims.operations,
    );
    for (statement.ppu_mmio_lookup_claims.execution) |claims|
        channel.mixFelts(&claims);
    channel.mixFelts(&statement.ppu_mmio_lookup_claims.ppu);
    channel.mixFelts(&.{statement.ppu_if_memory_claim});
    channel.mixFelts(&.{
        statement.ppu_execution_policy_claims.dma,
        statement.ppu_execution_policy_claims.ppu,
    });
    channel.mixFelts(
        &statement.dma_execution_lookup_claims.execution,
    );
    channel.mixFelts(&.{statement.dma_execution_lookup_claims.dma});
    channel.mixFelts(&statement.dma_memory_claims);
    channel.mixFelts(
        &statement.apu_execution_lookup_claims.execution,
    );
    channel.mixFelts(&.{statement.apu_execution_lookup_claims.apu});
    channel.mixU32s(&.{
        @intCast(statement.apu_execution_lookup_claims.execution_count),
        @intCast(statement.apu_execution_lookup_claims.apu_count),
    });
}

pub fn verifyLookupCancellation(
    statement: ExecutionStatement,
) !void {
    try rom_lookup.verifyCancellation(
        statement.base.base.rom_lookup_claims,
    );
    try action_lookup.verifyCancellation(
        statement.base.action_lookup_claims,
    );
    try mmio_lookup.verifyCancellation(
        statement.base.joypad_mmio_lookup_claims,
    );
    try timer_mmio_lookup.verifyCancellation(
        statement.base.timer_mmio_lookup_claims,
    );
    try ppu_mmio_lookup.verifyCancellation(
        statement.ppu_mmio_lookup_claims,
    );
    try ppu_execution_policy.verifyCancellation(
        statement.ppu_execution_policy_claims,
    );
    try dma_execution_lookup.verifyCancellation(
        statement.dma_execution_lookup_claims,
    );
    try apu_execution_lookup.verifyCancellation(
        statement.apu_execution_lookup_claims,
        statement.initial_apu,
        statement.final_apu,
    );
    if (statement.interrupt_service_memory_lookup_claims.service_count !=
        statement.expected_service_count)
        return error.InterruptServiceCountMismatch;
    const expected_dma_count: usize =
        statement.base.base.final.mcycle -
        statement.base.base.initial.mcycle;
    if (statement.dma_execution_lookup_claims.execution_count !=
        expected_dma_count or
        statement.dma_execution_lookup_claims.dma_count !=
            expected_dma_count)
        return error.DmaExecutionCountMismatch;

    var memory_total =
        statement.base.base.memory_lookup_claims.total();
    inline for (.{
        statement.base.joypad_if_memory_claim,
        statement.base.timer_if_memory_claim,
        statement.base.intermediate_observation_memory_claim,
        statement.scheduler_memory_lookup_claims.total(),
        statement.interrupt_service_memory_lookup_claims.total(),
        statement.ppu_if_memory_claim,
        statement.dma_memory_claims[0],
        statement.dma_memory_claims[1],
    }) |claim| memory_total = memory_total.add(claim);
    if (!memory_total.isZero())
        return error.CartridgeMemoryLookupSumNonZero;
}

pub fn publicDigest(statement: ExecutionStatement) Digest {
    var channel = Channel{};
    mixPublic(&channel, statement);
    return channel.digestBytes();
}

/// Fixed-width little-endian encoding of one machine endpoint extension.
pub fn encodeEndpoint(
    halt_bug: bool,
    ppu_state: ppu_binding.State,
    apu_state: apu.State,
    dma_state: dma.State,
) ![ENDPOINT_ENCODED_SIZE]u8 {
    try ppu_state.validate();
    try apu_state.validate();
    try dma_state.validate();
    return encodeEndpointUnchecked(halt_bug, ppu_state, apu_state, dma_state);
}

pub fn endpointDigest(
    halt_bug: bool,
    ppu_state: ppu_binding.State,
    apu_state: apu.State,
    dma_state: dma.State,
) !Digest {
    const encoded = try encodeEndpoint(
        halt_bug,
        ppu_state,
        apu_state,
        dma_state,
    );
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(ENDPOINT_DOMAIN);
    hash.update(&encoded);
    var result: Digest = undefined;
    hash.final(&result);
    return result;
}

fn validatePpuImageEndpoints(
    initial_ppu: ppu_binding.State,
    final_ppu: ppu_binding.State,
    initial_images: memory_lookup.Images,
    final_images: memory_lookup.Images,
) !void {
    if (initial_images.system.bytes.len != memory_lookup.SYSTEM_SIZE or
        final_images.system.bytes.len != memory_lookup.SYSTEM_SIZE)
        return error.InvalidSystemMemoryShape;
    try validateImageEndpoint(
        .initial,
        initial_ppu,
        initial_images,
    );
    try validateImageEndpoint(
        .final,
        final_ppu,
        final_images,
    );
}

fn validateDmaImageEndpoints(
    initial_dma: dma.State,
    final_dma: dma.State,
    initial_images: memory_lookup.Images,
    final_images: memory_lookup.Images,
) !void {
    if (initial_images.system.bytes.len != memory_lookup.SYSTEM_SIZE or
        final_images.system.bytes.len != memory_lookup.SYSTEM_SIZE)
        return error.InvalidSystemMemoryShape;
    if (initial_images.system.bytes[dma.DMA_ADDRESS] != initial_dma.page)
        return error.InitialDmaPageMismatch;
    if (final_images.system.bytes[dma.DMA_ADDRESS] != final_dma.page)
        return error.FinalDmaPageMismatch;
}

fn validateApuImageEndpoints(
    initial_apu: apu.State,
    final_apu: apu.State,
    initial_images: memory_lookup.Images,
    final_images: memory_lookup.Images,
) !void {
    if (initial_images.system.bytes.len != memory_lookup.SYSTEM_SIZE or
        final_images.system.bytes.len != memory_lookup.SYSTEM_SIZE)
        return error.InvalidSystemMemoryShape;
    const first: usize = apu.FIRST_ADDRESS;
    const end: usize = apu.LAST_ADDRESS + 1;
    if (!std.mem.eql(
        u8,
        initial_images.system.bytes[first..end],
        &initial_apu.registers,
    )) return error.InitialApuRegisterMismatch;
    if (!std.mem.eql(
        u8,
        final_images.system.bytes[first..end],
        &final_apu.registers,
    )) return error.FinalApuRegisterMismatch;
}

const Boundary = enum { initial, final };

fn validateImageEndpoint(
    boundary: Boundary,
    ppu_state: ppu_binding.State,
    images: memory_lookup.Images,
) !void {
    inline for ([_]ppu_binding.Register{
        .lcdc,
        .stat,
        .scy,
        .scx,
        .ly,
        .lyc,
        .wy,
    }) |register| {
        const address: usize = switch (register) {
            .lcdc => ppu_mmio.LCDC_ADDRESS,
            .stat => ppu_mmio.STAT_ADDRESS,
            .scy => ppu_mmio.SCY_ADDRESS,
            .scx => ppu_mmio.SCX_ADDRESS,
            .ly => ppu_mmio.LY_ADDRESS,
            .lyc => ppu_mmio.LYC_ADDRESS,
            .wy => ppu_mmio.WY_ADDRESS,
        };
        if (images.system.bytes[address] != ppu_state.read(register))
            return switch (boundary) {
                .initial => error.InitialPpuRegisterMismatch,
                .final => error.FinalPpuRegisterMismatch,
            };
    }
}

fn machineTimerMatches(
    state: machine.MachineState,
    device: timer.Timer,
) bool {
    return state.div_counter == device.div_counter and
        state.tima == device.readTima() and
        state.tma == device.tma and
        state.tac == device.tac and
        state.timer_reload == device.reload_state;
}

fn validateMachineProjection(
    boundary: Boundary,
    base: environment_statement.ExecutionStatement,
    state: machine.MachineState,
    images: memory_lookup.Images,
) !void {
    if (state.cpu.f & 0x0f != 0)
        return error.InvalidMachineFlags;
    if (state.tac & 0xf8 != 0)
        return error.InvalidMachineTac;
    const endpoint = switch (boundary) {
        .initial => base.base.initial,
        .final => base.base.final,
    };
    const timer_state = switch (boundary) {
        .initial => base.initial_timer,
        .final => base.final_timer,
    };
    if (!std.meta.eql(state.cpu, endpoint.cpu))
        return switch (boundary) {
            .initial => error.InitialMachineCpuMismatch,
            .final => error.FinalMachineCpuMismatch,
        };
    if (!machineTimerMatches(state, timer_state))
        return switch (boundary) {
            .initial => error.InitialMachineTimerMismatch,
            .final => error.FinalMachineTimerMismatch,
        };
    if (images.system.bytes.len != memory_lookup.SYSTEM_SIZE)
        return error.InvalidSystemMemoryShape;
    if (images.system.bytes[0xff0f] != state.interrupt_flags)
        return switch (boundary) {
            .initial => error.InitialInterruptFlagsMismatch,
            .final => error.FinalInterruptFlagsMismatch,
        };
    if (images.system.bytes[0xffff] != state.interrupt_enable)
        return switch (boundary) {
            .initial => error.InitialInterruptEnableMismatch,
            .final => error.FinalInterruptEnableMismatch,
        };
}

fn validateLogSize(log_size: u32, invalid: anyerror) !void {
    if (log_size < 4 or log_size > 24 or
        log_size >= @bitSizeOf(usize))
        return invalid;
}

fn mixEndpoint(
    channel: *Channel,
    halt_bug: bool,
    ppu_state: ppu_binding.State,
    apu_state: apu.State,
    dma_state: dma.State,
) void {
    const encoded = encodeEndpointUnchecked(
        halt_bug,
        ppu_state,
        apu_state,
        dma_state,
    );
    var words: [ENDPOINT_ENCODED_SIZE]u32 = undefined;
    for (&words, encoded) |*word, byte| word.* = byte;
    channel.mixU32s(&words);
}

fn encodeEndpointUnchecked(
    halt_bug: bool,
    ppu_state: ppu_binding.State,
    apu_state: apu.State,
    dma_state: dma.State,
) [ENDPOINT_ENCODED_SIZE]u8 {
    var out: [ENDPOINT_ENCODED_SIZE]u8 = undefined;
    var at: usize = 0;
    putU8(&out, &at, @intFromBool(halt_bug));

    const timing = ppu_state.timing;
    putU8(&out, &at, @intFromBool(timing.lcd_enabled));
    putU8(&out, &at, timing.line);
    putU16(&out, &at, timing.dot);
    putU8(&out, &at, @intFromBool(timing.startup_line));
    putU8(&out, &at, timing.lyc);
    putU8(&out, &at, timing.stat_enable);
    inline for (.{
        timing.coincidence,
        timing.lyc_interrupt_line,
        timing.stat_interrupt_line,
    }) |value| putU8(&out, &at, @intFromBool(value));
    putU8(&out, &at, ppu_state.lcdc);

    putU32(&out, &at, dma_state.clock);
    putU8(&out, &at, dma_state.page);
    putU8(&out, &at, dma_state.copied);
    putU8(&out, &at, @intFromEnum(dma_state.phase));
    putU8(&out, &at, @intFromBool(dma_state.restarting));

    // Preserve the complete v5 endpoint encoding as a byte prefix. The v6
    // PPU latch and v7 APU extensions are append-only and domain-separated.
    putU8(&out, &at, ppu_state.scy);
    putU8(&out, &at, ppu_state.scx);
    putU8(&out, &at, ppu_state.wy);
    for (apu_state.registers) |value| putU8(&out, &at, value);
    putU8(&out, &at, @intFromBool(apu_state.enabled));
    putU8(&out, &at, @intFromBool(apu_state.channel_status != null));
    putU8(&out, &at, apu_state.channel_status orelse 0);
    const wave_mode: u8 = switch (apu_state.wave_access) {
        .inactive => 0,
        .blocked => 1,
        .current_byte => 2,
        .unknown => 3,
    };
    putU8(&out, &at, wave_mode);
    putU8(
        &out,
        &at,
        if (apu_state.wave_access == .current_byte)
            apu_state.wave_access.current_byte
        else
            0,
    );
    std.debug.assert(at == out.len);
    return out;
}

fn putU8(
    out: *[ENDPOINT_ENCODED_SIZE]u8,
    at: *usize,
    value: anytype,
) void {
    out[at.*] = @intCast(value);
    at.* += 1;
}

fn putU16(
    out: *[ENDPOINT_ENCODED_SIZE]u8,
    at: *usize,
    value: u16,
) void {
    std.mem.writeInt(u16, out[at.*..][0..2], value, .little);
    at.* += 2;
}

fn putU32(
    out: *[ENDPOINT_ENCODED_SIZE]u8,
    at: *usize,
    value: u32,
) void {
    std.mem.writeInt(u32, out[at.*..][0..4], value, .little);
    at.* += 4;
}
