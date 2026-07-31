//! Canonical memory-image projection for Pokémon fixture device endpoints.

const std = @import("std");
const memory_lookup = @import("air/cartridge_memory_lookup.zig");
const ppu_binding = @import("air/ppu_binding.zig");
const runner = @import("runner/mod.zig");

const addresses = [_]u16{
    runner.joypad.P1_ADDRESS,
    0xff04,
    0xff05,
    0xff06,
    0xff07,
    runner.ppu_mmio.LCDC_ADDRESS,
    runner.ppu_mmio.STAT_ADDRESS,
    runner.ppu_mmio.SCY_ADDRESS,
    runner.ppu_mmio.SCX_ADDRESS,
    runner.ppu_mmio.LY_ADDRESS,
    runner.ppu_mmio.LYC_ADDRESS,
    runner.ppu_mmio.WY_ADDRESS,
    runner.dma.DMA_ADDRESS,
};

pub const Normalization = struct {
    changed_mask: u16,
    before: [addresses.len]u8,
    after: [addresses.len]u8,
};

pub fn normalize(
    system: *[memory_lookup.SYSTEM_SIZE]u8,
    joypad: runner.joypad.State,
    timer: runner.timer.Timer,
    ppu: ppu_binding.State,
    dma: runner.dma.State,
) Normalization {
    const values = [_]u8{
        joypad.readP1(),
        timer.readDiv(),
        timer.readTima(),
        timer.readTma(),
        timer.readTac(),
        ppu.read(.lcdc),
        ppu.read(.stat),
        ppu.read(.scy),
        ppu.read(.scx),
        ppu.read(.ly),
        ppu.read(.lyc),
        ppu.read(.wy),
        dma.page,
    };
    var result = Normalization{
        .changed_mask = 0,
        .before = undefined,
        .after = values,
    };
    for (addresses, values, 0..) |address, value, index| {
        result.before[index] = system[address];
        if (system[address] != value)
            result.changed_mask |= @as(u16, 1) << @intCast(index);
        system[address] = value;
    }
    return result;
}

pub fn validate(
    system: *const [memory_lookup.SYSTEM_SIZE]u8,
    normalization: Normalization,
) !void {
    if (normalization.changed_mask >> @intCast(addresses.len) != 0)
        return error.InvalidEndpointNormalizationMask;
    for (addresses, normalization.after) |address, expected| {
        if (system[address] != expected)
            return error.EndpointNormalizationMismatch;
    }
}

pub fn validateApu(
    system: *const [memory_lookup.SYSTEM_SIZE]u8,
    apu: runner.apu_mmio.State,
) !void {
    try apu.validate();
    if (!std.mem.eql(
        u8,
        system[runner.apu_mmio.FIRST_ADDRESS .. runner.apu_mmio.LAST_ADDRESS + 1],
        &apu.registers,
    )) return error.ApuEndpointMismatch;
}

test "normalization touches exactly the device endpoint bytes" {
    var system = [_]u8{0} ** memory_lookup.SYSTEM_SIZE;
    const joypad = try runner.joypad.State.init(0xff, 0, 3, 0);
    const timer = runner.timer.Timer{
        .div_counter = 0x1234,
        .tima = 0x56,
        .tma = 0x78,
        .tac = 5,
    };
    const ppu = ppu_binding.State{};
    const dma = runner.dma.State{ .clock = 13_312_966, .page = 0xc3 };
    const before = system;
    const normalized = normalize(&system, joypad, timer, ppu, dma);
    try validate(&system, normalized);
    try std.testing.expectEqual(
        @as(u16, (1 << 0) |
            (1 << 1) |
            (1 << 2) |
            (1 << 3) |
            (1 << 4) |
            (1 << 6) |
            (1 << 12)),
        normalized.changed_mask,
    );
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xff,
        0x12,
        0x56,
        0x78,
        0xfd,
        0,
        0x80,
        0,
        0,
        0,
        0,
        0,
        0xc3,
    }, &normalized.after);
    for (system, before, 0..) |actual, old, address| {
        const is_endpoint = for (addresses) |endpoint| {
            if (address == endpoint) break true;
        } else false;
        if (!is_endpoint)
            try std.testing.expectEqual(old, actual);
    }
    system[runner.dma.DMA_ADDRESS] ^= 1;
    try std.testing.expectError(
        error.EndpointNormalizationMismatch,
        validate(&system, normalized),
    );
}

test "APU endpoint validation fails on any raw latch mismatch" {
    var system = [_]u8{0} ** memory_lookup.SYSTEM_SIZE;
    const apu = runner.apu_mmio.State{};
    try validateApu(&system, apu);

    for (runner.apu_mmio.FIRST_ADDRESS..runner.apu_mmio.LAST_ADDRESS + 1) |address| {
        system[address] = 1;
        try std.testing.expectError(
            error.ApuEndpointMismatch,
            validateApu(&system, apu),
        );
        system[address] = 0;
    }
}
