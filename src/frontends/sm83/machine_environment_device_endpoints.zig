//! Device-owned memory-image boundary validation for SM83 environment replay.

const std = @import("std");
const runner = @import("runner/mod.zig");
const ledger_mod = @import("machine_environment_memory_ledger.zig");
const memory_lookup = @import("air/cartridge_memory_lookup.zig");
const joypad_trace = @import("joypad_trace.zig");
const timer_binding = @import("air/timer_binding.zig");
const ppu_binding = @import("air/ppu_binding.zig");
const ppu_mmio = @import("runner/ppu_mmio.zig");
const dma_binding = @import("air/dma_binding.zig");

const P1: u17 = runner.joypad.P1_ADDRESS;
const DIV: u17 = timer_binding.FIRST_ADDRESS;
const DMA: u17 = runner.dma.DMA_ADDRESS;

pub fn validate(
    initial: memory_lookup.Images,
    final: memory_lookup.Images,
    joypad_events: []const joypad_trace.EventRow,
    timer_events: []const timer_binding.EventRow,
    ppu_events: []const ppu_binding.EventRow,
    dma_events: []const dma_binding.EventRow,
) !void {
    const joypad_first = joypad_events[0].transition.before;
    const joypad_last =
        joypad_events[joypad_events.len - 1].transition.after;
    if (initial.system.bytes[P1] != joypad_first.readP1() or
        final.system.bytes[P1] != joypad_last.readP1())
        return error.JoypadMemoryEndpointMismatch;

    const timer_first = timer_events[0].transition.before;
    const timer_last = timer_events[timer_events.len - 1].transition.after;
    const timer_initial = [4]u8{
        timer_first.readDiv(),
        timer_first.readTima(),
        timer_first.readTma(),
        timer_first.readTac(),
    };
    const timer_final = [4]u8{
        timer_last.readDiv(),
        timer_last.readTima(),
        timer_last.readTma(),
        timer_last.readTac(),
    };
    if (!std.mem.eql(
        u8,
        initial.system.bytes[DIV .. DIV + 4],
        &timer_initial,
    ) or !std.mem.eql(
        u8,
        final.system.bytes[DIV .. DIV + 4],
        &timer_final,
    )) return error.TimerMemoryEndpointMismatch;

    const ppu_first = stateFromFirst(ppu_events);
    const ppu_last = stateFromLast(ppu_events);
    for ([_]ppu_binding.Register{
        .lcdc,
        .stat,
        .scy,
        .scx,
        .ly,
        .lyc,
        .wy,
    }) |register| {
        const address = ppuAddress(register);
        if (initial.system.bytes[address] != ppu_first.read(register) or
            final.system.bytes[address] != ppu_last.read(register))
            return error.PpuMemoryEndpointMismatch;
    }
    if (initial.system.bytes[DMA] !=
        dma_events[0].transition.before.page or
        final.system.bytes[DMA] !=
            dma_events[dma_events.len - 1].transition.after.page)
        return error.DmaMemoryEndpointMismatch;
}

pub fn installFinals(
    ledger: *ledger_mod.Ledger,
    final: memory_lookup.Images,
) void {
    ledger.bytes[P1] = final.system.bytes[P1];
    @memcpy(ledger.bytes[DIV .. DIV + 4], final.system.bytes[DIV .. DIV + 4]);
    for ([_]u16{
        ppu_mmio.LCDC_ADDRESS,
        ppu_mmio.STAT_ADDRESS,
        ppu_mmio.SCY_ADDRESS,
        ppu_mmio.SCX_ADDRESS,
        ppu_mmio.LY_ADDRESS,
        ppu_mmio.LYC_ADDRESS,
        ppu_mmio.WY_ADDRESS,
    }) |address| ledger.bytes[address] = final.system.bytes[address];
    @memcpy(
        ledger.bytes[runner.apu_mmio.FIRST_ADDRESS .. runner.apu_mmio.LAST_ADDRESS + 1],
        final.system.bytes[runner.apu_mmio.FIRST_ADDRESS .. runner.apu_mmio.LAST_ADDRESS + 1],
    );
}

fn stateFromFirst(events: []const ppu_binding.EventRow) ppu_binding.State {
    return .{
        .timing = events[0].transition.before,
        .lcdc = events[0].lcdc_before,
        .scy = events[0].latches_before[0],
        .scx = events[0].latches_before[1],
        .wy = events[0].latches_before[2],
    };
}

fn stateFromLast(events: []const ppu_binding.EventRow) ppu_binding.State {
    const last = events[events.len - 1];
    return .{
        .timing = last.transition.after,
        .lcdc = last.lcdc_after,
        .scy = last.latches_after[0],
        .scx = last.latches_after[1],
        .wy = last.latches_after[2],
    };
}

fn ppuAddress(register: ppu_binding.Register) u16 {
    return switch (register) {
        .lcdc => ppu_mmio.LCDC_ADDRESS,
        .stat => ppu_mmio.STAT_ADDRESS,
        .scy => ppu_mmio.SCY_ADDRESS,
        .scx => ppu_mmio.SCX_ADDRESS,
        .ly => ppu_mmio.LY_ADDRESS,
        .lyc => ppu_mmio.LYC_ADDRESS,
        .wy => ppu_mmio.WY_ADDRESS,
    };
}
