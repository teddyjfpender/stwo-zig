const std = @import("std");
const cartridge = @import("cartridge/mod.zig");
const ppu_binding = @import("air/ppu_binding.zig");
const replay = @import("pokemon_checkpoint_replay.zig");
const runner = @import("runner/mod.zig");
const machine = @import("runner/machine.zig");

test "benchmark replay reaches the complete battle with bounded memory" {
    const corpus_root = std.posix.getenv("SM83_POKEMON_CORPUS") orelse
        return error.SkipZigTest;
    var session = try replay.Session.init(
        std.testing.allocator,
        corpus_root,
        .{ .profile = .benchmark, .rows = 1 << 18 },
    );
    defer session.deinit();
    var callbacks: usize = 0;
    var mcycles: u32 = 0;
    var actions: usize = 0;
    for (replay.BENCHMARK_VERIFIED_PREFIX, 0..) |expected, index| {
        var chunk = try session.next(expected);
        const summary = chunk.summary();
        callbacks += summary.callbacks;
        mcycles += summary.mcycles;
        actions += summary.actions;
        if (index + 1 == replay.BENCHMARK_VERIFIED_PREFIX.len)
            try replay.validateBenchmarkOutcome(
                chunk.input().final_images.system.bytes,
            );
        chunk.deinit();
    }
    const terminal = try session.finish();
    try std.testing.expectEqual(@as(usize, 601_239), callbacks);
    try std.testing.expectEqual(@as(u32, 1_505_332), mcycles);
    try std.testing.expectEqual(@as(usize, 33), actions);
    try std.testing.expectEqual(@as(usize, 3_228), terminal.lookahead_rows);
    try std.testing.expectEqual(@as(u32, 3_235), terminal.lookahead_mcycles);
    try std.testing.expectEqual(@as(usize, 601_240), terminal.oracle_records);
}

test "pinned battle chunks stream once with exact adjacent endpoints" {
    const corpus_root = std.posix.getenv("SM83_POKEMON_CORPUS") orelse
        return error.SkipZigTest;
    const ChainBoundary = struct {
        machine_state: machine.MachineState,
        mapper: cartridge.mbc3.State,
        system_digest: [32]u8,
        sram_digest: [32]u8,
        joypad: runner.joypad.State,
        timer: runner.timer.Timer,
        ppu: ppu_binding.State,
        apu: runner.apu_mmio.State,
        dma: runner.dma.State,
        mcycle: u32,
    };

    var session = try replay.Session.init(
        std.testing.allocator,
        corpus_root,
        .{},
    );
    defer session.deinit();
    var previous: ?ChainBoundary = null;
    for (replay.VERIFIED_PREFIX, 0..) |counts, index| {
        var chunk = try session.next(counts);
        errdefer chunk.deinit();
        const input = chunk.input();
        if (previous) |boundary| {
            try std.testing.expectEqual(
                boundary.machine_state,
                input.results[0].before,
            );
            try std.testing.expectEqual(
                boundary.mapper,
                input.results[0].mapper_before,
            );
            try std.testing.expectEqualSlices(
                u8,
                &boundary.system_digest,
                &digest(input.initial_images.system.bytes),
            );
            try std.testing.expectEqualSlices(
                u8,
                &boundary.sram_digest,
                &digest(input.initial_images.sram.bytes),
            );
            try std.testing.expectEqual(boundary.joypad, input.initial_joypad);
            try std.testing.expectEqual(boundary.timer, input.initial_timer);
            try std.testing.expectEqual(boundary.ppu, input.initial_ppu);
            try std.testing.expectEqual(boundary.apu, input.initial_apu);
            try std.testing.expectEqual(boundary.dma, input.initial_dma);
            try std.testing.expectEqual(boundary.mcycle, input.initial_mcycle);
        }
        const last = input.results[input.results.len - 1];
        previous = .{
            .machine_state = last.after,
            .mapper = last.mapper_after,
            .system_digest = digest(input.final_images.system.bytes),
            .sram_digest = digest(input.final_images.sram.bytes),
            .joypad = chunk.final.joypad,
            .timer = chunk.final.timer,
            .ppu = chunk.final.ppu,
            .apu = chunk.final.apu,
            .dma = chunk.final.dma,
            .mcycle = input.initial_mcycle + counts.mcycles,
        };
        try std.testing.expectEqual(index, chunk.summary().index);
        chunk.deinit();
    }
    const terminal = try session.finish();
    try std.testing.expectEqual(@as(usize, 7_468), terminal.lookahead_rows);
}

fn digest(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}
