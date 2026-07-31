const std = @import("std");
const subject = @import("dma_memory_lookup.zig");
const binding = @import("dma_binding.zig");
const dma = @import("../runner/dma.zig");
const memory_lookup = @import("cartridge_memory_lookup.zig");
const memory_clock = @import("cartridge_memory_clock.zig");

test "DMA memory lookup emits ordered source read and OAM write" {
    const event = try transferEvent(10, 0xc0, 0, 0x42);
    const predecessors = subject.Predecessors{
        .source = .{ .clock = 7, .value = 0x42 },
        .destination = .{ .clock = 9, .value = 0x99 },
    };
    const accesses = try subject.accessesForEvent(event, predecessors);
    const clock = try memory_clock.phaseClock(10, memory_clock.DMA_PHASE);
    try std.testing.expectEqual(clock, accesses.source.clock);
    try std.testing.expectEqual(@as(u17, 0xc000), accesses.source.address);
    try std.testing.expectEqual(@as(u8, 0x42), accesses.source.next_value);
    try std.testing.expectEqual(@as(u17, 0xfe00), accesses.destination.address);
    try std.testing.expectEqual(@as(u8, 0x99), accesses.destination.previous_value);
    try std.testing.expectEqual(@as(u8, 0x42), accesses.destination.next_value);

    var witness = try subject.generateWitness(
        std.testing.allocator,
        4,
        &.{event},
        &.{predecessors},
    );
    defer witness.deinit();
    const relation = memory_lookup.Relation.dummy();
    var interaction = try subject.generateInteraction(
        std.testing.allocator,
        witness.accesses,
        4,
        relation,
    );
    defer interaction.deinit();
    try std.testing.expect(!interaction.claims[0].isZero());
    try std.testing.expect(!interaction.claims[1].isZero());
}

test "DMA memory lookup fails closed for ROM SRAM and predecessor drift" {
    const rom = try transferEvent(0, 0x00, 0, 1);
    try std.testing.expectError(
        error.UnsupportedDmaSourceRegion,
        subject.accessesForEvent(rom, .{
            .source = .{ .value = 1 },
        }),
    );
    const sram = try transferEvent(0, 0xa0, 0, 1);
    try std.testing.expectError(
        error.UnsupportedDmaSourceRegion,
        subject.accessesForEvent(sram, .{
            .source = .{ .value = 1 },
        }),
    );
    const wram = try transferEvent(0, 0xc0, 0, 0x55);
    try std.testing.expectError(
        error.InvalidDmaSourceValue,
        subject.accessesForEvent(wram, .{
            .source = .{ .value = 0x54 },
        }),
    );
    try std.testing.expectError(
        error.InvalidDmaPredecessorCount,
        subject.generateWitness(
            std.testing.allocator,
            4,
            &.{wram},
            &.{},
        ),
    );
}

test "DMA memory lookup accepts VRAM and E-page WRAM alias sources" {
    const vram = try transferEvent(4, 0x80, 3, 0xaa);
    const vram_access = try subject.accessesForEvent(vram, .{
        .source = .{ .value = 0xaa },
    });
    try std.testing.expectEqual(@as(u17, 0x8003), vram_access.source.address);

    const alias = try transferEvent(5, 0xe0, 4, 0xbb);
    const alias_access = try subject.accessesForEvent(alias, .{
        .source = .{ .value = 0xbb },
    });
    try std.testing.expectEqual(@as(u17, 0xc004), alias_access.source.address);
}

fn transferEvent(
    mcycle: u32,
    page: u8,
    copied: u8,
    value: u8,
) !binding.EventRow {
    const before = dma.State{
        .clock = mcycle,
        .page = page,
        .copied = copied,
        .phase = .transfer,
    };
    return .{
        .mcycle = mcycle,
        .transition = try dma.Transition.apply(
            before,
            .{ .transfer = value },
        ),
        .provenance = .{ .execution_row = 0, .cycle = 0 },
    };
}
