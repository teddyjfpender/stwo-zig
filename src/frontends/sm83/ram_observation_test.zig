const std = @import("std");
const cartridge_memory_lookup = @import("air/cartridge_memory_lookup.zig");
const memory = @import("memory.zig");
const observation = @import("ram_observation.zig");

test "region validation rejects every non-canonical or invalid shape" {
    try std.testing.expectError(
        error.EmptyObservation,
        observation.validate(&.{}),
    );
    try std.testing.expectError(
        error.ZeroLengthRegion,
        observation.validate(&.{.{
            .space = .system,
            .start = 0,
            .length = 0,
        }}),
    );
    try std.testing.expectError(
        error.NonCanonicalRegionOrder,
        observation.validate(&.{
            .{ .space = .system, .start = 0xc004, .length = 1 },
            .{ .space = .system, .start = 0xc002, .length = 1 },
        }),
    );
    try std.testing.expectError(
        error.NonCanonicalRegionOrder,
        observation.validate(&.{
            .{ .space = .sram, .start = 0, .length = 1 },
            .{ .space = .system, .start = 0xc000, .length = 1 },
        }),
    );
    try std.testing.expectError(
        error.NonCanonicalRegionOrder,
        observation.validate(&.{
            .{ .space = .system, .start = 0xc002, .length = 1 },
            .{ .space = .system, .start = 0xc002, .length = 1 },
        }),
    );
    try std.testing.expectError(
        error.OverlappingRegions,
        observation.validate(&.{
            .{ .space = .system, .start = 0xc001, .length = 4 },
            .{ .space = .system, .start = 0xc003, .length = 1 },
        }),
    );
    try std.testing.expectError(
        error.RegionOutOfBounds,
        observation.validate(&.{.{
            .space = .system,
            .start = cartridge_memory_lookup.SYSTEM_SIZE - 1,
            .length = 2,
        }}),
    );
    try std.testing.expectError(
        error.RegionOutOfBounds,
        observation.validate(&.{.{
            .space = .sram,
            .start = cartridge_memory_lookup.SRAM_SIZE - 1,
            .length = 2,
        }}),
    );
    try std.testing.expectError(
        error.RegionArithmeticOverflow,
        observation.validate(&.{.{
            .space = .system,
            .start = std.math.maxInt(u32),
            .length = 2,
        }}),
    );
}

test "region validation admits only canonical WRAM and physical SRAM" {
    try observation.validate(&.{
        .{ .space = .system, .start = 0xc000, .length = 0x2000 },
        .{ .space = .sram, .start = 0, .length = cartridge_memory_lookup.SRAM_SIZE },
    });

    const rejected_system_addresses = [_]u32{
        0x0000, // ROM
        0x8000, // VRAM
        0xa000, // logical cartridge SRAM
        0xe000, // WRAM echo
        0xfe00, // OAM
        0xfea0, // unusable
        0xff00, // MMIO
        0xff80, // HRAM
    };
    for (rejected_system_addresses) |start| {
        try std.testing.expectError(
            error.RegionOutsideObservationDomain,
            observation.validate(&.{.{
                .space = .system,
                .start = start,
                .length = 1,
            }}),
        );
    }
    try std.testing.expectError(
        error.RegionOutsideObservationDomain,
        observation.validate(&.{.{
            .space = .system,
            .start = 0xdfff,
            .length = 2,
        }}),
    );
}

test "digest binds canonical descriptors and only observed values" {
    var system = [_]u8{0} ** cartridge_memory_lookup.SYSTEM_SIZE;
    var sram = [_]u8{0} ** cartridge_memory_lookup.SRAM_SIZE;
    const regions = [_]observation.Region{
        .{ .space = .system, .start = 0xC000, .length = 2 },
        .{ .space = .sram, .start = 0x0100, .length = 2 },
    };

    const baseline = try observation.digest(makeImages(&system, &sram), &regions);

    const omitted = try observation.digest(
        makeImages(&system, &sram),
        regions[0..1],
    );
    try std.testing.expect(!std.mem.eql(u8, &baseline, &omitted));

    var descriptor_mutation = regions;
    descriptor_mutation[0].start += 1;
    const moved = try observation.digest(
        makeImages(&system, &sram),
        &descriptor_mutation,
    );
    try std.testing.expect(!std.mem.eql(u8, &baseline, &moved));

    system[0xC000] ^= 1;
    const system_mutation = try observation.digest(
        makeImages(&system, &sram),
        &regions,
    );
    try std.testing.expect(!std.mem.eql(u8, &baseline, &system_mutation));
    system[0xC000] ^= 1;

    sram[0x0101] ^= 1;
    const sram_mutation = try observation.digest(
        makeImages(&system, &sram),
        &regions,
    );
    try std.testing.expect(!std.mem.eql(u8, &baseline, &sram_mutation));
    sram[0x0101] ^= 1;

    system[0xBFFF] ^= 1;
    const outside_mutation = try observation.digest(
        makeImages(&system, &sram),
        &regions,
    );
    try std.testing.expectEqualSlices(u8, &baseline, &outside_mutation);
}

test "digest rejects malformed backing image shapes before slicing" {
    var system = [_]u8{0} ** cartridge_memory_lookup.SYSTEM_SIZE;
    var sram = [_]u8{0} ** cartridge_memory_lookup.SRAM_SIZE;
    const regions = [_]observation.Region{.{
        .space = .system,
        .start = cartridge_memory_lookup.SYSTEM_SIZE - 1,
        .length = 1,
    }};

    try std.testing.expectError(
        error.InvalidSystemMemoryShape,
        observation.digest(.{
            .system = .{ .bytes = system[0 .. system.len - 1] },
            .sram = .{ .bytes = &sram },
        }, &regions),
    );
    try std.testing.expectError(
        error.InvalidSramShape,
        observation.digest(.{
            .system = .{ .bytes = &system },
            .sram = .{ .bytes = sram[0 .. sram.len - 1] },
        }, &regions),
    );
}

fn makeImages(
    system: []const u8,
    sram: []const u8,
) cartridge_memory_lookup.Images {
    return .{
        .system = memory.Image.init(system) catch unreachable,
        .sram = cartridge_memory_lookup.SramImage.init(sram) catch unreachable,
    };
}
