//! Commitment to selected RAM regions at the final execution boundary.

const std = @import("std");
const cartridge_memory_lookup = @import("air/cartridge_memory_lookup.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const AddressSpace = enum(u8) {
    system,
    sram,
};

pub const Region = struct {
    space: AddressSpace,
    start: u32,
    length: u32,
};

pub const Error = error{
    InvalidSystemMemoryShape,
    InvalidSramShape,
    EmptyObservation,
    ZeroLengthRegion,
    RegionArithmeticOverflow,
    RegionOutOfBounds,
    RegionOutsideObservationDomain,
    NonCanonicalRegionOrder,
    OverlappingRegions,
    TooManyRegions,
};

const domain_tag = "stwo-zig/sm83/final-ram-observation/v1\x00";
const WRAM_START: u32 = 0xc000;
const WRAM_END: u32 = 0xe000;

pub fn validate(regions: []const Region) Error!void {
    if (regions.len == 0) return error.EmptyObservation;

    var previous: ?Region = null;
    var previous_end: u32 = 0;

    for (regions) |region| {
        if (region.length == 0) return error.ZeroLengthRegion;

        const end = std.math.add(u32, region.start, region.length) catch
            return error.RegionArithmeticOverflow;
        const limit: u32 = switch (region.space) {
            .system => cartridge_memory_lookup.SYSTEM_SIZE,
            .sram => cartridge_memory_lookup.SRAM_SIZE,
        };
        if (end > limit) return error.RegionOutOfBounds;
        // The mutable-memory relation canonicalizes echo accesses to WRAM
        // keys. Until device relations expose equally canonical observation
        // keys, public system observations are limited to canonical WRAM.
        if (region.space == .system and
            (region.start < WRAM_START or end > WRAM_END))
        {
            return error.RegionOutsideObservationDomain;
        }

        if (previous) |prior| {
            const prior_space = @intFromEnum(prior.space);
            const current_space = @intFromEnum(region.space);
            if (current_space < prior_space) return error.NonCanonicalRegionOrder;
            if (current_space == prior_space) {
                if (region.start <= prior.start) return error.NonCanonicalRegionOrder;
                if (region.start < previous_end) return error.OverlappingRegions;
            }
        }

        previous = region;
        previous_end = end;
    }
}

pub fn digest(
    images: cartridge_memory_lookup.Images,
    regions: []const Region,
) Error![Sha256.digest_length]u8 {
    if (images.system.bytes.len != cartridge_memory_lookup.SYSTEM_SIZE)
        return error.InvalidSystemMemoryShape;
    if (images.sram.bytes.len != cartridge_memory_lookup.SRAM_SIZE)
        return error.InvalidSramShape;

    try validate(regions);
    const region_count = std.math.cast(u32, regions.len) orelse
        return error.TooManyRegions;

    var hasher = Sha256.init(.{});
    hasher.update(domain_tag);
    updateU32(&hasher, region_count);

    for (regions) |region| {
        const space = [_]u8{@intFromEnum(region.space)};
        hasher.update(&space);
        updateU32(&hasher, region.start);
        updateU32(&hasher, region.length);

        const bytes = switch (region.space) {
            .system => images.system.bytes,
            .sram => images.sram.bytes,
        };
        const start: usize = @intCast(region.start);
        const end = start + @as(usize, @intCast(region.length));
        hasher.update(bytes[start..end]);
    }

    var result: [Sha256.digest_length]u8 = undefined;
    hasher.final(&result);
    return result;
}

fn updateU32(hasher: *Sha256, value: u32) void {
    var encoded: [4]u8 = undefined;
    std.mem.writeInt(u32, &encoded, value, .little);
    hasher.update(&encoded);
}
