//! Concrete RV64 memory contract shared by mappings and backing pages.
const std = @import("std");
pub const PAGE_SIZE: usize = 4096;
pub const Permissions = struct { read: bool = false, write: bool = false, execute: bool = false };
pub const Region = struct { start: u64, size: u64, permissions: Permissions };
pub const Limits = struct {
    max_mapped_bytes: u64 = 256 * 1024 * 1024,
    max_pages: usize = 65536,
    max_regions: usize = 256,
};
pub const Error = std.mem.Allocator.Error || error{ AddressOverflow, UnmappedAddress, AccessDenied, MisalignedAddress, OverlappingRegion, ResourceLimit, InvalidRegion };
pub const Access = enum { read, write, execute, initialize };
pub const Observed = struct { value: u64, before_word: u64, after_word: u64 };

pub fn endAddress(address: u64, size: u64) Error!u64 {
    if (size == 0) return error.InvalidRegion;
    return std.math.add(u64, address, size - 1) catch error.AddressOverflow;
}

pub fn aligned(address: u64, width: u4) Error!void {
    if (width != 1 and width != 2 and width != 4 and width != 8) return error.InvalidRegion;
    if (address & (@as(u64, width) - 1) != 0) return error.MisalignedAddress;
}

pub fn widthMask(width: u4) u64 {
    return @as(u64, std.math.maxInt(u64)) >> @as(u6, @intCast((8 - @as(u7, width)) * 8));
}
