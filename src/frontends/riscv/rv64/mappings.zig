//! Sorted, bounded permission ranges. Cached entries are values, never pointers
//! into a reallocating list. Mappings are append-only and cannot change rights.
const std = @import("std");
const types = @import("memory_types.zig");
const Entry = struct { first: u64, last: u64, permissions: types.Permissions };

pub const Mappings = struct {
    allocator: std.mem.Allocator,
    limits: types.Limits,
    entries: std.ArrayList(Entry) = .empty,
    mapped_bytes: u64 = 0,
    code_cache: ?Entry = null,
    data_cache: ?Entry = null,

    pub fn init(allocator: std.mem.Allocator, limits: types.Limits) Mappings {
        return .{ .allocator = allocator, .limits = limits };
    }

    pub fn deinit(self: *Mappings) void {
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn add(self: *Mappings, region: types.Region) types.Error!void {
        const last = try types.endAddress(region.start, region.size);
        if (self.entries.items.len >= self.limits.max_regions or
            region.size > self.limits.max_mapped_bytes - self.mapped_bytes) return error.ResourceLimit;
        const index = self.upperBound(region.start);
        if (index > 0 and self.entries.items[index - 1].last >= region.start) return error.OverlappingRegion;
        if (index < self.entries.items.len and self.entries.items[index].first <= last) return error.OverlappingRegion;
        try self.entries.insert(self.allocator, index, .{ .first = region.start, .last = last, .permissions = region.permissions });
        self.mapped_bytes += region.size;
    }

    pub fn check(self: *Mappings, address: u64, size: u64, access: types.Access) types.Error!void {
        const last = try types.endAddress(address, size);
        const cached = if (access == .execute) self.code_cache else self.data_cache;
        if (cached) |entry| {
            if (address >= entry.first and last <= entry.last) {
                if (!allows(entry.permissions, access)) return error.AccessDenied;
                return;
            }
        }
        var index = self.upperBound(address);
        if (index == 0) return error.UnmappedAddress;
        index -= 1;
        var cursor = address;
        while (index < self.entries.items.len) : (index += 1) {
            const entry = self.entries.items[index];
            if (cursor < entry.first or cursor > entry.last) return error.UnmappedAddress;
            if (!allows(entry.permissions, access)) return error.AccessDenied;
            if (entry.last >= last) {
                // Cache only an actual single range. Combining adjacent ranges
                // could accidentally grant a neighbour stronger permissions.
                if (cursor == address) {
                    if (access == .execute) self.code_cache = entry else self.data_cache = entry;
                }
                return;
            }
            cursor = entry.last + 1;
        }
        return error.UnmappedAddress;
    }

    /// First entry whose start is greater than address.
    fn upperBound(self: *const Mappings, address: u64) usize {
        var low: usize = 0;
        var high = self.entries.items.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            if (self.entries.items[mid].first <= address) low = mid + 1 else high = mid;
        }
        return low;
    }
};

fn allows(permissions: types.Permissions, access: types.Access) bool {
    return switch (access) {
        .read => permissions.read,
        .write => permissions.write,
        .execute => permissions.execute,
        .initialize => true,
    };
}
