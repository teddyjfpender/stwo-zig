//! Immutable RAM permission authority for the prospective value-only root.
//! A receiver builds this from independently admitted ELF/ABI mappings once.
//! Certificates may undergrant rights; they can never grant unavailable access.
const std = @import("std");
const Memory = @import("../../memory.zig").Memory;
pub const VERSION = 2;
pub const MAX_REGIONS = 256;
pub const Region = struct { first: u64, last: u64, flags: u3 };
pub const Grant = struct { first: u64, last: u64, mask: u2 };
pub const Span = enum {
    word8,
    chunk512,
    page4096,
    pub fn bytes(self: Span) u64 {
        return switch (self) {
            .word8 => 8,
            .chunk512 => 512,
            .page4096 => 4096,
        };
    }
    pub fn log(self: Span) u32 {
        return switch (self) {
            .word8 => 3,
            .chunk512 => 9,
            .page4096 => 12,
        };
    }
};

const GrantIterator = struct {
    regions: []const Region,
    mask: u3 = 1,
    cursor: usize = 0,
    pending: ?Grant = null,
    fn next(self: *GrantIterator) ?Grant {
        while (self.mask <= 3) {
            var result = self.pending;
            self.pending = null;
            while (self.cursor < self.regions.len) {
                const region = self.regions[self.cursor];
                self.cursor += 1;
                if (region.flags & self.mask != self.mask) continue;
                const grant = Grant{ .first = region.first, .last = region.last, .mask = @intCast(self.mask) };
                if (result) |*prior| {
                    if (prior.last != std.math.maxInt(u64) and prior.last + 1 == grant.first) {
                        prior.last = grant.last;
                    } else {
                        self.pending = grant;
                        return result;
                    }
                } else result = grant;
            }
            self.mask += 1;
            self.cursor = 0;
            if (result) |grant| return grant;
        }
        return null;
    }
};

pub const Policy = struct {
    allocator: std.mem.Allocator,
    regions: []Region,
    grants: []Grant,
    identity: [32]u8,

    pub fn init(a: std.mem.Allocator, supplied: []const Region) !Policy {
        try validateRegions(supplied);
        const regions = try a.dupe(Region, supplied);
        errdefer a.free(regions);
        var grants: std.ArrayList(Grant) = .empty;
        errdefer grants.deinit(a);
        var iterator = GrantIterator{ .regions = regions };
        while (iterator.next()) |grant| try grants.append(a, grant);
        return .{ .allocator = a, .regions = regions, .grants = try grants.toOwnedSlice(a), .identity = identityOf(regions) };
    }

    pub fn fromMemory(a: std.mem.Allocator, memory: *const Memory) !Policy {
        var regions: [MAX_REGIONS]Region = undefined;
        const source = memory.mappings.entries.items;
        if (source.len > MAX_REGIONS) return error.RamPolicyResourceLimit;
        for (source, regions[0..source.len]) |entry, *region| region.* = .{
            .first = entry.first,
            .last = entry.last,
            .flags = @as(u3, @intFromBool(entry.permissions.read)) | (@as(u3, @intFromBool(entry.permissions.write)) << 1) | (@as(u3, @intFromBool(entry.permissions.execute)) << 2),
        };
        return init(a, regions[0..source.len]);
    }

    pub fn validate(self: *const Policy) !void {
        try validateRegions(self.regions);
        if (!std.meta.eql(identityOf(self.regions), self.identity)) return error.RamPolicyIdentityMismatch;
        var iterator = GrantIterator{ .regions = self.regions };
        var index: usize = 0;
        while (iterator.next()) |grant| : (index += 1) {
            if (index >= self.grants.len or !std.meta.eql(grant, self.grants[index])) return error.NoncanonicalRamPolicyGrants;
        }
        if (index != self.grants.len) return error.NoncanonicalRamPolicyGrants;
    }

    /// Admission for the immutable-ROM execution profile only. The generic
    /// permission primitive/native memory may still represent RWX mappings.
    pub fn validateImmutableExecution(self: *const Policy) !void {
        try self.validate();
        for (self.regions) |region| if ((region.flags & 6) == 6) return error.WritableExecutableRv64Policy;
    }

    pub fn find(self: *const Policy, span: Span, address: u64, mask: u2) !usize {
        if (mask == 0) return error.EmptyRamPolicyGrant;
        if (address & (span.bytes() - 1) != 0) return error.MisalignedRamPolicySpan;
        const last = try std.math.add(u64, address, span.bytes() - 1);
        for (self.grants, 0..) |grant, index| {
            if (grant.mask == mask and grant.first <= address and last <= grant.last) return index;
        }
        return error.RamPolicyAccessDenied;
    }

    pub fn deinit(self: *Policy) void {
        self.allocator.free(self.regions);
        self.allocator.free(self.grants);
        self.* = undefined;
    }
};

fn validateRegions(regions: []const Region) !void {
    if (regions.len > MAX_REGIONS) return error.RamPolicyResourceLimit;
    for (regions, 0..) |region, i| {
        if (region.first > region.last or (i > 0 and regions[i - 1].last >= region.first)) return error.NoncanonicalRamPolicyRegions;
    }
}

fn identityOf(regions: []const Region) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("RV64 immutable RAM mapping policy v2\x00");
    var count: [4]u8 = undefined;
    std.mem.writeInt(u32, &count, @intCast(regions.len), .little);
    hasher.update(&count);
    for (regions) |region| {
        var bytes: [17]u8 = undefined;
        std.mem.writeInt(u64, bytes[0..8], region.first, .little);
        std.mem.writeInt(u64, bytes[8..16], region.last, .little);
        bytes[16] = region.flags;
        hasher.update(&bytes);
    }
    return hasher.finalResult();
}
