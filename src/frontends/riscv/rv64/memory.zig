//! Concrete RV64 memory facade. Permission checks precede backing access.
const std = @import("std");
const types = @import("memory_types.zig");
const Mappings = @import("mappings.zig").Mappings;
const Pages = @import("pages.zig").Pages;
pub const PAGE_SIZE = types.PAGE_SIZE;
pub const Permissions = types.Permissions;
pub const Region = types.Region;
pub const Limits = types.Limits;
pub const Error = types.Error;
pub const Observed = types.Observed;
pub const endAddress = types.endAddress;

pub const Memory = struct {
    mappings: Mappings,
    backing: Pages,

    pub fn init(allocator: std.mem.Allocator, limits: Limits) Memory {
        return .{ .mappings = Mappings.init(allocator, limits), .backing = Pages.init(allocator, limits.max_pages) };
    }

    pub fn deinit(self: *Memory) void {
        self.backing.deinit();
        self.mappings.deinit();
        self.* = undefined;
    }

    pub fn map(self: *Memory, region: Region) Error!void {
        try self.mappings.add(region);
    }

    pub fn pageCount(self: *const Memory) usize {
        return self.backing.table.count();
    }

    pub fn load(self: *Memory, address: u64, width: u4) Error!u64 {
        return (try self.loadObserved(address, width)).value;
    }

    pub fn loadObserved(self: *Memory, address: u64, width: u4) Error!Observed {
        try types.aligned(address, width);
        try self.mappings.check(address, width, .read);
        return self.backing.load(address, width);
    }

    pub fn fetch(self: *Memory, address: u64) Error!u32 {
        try types.aligned(address, 4);
        try self.mappings.check(address, 4, .execute);
        return @intCast(self.backing.load(address, 4).value);
    }

    pub fn store(self: *Memory, address: u64, width: u4, value: u64) Error!void {
        _ = try self.storeObserved(address, width, value);
    }

    pub fn storeObserved(self: *Memory, address: u64, width: u4, value: u64) Error!Observed {
        try types.aligned(address, width);
        try self.mappings.check(address, width, .write);
        return self.backing.store(address, width, value);
    }

    /// Loader/host only. Guest writes must use store's permission checks.
    pub fn initialize(self: *Memory, address: u64, bytes: []const u8) Error!void {
        if (bytes.len == 0) return;
        try self.mappings.check(address, bytes.len, .initialize);
        try self.backing.initialize(address, bytes);
    }
};
