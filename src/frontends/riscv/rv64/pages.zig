//! Sparse backing with four tagged page-cache entries and transactional growth.
//! Page pointers remain stable until deinit. Missing pages are never cached.
const std = @import("std");
const types = @import("memory_types.zig");
const Page = [types.PAGE_SIZE]u8;
const Cached = struct { index: u64 = 0, page: ?*Page = null };
const Pending = struct { index: u64, page: *Page };

pub const Pages = struct {
    allocator: std.mem.Allocator,
    max_pages: usize,
    table: std.AutoHashMap(u64, *Page),
    cache: [4]Cached = @splat(.{}),

    pub fn init(allocator: std.mem.Allocator, limit: usize) Pages {
        return .{ .allocator = allocator, .max_pages = limit, .table = std.AutoHashMap(u64, *Page).init(allocator) };
    }

    pub fn deinit(self: *Pages) void {
        var it = self.table.valueIterator();
        while (it.next()) |page| self.allocator.destroy(page.*);
        self.table.deinit();
        self.* = undefined;
    }

    fn lookup(self: *Pages, index: u64) ?*Page {
        const slot = &self.cache[@intCast((index ^ (index >> 17) ^ (index >> 32)) & 3)];
        if (slot.page != null and slot.index == index) return slot.page;
        const page = self.table.get(index) orelse return null;
        slot.* = .{ .index = index, .page = page };
        return page;
    }

    pub fn load(self: *Pages, address: u64, width: u4) types.Observed {
        const page = self.lookup(address / types.PAGE_SIZE) orelse return .{ .value = 0, .before_word = 0, .after_word = 0 };
        const offset: usize = @intCast(address % types.PAGE_SIZE);
        const before = std.mem.readInt(u64, page[(offset & ~@as(usize, 7))..][0..8], .little);
        const shift: u6 = @intCast((offset & 7) * 8);
        return .{ .value = (before >> shift) & types.widthMask(width), .before_word = before, .after_word = before };
    }

    pub fn store(self: *Pages, address: u64, width: u4, value: u64) types.Error!types.Observed {
        const page = try self.ensureOne(address / types.PAGE_SIZE);
        const offset: usize = @intCast(address % types.PAGE_SIZE);
        const bytes = page[(offset & ~@as(usize, 7))..][0..8];
        const before = std.mem.readInt(u64, bytes, .little);
        const shift: u6 = @intCast((offset & 7) * 8);
        const mask = types.widthMask(width);
        const after = (before & ~(mask << shift)) | ((value & mask) << shift);
        std.mem.writeInt(u64, bytes, after, .little);
        return .{ .value = value & mask, .before_word = before, .after_word = after };
    }

    fn ensureOne(self: *Pages, index: u64) types.Error!*Page {
        if (self.lookup(index)) |page| return page;
        if (self.table.count() >= self.max_pages) return error.ResourceLimit;
        const page = try self.allocator.create(Page);
        errdefer self.allocator.destroy(page);
        try self.table.ensureUnusedCapacity(1);
        @memset(page, 0);
        self.table.putAssumeCapacity(index, page);
        return self.lookup(index).?;
    }

    pub fn initialize(self: *Pages, address: u64, bytes: []const u8) types.Error!void {
        const last = try types.endAddress(address, bytes.len);
        try self.reserve(address / types.PAGE_SIZE, last / types.PAGE_SIZE);
        var copied: usize = 0;
        while (copied < bytes.len) {
            const current = address + copied;
            const page = self.lookup(current / types.PAGE_SIZE).?;
            const offset: usize = @intCast(current % types.PAGE_SIZE);
            const count = @min(bytes.len - copied, types.PAGE_SIZE - offset);
            @memcpy(page[offset..][0..count], bytes[copied..][0..count]);
            copied += count;
        }
    }

    /// The caller validates alignment/permissions and supplies disjoint words.
    /// Reserve the entire span before publishing any byte change.
    pub fn storeWords(self: *Pages, address: u64, words: []const u64) types.Error!void {
        const bytes = std.math.mul(u64, words.len, 8) catch return error.AddressOverflow;
        const last = try types.endAddress(address, bytes);
        try self.reserve(address / types.PAGE_SIZE, last / types.PAGE_SIZE);
        for (words, 0..) |word, i| {
            const current = address + i * 8;
            const page = self.lookup(current / types.PAGE_SIZE).?;
            const offset: usize = @intCast(current % types.PAGE_SIZE);
            std.mem.writeInt(u64, page[offset..][0..8], word, .little);
        }
    }

    /// Allocate unpublished pages first; publish all pages only when every
    /// allocation and hash-table reservation has succeeded. Failure changes
    /// neither table membership nor architectural bytes.
    fn reserve(self: *Pages, first: u64, last: u64) types.Error!void {
        var missing: usize = 0;
        var only_index: u64 = 0;
        var index = first;
        while (true) : (index += 1) {
            if (!self.table.contains(index)) {
                missing += 1;
                only_index = index;
            }
            if (index == last) break;
        }
        if (missing > self.max_pages - self.table.count() or missing > std.math.maxInt(u32) - self.table.count()) return error.ResourceLimit;
        if (missing == 0) return;
        if (missing == 1) {
            _ = try self.ensureOne(only_index);
            return;
        }
        const pending = try self.allocator.alloc(Pending, missing);
        defer self.allocator.free(pending);
        var prepared: usize = 0;
        errdefer for (pending[0..prepared]) |item| self.allocator.destroy(item.page);
        index = first;
        while (true) : (index += 1) {
            if (!self.table.contains(index)) {
                const page = try self.allocator.create(Page);
                @memset(page, 0);
                pending[prepared] = .{ .index = index, .page = page };
                prepared += 1;
            }
            if (index == last) break;
        }
        try self.table.ensureUnusedCapacity(@intCast(missing));
        for (pending) |item| self.table.putAssumeCapacity(item.index, item.page);
    }
};
