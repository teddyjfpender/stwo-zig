//! Byte-addressable sparse memory for RISC-V execution.
//!
//! The 32-bit address space is split into 64 KiB pages. A flat page table makes
//! the fetch/load hot path two indexed loads instead of four hash lookups, while
//! pages remain sparse and untouched bytes retain the architectural value zero.

const std = @import("std");

const PAGE_BITS = 16;
const PAGE_SIZE = 1 << PAGE_BITS;
const PAGE_COUNT = 1 << (32 - PAGE_BITS);
const PAGE_MASK = PAGE_SIZE - 1;
const Page = [PAGE_SIZE]u8;

pub const Memory = struct {
    pages: []?*Page,
    initialized_words: std.AutoHashMap(u32, void),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Memory {
        return initFallible(allocator) catch @panic("Memory.init: allocation failed");
    }

    /// Fallible constructor used by transactional extension execution.
    pub fn initFallible(allocator: std.mem.Allocator) error{OutOfMemory}!Memory {
        const pages = try allocator.alloc(?*Page, PAGE_COUNT);
        @memset(pages, null);
        return .{
            .pages = pages,
            .initialized_words = std.AutoHashMap(u32, void).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Memory) void {
        for (self.pages) |maybe_page| {
            if (maybe_page) |page| self.allocator.destroy(page);
        }
        self.allocator.free(self.pages);
        self.initialized_words.deinit();
        self.* = undefined;
    }

    /// Add every initialized aligned word address without exposing the memory
    /// representation to commitment consumers.
    pub fn addAlignedWordAddresses(
        self: *const Memory,
        addresses: *std.AutoHashMap(u32, void),
    ) !void {
        var iterator = self.initialized_words.keyIterator();
        while (iterator.next()) |addr| try addresses.put(addr.*, {});
    }

    // ----- Byte access -----

    pub inline fn readByte(self: *const Memory, addr: u32) u8 {
        const page = self.pages[pageIndex(addr)] orelse return 0;
        return page[pageOffset(addr)];
    }

    pub fn writeByte(self: *Memory, addr: u32, val: u8) void {
        const page = self.ensurePage(addr);
        page[pageOffset(addr)] = val;
        self.markInitializedRange(addr, 1);
    }

    // ----- 16-bit little-endian access -----

    pub inline fn readU16(self: *const Memory, addr: u32) u16 {
        const offset = pageOffset(addr);
        if (offset <= PAGE_SIZE - 2) {
            const page = self.pages[pageIndex(addr)] orelse return 0;
            return @as(u16, page[offset]) |
                (@as(u16, page[offset + 1]) << 8);
        }
        return @as(u16, self.readByte(addr)) |
            (@as(u16, self.readByte(addr +% 1)) << 8);
    }

    pub fn writeU16(self: *Memory, addr: u32, val: u16) void {
        const offset = pageOffset(addr);
        if (offset <= PAGE_SIZE - 2) {
            const page = self.ensurePage(addr);
            page[offset] = @truncate(val);
            page[offset + 1] = @truncate(val >> 8);
            self.markInitializedRange(addr, 2);
            return;
        }
        self.writeByte(addr, @truncate(val));
        self.writeByte(addr +% 1, @truncate(val >> 8));
    }

    // ----- 32-bit little-endian access -----

    pub inline fn readU32(self: *const Memory, addr: u32) u32 {
        const offset = pageOffset(addr);
        if (offset <= PAGE_SIZE - 4) {
            const page = self.pages[pageIndex(addr)] orelse return 0;
            return @as(u32, page[offset]) |
                (@as(u32, page[offset + 1]) << 8) |
                (@as(u32, page[offset + 2]) << 16) |
                (@as(u32, page[offset + 3]) << 24);
        }
        return @as(u32, self.readByte(addr)) |
            (@as(u32, self.readByte(addr +% 1)) << 8) |
            (@as(u32, self.readByte(addr +% 2)) << 16) |
            (@as(u32, self.readByte(addr +% 3)) << 24);
    }

    pub fn writeU32(self: *Memory, addr: u32, val: u32) void {
        const offset = pageOffset(addr);
        if (offset <= PAGE_SIZE - 4) {
            const page = self.ensurePage(addr);
            page[offset] = @truncate(val);
            page[offset + 1] = @truncate(val >> 8);
            page[offset + 2] = @truncate(val >> 16);
            page[offset + 3] = @truncate(val >> 24);
            self.markInitializedRange(addr, 4);
            return;
        }
        self.writeByte(addr, @truncate(val));
        self.writeByte(addr +% 1, @truncate(val >> 8));
        self.writeByte(addr +% 2, @truncate(val >> 16));
        self.writeByte(addr +% 3, @truncate(val >> 24));
    }

    /// Reserve initialized-word capacity and materialize every sparse page
    /// required by a later aligned-word commit. Added zero pages are logically
    /// invisible if a subsequent prepare step fails.
    pub fn prepareAlignedWordWrites(
        self: *Memory,
        addresses: []const u32,
    ) error{OutOfMemory}!void {
        var missing_words: usize = 0;
        for (addresses) |addr| {
            std.debug.assert(addr & 3 == 0);
            if (!self.initialized_words.contains(addr)) missing_words += 1;
        }
        try self.initialized_words.ensureUnusedCapacity(@intCast(missing_words));

        for (addresses) |addr| {
            const index = pageIndex(addr);
            if (self.pages[index] != null) continue;
            const page = try self.allocator.create(Page);
            @memset(page, 0);
            self.pages[index] = page;
        }
    }

    /// Whether one later `writeU32AssumePrepared` is guaranteed not to
    /// allocate. Retirement transactions use this read-only predicate to keep
    /// the common store path out of both the allocator and the reserve helper.
    pub inline fn alignedWordWriteIsPrepared(
        self: *const Memory,
        addr: u32,
    ) bool {
        if (addr & 3 != 0 or self.pages[pageIndex(addr)] == null) return false;
        if (self.initialized_words.contains(addr)) return true;
        const maximum_entries = self.initialized_words.capacity() *
            std.hash_map.default_max_load_percentage / 100;
        return maximum_entries - self.initialized_words.count() >= 1;
    }

    /// Commit one aligned write after `prepareAlignedWordWrites` covered its
    /// address. This path contains no allocator call and cannot fail.
    pub fn writeU32AssumePrepared(self: *Memory, addr: u32, val: u32) void {
        std.debug.assert(addr & 3 == 0);
        const page = self.pages[pageIndex(addr)] orelse unreachable;
        const offset = pageOffset(addr);
        page[offset] = @truncate(val);
        page[offset + 1] = @truncate(val >> 8);
        page[offset + 2] = @truncate(val >> 16);
        page[offset + 3] = @truncate(val >> 24);
        self.initialized_words.putAssumeCapacity(addr, {});
    }

    // ----- Bulk access -----

    /// Copy a contiguous slice of bytes into memory starting at `base_addr`.
    pub fn loadSegment(self: *Memory, base_addr: u32, segment: []const u8) void {
        self.writeBytes(base_addr, segment);
    }

    /// Materialize a zero-initialized ELF range. Presence matters to the
    /// memory commitment even when the guest never accesses the bytes.
    pub fn loadZeroes(self: *Memory, base_addr: u32, len: u32) void {
        self.markInitializedRange(base_addr, len);
        var remaining: usize = len;
        var addr = base_addr;
        while (remaining != 0) {
            const offset = pageOffset(addr);
            const chunk_len = @min(remaining, PAGE_SIZE - offset);
            if (self.pages[pageIndex(addr)]) |page| {
                @memset(page[offset .. offset + chunk_len], 0);
            }
            addr +%= @intCast(chunk_len);
            remaining -= chunk_len;
        }
    }

    /// Read `buf.len` bytes from guest memory starting at `addr` into `buf`.
    pub fn readSlice(self: *const Memory, base_addr: u32, buf: []u8) void {
        var remaining = buf;
        var addr = base_addr;
        while (remaining.len != 0) {
            const offset = pageOffset(addr);
            const chunk_len = @min(remaining.len, PAGE_SIZE - offset);
            if (self.pages[pageIndex(addr)]) |page| {
                @memcpy(remaining[0..chunk_len], page[offset .. offset + chunk_len]);
            } else {
                @memset(remaining[0..chunk_len], 0);
            }
            addr +%= @intCast(chunk_len);
            remaining = remaining[chunk_len..];
        }
    }

    /// Write `data` bytes into guest memory starting at `addr`.
    pub fn writeSlice(self: *Memory, base_addr: u32, data: []const u8) void {
        self.writeBytes(base_addr, data);
    }

    fn writeBytes(self: *Memory, base_addr: u32, data: []const u8) void {
        self.markInitializedRange(base_addr, data.len);
        var remaining = data;
        var addr = base_addr;
        while (remaining.len != 0) {
            const offset = pageOffset(addr);
            const chunk_len = @min(remaining.len, PAGE_SIZE - offset);
            const page = self.ensurePage(addr);
            @memcpy(page[offset .. offset + chunk_len], remaining[0..chunk_len]);
            addr +%= @intCast(chunk_len);
            remaining = remaining[chunk_len..];
        }
    }

    fn ensurePage(self: *Memory, addr: u32) *Page {
        const index = pageIndex(addr);
        if (self.pages[index]) |page| return page;
        const page = self.allocator.create(Page) catch
            @panic("Memory.ensurePage: allocation failed");
        @memset(page, 0);
        self.pages[index] = page;
        return page;
    }

    fn markInitializedRange(self: *Memory, base_addr: u32, len: usize) void {
        var remaining = len;
        var addr = base_addr;
        while (remaining != 0) {
            self.initialized_words.put(addr & ~@as(u32, 3), {}) catch
                @panic("Memory: initialized-word allocation failed");
            const advance = @min(remaining, 4 - @as(usize, @intCast(addr & 3)));
            addr +%= @intCast(advance);
            remaining -= advance;
        }
    }

    inline fn pageIndex(addr: u32) usize {
        return @intCast(addr >> PAGE_BITS);
    }

    inline fn pageOffset(addr: u32) usize {
        return @intCast(addr & PAGE_MASK);
    }
};

test "Memory readU32/writeU32 roundtrip" {
    var mem = Memory.init(std.testing.allocator);
    defer mem.deinit();

    mem.writeU32(0x1000, 0xDEAD_BEEF);
    try std.testing.expectEqual(@as(u32, 0xDEAD_BEEF), mem.readU32(0x1000));
}

test "Memory byte-level access" {
    var mem = Memory.init(std.testing.allocator);
    defer mem.deinit();

    mem.writeByte(0x10, 0xAB);
    try std.testing.expectEqual(@as(u8, 0xAB), mem.readByte(0x10));
}

test "Memory readByte returns 0 for untouched addresses" {
    var mem = Memory.init(std.testing.allocator);
    defer mem.deinit();

    try std.testing.expectEqual(@as(u8, 0), mem.readByte(0x42));
}

test "Memory little-endian byte order" {
    var mem = Memory.init(std.testing.allocator);
    defer mem.deinit();

    mem.writeU32(0x100, 0x04030201);
    try std.testing.expectEqual(@as(u8, 0x01), mem.readByte(0x100));
    try std.testing.expectEqual(@as(u8, 0x02), mem.readByte(0x101));
    try std.testing.expectEqual(@as(u8, 0x03), mem.readByte(0x102));
    try std.testing.expectEqual(@as(u8, 0x04), mem.readByte(0x103));
}

test "Memory readU16/writeU16 roundtrip" {
    var mem = Memory.init(std.testing.allocator);
    defer mem.deinit();

    mem.writeU16(0x200, 0xBEEF);
    try std.testing.expectEqual(@as(u16, 0xBEEF), mem.readU16(0x200));
}

test "Memory accesses preserve wrapping page-boundary semantics" {
    var mem = Memory.init(std.testing.allocator);
    defer mem.deinit();

    mem.writeU32(0xFFFF_FFFE, 0x0403_0201);
    try std.testing.expectEqual(@as(u32, 0x0403_0201), mem.readU32(0xFFFF_FFFE));
    try std.testing.expectEqual(@as(u8, 0x03), mem.readByte(0));
    try std.testing.expectEqual(@as(u8, 0x04), mem.readByte(1));
}

test "Memory prepared aligned writes commit without lazy allocation" {
    var mem = try Memory.initFallible(std.testing.allocator);
    defer mem.deinit();
    const addresses = [_]u32{ 0x0000_fffc, 0x0001_0000 };
    try std.testing.expect(!mem.alignedWordWriteIsPrepared(addresses[0]));
    try std.testing.expect(!mem.alignedWordWriteIsPrepared(addresses[1]));
    try std.testing.expect(!mem.alignedWordWriteIsPrepared(addresses[0] + 1));
    try mem.prepareAlignedWordWrites(&addresses);
    try std.testing.expect(mem.alignedWordWriteIsPrepared(addresses[0]));
    try std.testing.expect(mem.alignedWordWriteIsPrepared(addresses[1]));
    mem.writeU32AssumePrepared(addresses[0], 0x0403_0201);
    mem.writeU32AssumePrepared(addresses[1], 0x0807_0605);
    try std.testing.expectEqual(@as(u32, 0x0403_0201), mem.readU32(addresses[0]));
    try std.testing.expectEqual(@as(u32, 0x0807_0605), mem.readU32(addresses[1]));
}
