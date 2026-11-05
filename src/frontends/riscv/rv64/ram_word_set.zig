//! First-pass RAM word keys only. No mutable guest values, instruction fetches,
//! register state or proof authority. Zero-valued words remain present.
const std = @import("std");
const Event = @import("ethereum_services/session.zig").Event;
const Retirement = @import("machine.zig").Retirement;
const Block = struct { page: u64, bits: [8]u64 = @splat(0) };
pub const Set = struct {
    allocator: std.mem.Allocator,
    max_words: usize,
    count: usize = 0,
    pages: std.AutoHashMapUnmanaged(u64, *Block) = .empty,
    blocks: std.ArrayList(*Block) = .empty,
    cache_pages: [32]u64 = @splat(std.math.maxInt(u64)),
    cache_blocks: [32]*Block = undefined,
    failure: ?anyerror = null,
    pub fn init(a: std.mem.Allocator, max_words: usize) !Set {
        if (max_words == 0 or max_words > 1 << 24) return error.InvalidRamWordSetLimit;
        return .{ .allocator = a, .max_words = max_words };
    }
    pub fn deinit(self: *Set) void {
        for (self.blocks.items) |block| self.allocator.destroy(block);
        self.blocks.deinit(self.allocator);
        self.pages.deinit(self.allocator);
        self.* = undefined;
    }
    pub fn mark(self: *Set, address: u64) !void {
        if (address & 7 != 0 or address > std.math.maxInt(u64) - 7) return error.InvalidRamWordAddress;
        const page = address >> 12;
        const cache: usize = @intCast(page & 31);
        const block = if (self.cache_pages[cache] == page) self.cache_blocks[cache] else blk: {
            const entry = try self.pages.getOrPut(self.allocator, page);
            if (!entry.found_existing) {
                errdefer _ = self.pages.remove(page);
                const fresh = try self.allocator.create(Block);
                errdefer self.allocator.destroy(fresh);
                fresh.* = .{ .page = page };
                try self.blocks.append(self.allocator, fresh);
                entry.value_ptr.* = fresh;
            }
            self.cache_pages[cache] = page;
            self.cache_blocks[cache] = entry.value_ptr.*;
            break :blk entry.value_ptr.*;
        };
        const index: usize = @intCast((address >> 3) & 511);
        const bit = @as(u64, 1) << @intCast(index & 63);
        if (block.bits[index >> 6] & bit != 0) return;
        if (self.count == self.max_words) return error.RamWordSetLimit;
        block.bits[index >> 6] |= bit;
        self.count += 1;
    }
    pub fn observeRetirement(self: *Set, row: Retirement) !void {
        if (row.memory) |effect| try self.mark(effect.address.toInt() & ~@as(u64, 7));
    }
    pub fn observeEvent(self: *Set, event: Event) !void {
        try @import("boundary_capture.zig").visitEventWordAddresses(event, self);
    }
    /// Source visitor contract. Both reads and writes create INITIAL cells.
    pub fn word(self: *Set, address: u64) !void {
        try self.mark(address);
    }
    pub fn sorted(self: *const Set, a: std.mem.Allocator) ![]u64 {
        const order = try a.dupe(*Block, self.blocks.items);
        defer a.free(order);
        std.mem.sort(*Block, order, {}, struct {
            fn less(_: void, x: *Block, y: *Block) bool {
                return x.page < y.page;
            }
        }.less);
        const keys = try a.alloc(u64, self.count);
        var at: usize = 0;
        for (order) |block| for (block.bits, 0..) |bits0, group| {
            var bits = bits0;
            while (bits != 0) : (bits &= bits - 1) {
                keys[at] = (block.page << 12) | ((group * 64 + @ctz(bits)) << 3);
                at += 1;
            }
        };
        std.debug.assert(at == keys.len);
        return keys;
    }
};

test "RAM first-pass page bitmap preserves zero keys boundaries duplicates and limits" {
    const a = std.testing.allocator;
    var set = try Set.init(a, 5);
    defer set.deinit();
    for ([_]u64{ 0, 4096, 4088, 8, 0, 1 << 44 }) |address| try set.mark(address);
    const keys = try set.sorted(a);
    defer a.free(keys);
    try std.testing.expectEqualSlices(u64, &.{ 0, 8, 4088, 4096, 1 << 44 }, keys);
    try std.testing.expectError(error.RamWordSetLimit, set.mark(16));
    try std.testing.expectError(error.InvalidRamWordAddress, set.mark(1));
    try set.mark(0);
    try std.testing.expectEqual(@as(usize, 5), set.count);
}

fn compareEvent(event: Event) !void {
    const a = std.testing.allocator;
    var memory = @import("memory.zig").Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = 0x1000, .size = 0x10000, .permissions = .{ .read = true, .write = true } });
    var capture = try @import("boundary_capture.zig").Capture.init(a, 0, 1, 1 << 20);
    defer capture.deinit();
    try capture.appendEvent(event, &memory);
    const cells = try capture.sorted(a);
    defer a.free(cells);
    var words = try Set.init(a, 1 << 20);
    defer words.deinit();
    try words.observeEvent(event);
    const keys = try words.sorted(a);
    defer a.free(keys);
    try std.testing.expectEqual(cells.len, keys.len);
    for (cells, keys) |cell, key| try std.testing.expectEqual(cell.address, key);
}

test "RAM-key service visitor equals complete source boundary cells for every family and variable range" {
    inline for (.{ "keccak", "secp", "sha256", "arith256_mod", "curve" }) |name| {
        var call: @FieldType(Event, name) = undefined;
        @memset(std.mem.asBytes(&call), 0);
        if (@hasField(@TypeOf(call), "kind")) call.kind = std.enums.values(@FieldType(@TypeOf(call), "kind"))[0];
        if (@hasField(@TypeOf(call), "op")) call.op = std.enums.values(@FieldType(@TypeOf(call), "op"))[0];
        call.clock = 1;
        call.pointer = 0x2000;
        if (@hasField(@TypeOf(call), "kind")) {
            for (std.enums.values(@FieldType(@TypeOf(call), "kind"))) |kind| {
                call.kind = kind;
                try compareEvent(@unionInit(Event, name, call));
            }
        } else if (@hasField(@TypeOf(call), "op")) {
            for (std.enums.values(@FieldType(@TypeOf(call), "op"))) |op| {
                call.op = op;
                try compareEvent(@unionInit(Event, name, call));
            }
        } else try compareEvent(@unionInit(Event, name, call));
    }
    const BM = @import("ethereum_services/bulk_memory.zig");
    const zeroes: [8]u64 = @splat(0);
    for (std.enums.values(BM.Kind)) |kind| {
        const packet = BM.Packet{ .dst = 0x4000, .word1 = switch (kind) {
            .memcpy => 0x6003,
            .memset => 0,
            .memcmp => 0x6000,
            .jumpdest => 0x8000,
        }, .len = 64, .examined = 3 };
        try compareEvent(.{ .bulk = .{ .call = .{ .clock = 1, .pc = 0x1000, .pointer = 0x2000, .tag = BM.tagOf(kind) }, .packet = packet, .dst_before = zeroes[0..if (kind == .memcmp or kind == .jumpdest) 1 else 8] } });
    }
    const Sponge = @import("ethereum_services/keccak_sponge.zig");
    for ([_]u64{ 0, 1, 8, 135, 136, 200 }) |len| for (0..8) |shift| {
        try compareEvent(.{ .sponge = .{ .call = .{ .clock = 1, .pc = 0x1000, .pointer = 0x2000 }, .packet = .{ .state = 0x4000, .input = 0x6000 + shift, .len = len, .flags = Sponge.FINALIZE | Sponge.FRESH }, .state_before = @splat(0) } });
    };
}
