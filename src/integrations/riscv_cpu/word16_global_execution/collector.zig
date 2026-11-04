//! Narrow cross-shard predecessor hints from captured CPU effects, never VM/P2.
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
const X = A.memory.load_store_v2;
const R = A.memory.closed_ram;
const CPU = @import("../word16_execution/cpu_source.zig");
const Public = @import("../word16_execution/memory/statement.zig");
pub const StateTable = @import("ledger_table.zig").StateTable;
const ImageOwner = @import("../word16_execution/expected_image.zig").Owner;
const PageTable = @FieldType(@FieldType(@FieldType(@FieldType(ImageOwner, "loaded"), "memory"), "backing"), "table");
const PAGE_SIZE: u64 = @import("stwo_riscv_frontend").rv64.memory.PAGE_SIZE;
/// First-touch word state `{initialWord, wordRights}` of `Public.fromOwner(owner)`,
/// computed once per guest page instead of per word (a page-table lookup and
/// eight first-match region scans each). Exact: it answers only aligned words
/// in pages whose every byte has the same first-matching policy region (or
/// none), where `wordRights` is that region's rights; otherwise null and the
/// caller takes the image path (including all of its errors). Values are read
/// from the same page bytes `Owner.initialWord` reads. Producer speed only.
pub const OwnerPages = struct {
    owner: *const ImageOwner,
    index: u64 = std.math.maxInt(u64),
    page: ?@FieldType(PageTable.KV, "value") = null,
    rights: ?u2 = null,
    pub fn lookup(self: *OwnerPages, address: u64) ?R.types.State {
        if (address & 7 != 0 or address > std.math.maxInt(u64) - 7) return null;
        const index = address / PAGE_SIZE;
        if (index != self.index) {
            self.index = index;
            self.page = self.owner.loaded.memory.backing.table.get(index);
            self.rights = uniformRights(self.owner.policy.regions, index * PAGE_SIZE, index * PAGE_SIZE + (PAGE_SIZE - 1));
        }
        const rights = self.rights orelse return null;
        const offset: usize = @intCast(address % PAGE_SIZE);
        const value = if (self.page) |page| std.mem.readInt(u64, page[offset..][0..8], .little) else 0;
        return .{ .value = value, .rights = rights };
    }
};
/// The rights every address in [lo, hi] gets under first-match region lookup
/// (`statement.zig` Callbacks.rights), or null when they differ.
pub fn uniformRights(regions: anytype, lo: u64, hi: u64) ?u2 {
    for (regions) |region| {
        if (region.last < lo or region.first > hi) continue;
        // First region touching the range: it must cover all of it.
        if (region.first <= lo and hi <= region.last) return @intCast(region.flags & 3);
        return null;
    }
    return 0;
}
test "uniform page rights follow first-match region order" {
    const Region = struct { first: u64, last: u64, flags: u3 };
    const regions = [_]Region{ .{ .first = 0x1000, .last = 0x1fff, .flags = 1 }, .{ .first = 0x0, .last = 0xffff, .flags = 3 }, .{ .first = 0x20000, .last = 0x20fff, .flags = 2 } };
    try std.testing.expectEqual(@as(?u2, 1), uniformRights(&regions, 0x1000, 0x1fff));
    try std.testing.expectEqual(@as(?u2, 3), uniformRights(&regions, 0x2000, 0x2fff));
    try std.testing.expectEqual(@as(?u2, null), uniformRights(&regions, 0x0800, 0x17ff));
    try std.testing.expectEqual(@as(?u2, null), uniformRights(&regions, 0xf800, 0x107ff));
    try std.testing.expectEqual(@as(?u2, 0), uniformRights(&regions, 0x10000, 0x10fff));
    try std.testing.expectEqual(@as(?u2, 2), uniformRights(&regions, 0x20000, 0x20fff));
}
pub const Ledger = struct {
    allocator: std.mem.Allocator,
    image: Public.Image,
    /// Same key set and values as the former `AutoHashMapUnmanaged(u64,
    /// State)`; a paged radix table (ledger_table.zig). Producer hints only.
    states: StateTable = .empty,
    initial: std.ArrayList(R.types.Cell) = .empty,
    next_epoch: u32 = 1,
    /// Optional exact fast path for first-touch reads when `image` is
    /// `Public.fromOwner(pages.owner)` (set by the Ethereum ordered owner).
    pages: ?OwnerPages = null,
    pub fn init(a: std.mem.Allocator, image: Public.Image) Ledger {
        return .{ .allocator = a, .image = image };
    }
    pub fn deinit(self: *Ledger) void {
        self.states.deinit(self.allocator);
        self.initial.deinit(self.allocator);
    }
    /// On failure discard the ledger; no partially updated cursor may be retried.
    /// `stride` is the producing CPU's OWNER tick stride (layout.ramStride).
    pub fn shard(self: *Ledger, records: []const CPU.MemoryRecord, epoch: u16, stride: u32) ![]X.native.Event {
        if (epoch != self.next_epoch) return error.InvalidGlobalMemoryEpoch;
        const out = try self.allocator.alloc(X.native.Event, records.len);
        errdefer self.allocator.free(out);
        var previous: u24 = 0;
        for (records, out) |record, *event| {
            if (record.epoch != epoch or record.tick <= previous or record.tick % stride != 0) return error.InvalidMemoryRecordTime;
            previous = record.tick;
            const d = try X.native.describe(record.opcode);
            const ea = record.a +% record.immediate;
            const address = ea & ~@as(u64, 7);
            if (record.effect.address.toInt() != ea or record.effect.width != d.width or record.effect.write != d.write) return error.InvalidMemoryRecordEffect;
            const slot = try self.states.getOrPut(self.allocator, address);
            if (!slot.found_existing) {
                slot.value_ptr.* = .{ .value = try self.image.initialWord(address), .rights = try self.image.wordRights(address) };
                try self.initial.append(self.allocator, .{ .address = address, .state = slot.value_ptr.* });
            }
            const before = slot.value_ptr.*;
            if (record.effect.before_word.toInt() != before.value) return error.InconsistentCapturedMemoryBefore;
            const after = R.types.State{ .value = record.effect.after_word.toInt(), .epoch = epoch, .tick = record.tick, .rights = before.rights };
            event.* = .{ .opcode = record.opcode, .immediate = record.immediate, .a = record.a, .b = record.b, .c = record.c, .epoch = epoch, .tick = record.tick, .before = before, .after = after };
            try X.native.validate(event.*);
            slot.value_ptr.* = after;
        }
        self.next_epoch += 1;
        return out;
    }
    pub fn boundaries(self: *const Ledger) !struct { initial: []R.types.Cell, terminal: []R.types.Cell } {
        const initial = try self.allocator.dupe(R.types.Cell, self.initial.items);
        errdefer self.allocator.free(initial);
        // Addresses are unique (one first touch each), so an unstable sort
        // yields exactly the stable sort's order.
        std.sort.pdq(R.types.Cell, initial, {}, less);
        const terminal = try self.allocator.alloc(R.types.Cell, initial.len);
        errdefer self.allocator.free(terminal);
        for (initial, terminal) |cell, *out| out.* = .{ .address = cell.address, .state = self.states.get(cell.address).? };
        return .{ .initial = initial, .terminal = terminal };
    }
};
fn less(_: void, a: R.types.Cell, b: R.types.Cell) bool {
    return a.address < b.address;
}
