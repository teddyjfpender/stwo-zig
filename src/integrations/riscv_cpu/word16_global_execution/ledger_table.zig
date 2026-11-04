//! Word-address -> RAM state map behind the chronological capture ledger.
//!
//! Drop-in for the `std.AutoHashMapUnmanaged(u64, State)` the ledger used:
//! same key set, same values, same `getOrPut`/`getPtr`/`get`/`count` contract
//! (an absent key's `value_ptr` is undefined until the caller writes it). It
//! holds producer hints only; nothing here is acceptance authority, and no
//! iteration order is exposed, so every ledger output is unchanged.
//!
//! Layout (HPC: replace a pointer-chasing hash probe per memory record with a
//! cache-friendly radix walk). An aligned word `address` lives in the 4 KiB
//! guest page `address >> 12`, slot `(address >> 3) & 511`:
//! - pages below 4 GiB of guest address space: two-level radix directory
//!   (1024 x 1024 page pointers), plus a one-entry last-page cache, so the
//!   stack/heap locality of a RISC-V trace hits the same page repeatedly;
//! - pages at or above 4 GiB: a page hash map (never reached by the Ethereum
//!   guest, kept for exact key coverage);
//! - unaligned keys: a plain hash map. Such a key can never be admitted
//!   (`Image.wordRights` rejects it), but it is stored exactly as before so a
//!   failed ledger has the same contents.
//! Pages are carved from 64-page slabs, so allocation is amortised and the
//! table never frees anything before `deinit` (the ledger only grows).
const std = @import("std");
const State = @import("stwo_riscv_frontend").rv64_air.memory.closed_ram.types.State;

pub const PAGE_WORDS = 512;
const PAGE_SHIFT = 12;
const LEAF_BITS = 10;
const DIRECT_PAGES: u64 = 1 << (2 * LEAF_BITS);
const SLAB_PAGES = 64;

pub const Page = struct {
    present: [PAGE_WORDS / 64]u64,
    states: [PAGE_WORDS]State,
};
const Leaf = [1 << LEAF_BITS]?*Page;

pub const GetOrPutResult = struct { found_existing: bool, value_ptr: *State };

pub const StateTable = struct {
    dir: [1 << LEAF_BITS]?*Leaf = @splat(null),
    far: std.AutoHashMapUnmanaged(u64, *Page) = .empty,
    odd: std.AutoHashMapUnmanaged(u64, State) = .empty,
    leaves: std.ArrayList(*Leaf) = .empty,
    slabs: std.ArrayList([]Page) = .empty,
    slab_used: usize = SLAB_PAGES,
    len: usize = 0,
    pages: usize = 0,
    last_index: u64 = std.math.maxInt(u64),
    last_page: ?*Page = null,

    pub const empty: StateTable = .{};

    pub fn deinit(self: *StateTable, a: std.mem.Allocator) void {
        for (self.slabs.items) |slab| a.free(slab);
        self.slabs.deinit(a);
        for (self.leaves.items) |leaf| a.destroy(leaf);
        self.leaves.deinit(a);
        self.far.deinit(a);
        self.odd.deinit(a);
        self.* = undefined;
    }

    pub fn count(self: *const StateTable) usize {
        return self.len + self.odd.count();
    }

    /// Bytes of table storage (slabs + directory leaves), report-only.
    pub fn storageBytes(self: *const StateTable) usize {
        return self.slabs.items.len * SLAB_PAGES * @sizeOf(Page) + self.leaves.items.len * @sizeOf(Leaf);
    }

    /// Capacity hint kept for API compatibility: pages are allocated on demand.
    pub fn ensureUnusedCapacity(_: *StateTable, _: std.mem.Allocator, _: anytype) !void {}

    fn newPage(self: *StateTable, a: std.mem.Allocator) !*Page {
        if (self.slab_used == SLAB_PAGES) {
            try self.slabs.ensureUnusedCapacity(a, 1);
            const slab = try a.alloc(Page, SLAB_PAGES);
            self.slabs.appendAssumeCapacity(slab);
            self.slab_used = 0;
        }
        const page = &self.slabs.items[self.slabs.items.len - 1][self.slab_used];
        self.slab_used += 1;
        self.pages += 1;
        page.present = @splat(0);
        return page;
    }

    fn findPage(self: *const StateTable, index: u64) ?*Page {
        if (index < DIRECT_PAGES) {
            const leaf = self.dir[@intCast(index >> LEAF_BITS)] orelse return null;
            return leaf[@intCast(index & ((1 << LEAF_BITS) - 1))];
        }
        return self.far.get(index);
    }

    fn pageFor(self: *StateTable, a: std.mem.Allocator, index: u64) !*Page {
        if (index == self.last_index) return self.last_page.?;
        const page = if (index < DIRECT_PAGES) direct: {
            const leaf_slot = &self.dir[@intCast(index >> LEAF_BITS)];
            if (leaf_slot.* == null) {
                try self.leaves.ensureUnusedCapacity(a, 1);
                const leaf = try a.create(Leaf);
                leaf.* = @splat(null);
                self.leaves.appendAssumeCapacity(leaf);
                leaf_slot.* = leaf;
            }
            const page_slot = &leaf_slot.*.?[@intCast(index & ((1 << LEAF_BITS) - 1))];
            if (page_slot.* == null) page_slot.* = try self.newPage(a);
            break :direct page_slot.*.?;
        } else far: {
            try self.far.ensureUnusedCapacity(a, 1);
            const entry = self.far.getOrPutAssumeCapacity(index);
            if (!entry.found_existing) entry.value_ptr.* = self.newPage(a) catch |err| {
                self.far.removeByPtr(entry.key_ptr);
                return err;
            };
            break :far entry.value_ptr.*;
        };
        self.last_index = index;
        self.last_page = page;
        return page;
    }

    pub fn getOrPut(self: *StateTable, a: std.mem.Allocator, address: u64) !GetOrPutResult {
        if (address & 7 != 0) {
            const entry = try self.odd.getOrPut(a, address);
            return .{ .found_existing = entry.found_existing, .value_ptr = entry.value_ptr };
        }
        const page = try self.pageFor(a, address >> PAGE_SHIFT);
        const slot: usize = @intCast((address >> 3) & (PAGE_WORDS - 1));
        const bit = @as(u64, 1) << @intCast(slot & 63);
        const found = page.present[slot >> 6] & bit != 0;
        if (!found) {
            page.present[slot >> 6] |= bit;
            self.len += 1;
        }
        return .{ .found_existing = found, .value_ptr = &page.states[slot] };
    }

    pub fn getPtr(self: *StateTable, address: u64) ?*State {
        if (address & 7 != 0) return self.odd.getPtr(address);
        const index = address >> PAGE_SHIFT;
        const page = if (index == self.last_index) self.last_page.? else self.findPage(index) orelse return null;
        const slot: usize = @intCast((address >> 3) & (PAGE_WORDS - 1));
        if (page.present[slot >> 6] & (@as(u64, 1) << @intCast(slot & 63)) == 0) return null;
        return &page.states[slot];
    }

    pub fn get(self: *const StateTable, address: u64) ?State {
        if (address & 7 != 0) return self.odd.get(address);
        const page = self.findPage(address >> PAGE_SHIFT) orelse return null;
        const slot: usize = @intCast((address >> 3) & (PAGE_WORDS - 1));
        if (page.present[slot >> 6] & (@as(u64, 1) << @intCast(slot & 63)) == 0) return null;
        return page.states[slot];
    }
};

test "StateTable matches AutoHashMap on a random trace" {
    const a = std.testing.allocator;
    var table: StateTable = .empty;
    defer table.deinit(a);
    var reference: std.AutoHashMapUnmanaged(u64, State) = .empty;
    defer reference.deinit(a);
    var prng = std.Random.DefaultPrng.init(0x5eed_1ed9e7);
    const r = prng.random();
    const bases = [_]u64{ 0, 0x0080_0000, 0x02c0_0000, 0x0fff_f000, 0xffff_f000, 0x1_0000_0000, 0xffff_ffff_ffff_f000 };
    for (0..200_000) |i| {
        const base = bases[r.uintLessThan(usize, bases.len)];
        var address = base +% r.uintLessThan(u64, 1 << 14);
        if (r.uintLessThan(u8, 16) != 0) address &= ~@as(u64, 7);
        const value = State{ .value = r.int(u64), .epoch = @truncate(i), .tick = @truncate(i), .rights = @truncate(i) };
        switch (r.uintLessThan(u8, 3)) {
            0 => {
                const got = try table.getOrPut(a, address);
                const want = try reference.getOrPut(a, address);
                try std.testing.expectEqual(want.found_existing, got.found_existing);
                got.value_ptr.* = value;
                want.value_ptr.* = value;
            },
            1 => {
                const got = table.getPtr(address);
                const want = reference.getPtr(address);
                try std.testing.expectEqual(want == null, got == null);
                if (got) |p| {
                    try std.testing.expectEqual(want.?.*, p.*);
                    p.* = value;
                    want.?.* = value;
                }
            },
            else => try std.testing.expectEqual(reference.get(address), table.get(address)),
        }
    }
    try std.testing.expectEqual(reference.count(), table.count());
    var it = reference.iterator();
    while (it.next()) |entry| try std.testing.expectEqual(entry.value_ptr.*, table.get(entry.key_ptr.*).?);
}

test "StateTable getOrPut leaves an absent value for the caller" {
    const a = std.testing.allocator;
    var table: StateTable = .empty;
    defer table.deinit(a);
    try std.testing.expect(table.get(0x1000) == null);
    const first = try table.getOrPut(a, 0x1000);
    try std.testing.expect(!first.found_existing);
    first.value_ptr.* = .{ .value = 7, .rights = 1 };
    const again = try table.getOrPut(a, 0x1000);
    try std.testing.expect(again.found_existing);
    try std.testing.expectEqual(@as(u64, 7), again.value_ptr.value);
    try std.testing.expectEqual(@as(usize, 1), table.count());
    try std.testing.expect(table.getPtr(0x1008) == null);
    try std.testing.expect(table.getPtr(0x1001) == null);
}
