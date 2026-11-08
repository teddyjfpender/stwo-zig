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
test "parallel boundary sort equals the serial sort (unique addresses)" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x5eed_b0da);
    const r = prng.random();
    for ([_]usize{ 0, 1, 7, PARALLEL_MIN - 1, PARALLEL_MIN, PARALLEL_MIN + 3, 200_003 }) |n| {
        const cells = try a.alloc(R.types.Cell, n);
        defer a.free(cells);
        const expected = try a.alloc(R.types.Cell, n);
        defer a.free(expected);
        // Unique addresses (a random permutation of 8-byte words) with payloads.
        for (cells, 0..) |*cell, i| cell.* = .{ .address = 8 * @as(u64, i), .state = .{ .value = r.int(u64), .rights = r.int(u2) } };
        r.shuffle(R.types.Cell, cells);
        @memcpy(expected, cells);
        std.sort.pdq(R.types.Cell, expected, {}, less);
        sortCells(a, cells);
        for (cells, expected) |x, y| try std.testing.expectEqualDeep(y, x);
    }
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
        // yields exactly the stable sort's order (and so does the parallel
        // chunk sort + merge below: the order is the unique address order).
        sortCells(self.allocator, initial);
        const terminal = try self.allocator.alloc(R.types.Cell, initial.len);
        errdefer self.allocator.free(terminal);
        terminalStates(self, initial, terminal);
        return .{ .initial = initial, .terminal = terminal };
    }
};
/// M6 capture tail: sort/look up boundary cells on up to PARALLEL threads
/// above PARALLEL_MIN cells (`STWO_RV64_CAPTURE_PARALLEL_BOUNDARIES=0` off).
/// Scheduling only; any thread or scratch failure falls back to serial.
const PARALLEL = 8;
const PARALLEL_MIN = 1 << 16;
fn parallelBoundaries(n: usize) bool {
    if (n < PARALLEL_MIN) return false;
    const text = std.posix.getenv("STWO_RV64_CAPTURE_PARALLEL_BOUNDARIES") orelse return true;
    return !std.mem.eql(u8, text, "0");
}
fn sortChunk(cells: []R.types.Cell) void {
    std.sort.pdq(R.types.Cell, cells, {}, less);
}
fn mergeRuns(x: []const R.types.Cell, y: []const R.types.Cell, out: []R.types.Cell) void {
    var i: usize = 0;
    var j: usize = 0;
    for (out) |*slot| {
        if (j == y.len or (i < x.len and x[i].address < y[j].address)) {
            slot.* = x[i];
            i += 1;
        } else {
            slot.* = y[j];
            j += 1;
        }
    }
}
fn sortCells(a: std.mem.Allocator, cells: []R.types.Cell) void {
    const n = cells.len;
    if (!parallelBoundaries(n)) return sortChunk(cells);
    const scratch = a.alloc(R.types.Cell, n) catch return sortChunk(cells);
    defer a.free(scratch);
    var bounds: [PARALLEL + 1]usize = undefined;
    for (&bounds, 0..) |*b, i| b.* = n * i / PARALLEL;
    var threads: [PARALLEL]?std.Thread = @splat(null);
    for (1..PARALLEL) |k| threads[k] = std.Thread.spawn(.{}, sortChunk, .{cells[bounds[k]..bounds[k + 1]]}) catch null;
    sortChunk(cells[bounds[0]..bounds[1]]);
    for (1..PARALLEL) |k| if (threads[k]) |t| t.join() else sortChunk(cells[bounds[k]..bounds[k + 1]]);
    // Pairwise merges of sorted runs, each level's pairs in parallel.
    var src = cells;
    var dst = scratch;
    var runs: usize = PARALLEL;
    while (runs > 1) : (runs = (runs + 1) / 2) {
        var level: [PARALLEL / 2]?std.Thread = @splat(null);
        var pair: usize = 0;
        while (2 * pair < runs) : (pair += 1) {
            const lo = bounds[2 * pair];
            const mid = bounds[@min(2 * pair + 1, runs)];
            const hi = bounds[@min(2 * pair + 2, runs)];
            if (pair == 0) continue;
            level[pair] = std.Thread.spawn(.{}, mergeRuns, .{ src[lo..mid], src[mid..hi], dst[lo..hi] }) catch null;
            if (level[pair] == null) mergeRuns(src[lo..mid], src[mid..hi], dst[lo..hi]);
        }
        mergeRuns(src[bounds[0]..bounds[@min(1, runs)]], src[bounds[@min(1, runs)]..bounds[@min(2, runs)]], dst[bounds[0]..bounds[@min(2, runs)]]);
        for (level) |t| if (t) |thread| thread.join();
        // Run k of the next level spans old runs 2k and 2k+1.
        var k: usize = 0;
        while (2 * k < runs) : (k += 1) bounds[k] = bounds[2 * k];
        bounds[k] = bounds[runs];
        const swap = src;
        src = dst;
        dst = swap;
    }
    if (src.ptr != cells.ptr) @memcpy(cells, src);
}
const TerminalPart = struct {
    ledger: *const Ledger,
    initial: []const R.types.Cell,
    terminal: []R.types.Cell,
    fn run(self: TerminalPart) void {
        for (self.initial, self.terminal) |cell, *out| out.* = .{ .address = cell.address, .state = self.ledger.states.get(cell.address).? };
    }
};
fn terminalStates(ledger: *const Ledger, initial: []const R.types.Cell, terminal: []R.types.Cell) void {
    const n = initial.len;
    if (!parallelBoundaries(n)) return (TerminalPart{ .ledger = ledger, .initial = initial, .terminal = terminal }).run();
    var threads: [PARALLEL]?std.Thread = @splat(null);
    for (1..PARALLEL) |k| {
        const part = TerminalPart{ .ledger = ledger, .initial = initial[n * k / PARALLEL .. n * (k + 1) / PARALLEL], .terminal = terminal[n * k / PARALLEL .. n * (k + 1) / PARALLEL] };
        threads[k] = std.Thread.spawn(.{}, TerminalPart.run, .{part}) catch blk: {
            part.run();
            break :blk null;
        };
    }
    (TerminalPart{ .ledger = ledger, .initial = initial[0 .. n / PARALLEL], .terminal = terminal[0 .. n / PARALLEL] }).run();
    for (threads) |t| if (t) |thread| thread.join();
}
fn less(_: void, a: R.types.Cell, b: R.types.Cell) bool {
    return a.address < b.address;
}
