//! Native access-density measurement only. No hashes, trace rows or proof
//! authority. observe() consumes full before/after 8-byte native words; retire()
//! closes exactly one architectural instruction, including an atomic service.
const std = @import("std");
pub const CHUNK_BYTES = [_]u32{ 64, 128, 256, 512, 1024, 2048, 4096 };
pub const MAX_BATCH_STEPS = 1 << 22;
pub const OPCODE_COUNT = 65;
pub const Service = enum { keccak, secp_add, secp_double };
// Default native 256MiB mapping budget, with room for 256 partial-region edges.
pub const MAX_PAGES = 65536 + 256;
pub const MAX_CELLS = 256 * 1024 * 1024 / 8 + 256;
pub const Stats = struct {
    first_step: u64,
    end_step: u64,
    instructions: u32,
    opcode_counts: [OPCODE_COUNT]u64,
    unclassified_instructions: u64,
    keccak_calls: u64,
    secp_add_calls: u64,
    secp_double_calls: u64,
    access_events: u64,
    distinct_touched_cells: u64,
    distinct_written_cells: u64,
    net_changed_cells: u64,
    /// Aligned chunk counts in CHUNK_BYTES order, not byte totals.
    touched_chunks: [CHUNK_BYTES.len]u64,
    net_changed_chunks: [CHUNK_BYTES.len]u64,
    /// Exact binary union internal nodes, excluding chunk-leaf hashing.
    touched_internal_nodes: [CHUNK_BYTES.len]u64,
    net_changed_internal_nodes: [CHUNK_BYTES.len]u64,
};
const Bits = [8]u64;
const Page = struct { touched: Bits = @splat(0), written: Bits = @splat(0), changed: Bits = @splat(0) };
const Net = struct { initial: u64, final: u64 };

pub const Census = struct {
    allocator: std.mem.Allocator,
    batch_steps: u32,
    pages: std.AutoHashMap(u64, Page),
    words: std.AutoHashMap(u64, Net),
    stats: std.ArrayList(Stats) = .empty,
    page_keys: std.ArrayList(u64) = .empty,
    total_steps: u64 = 0,
    steps: u32 = 0,
    opcode_counts: [OPCODE_COUNT]u64 = @splat(0),
    service_counts: [3]u64 = @splat(0),
    unclassified_instructions: u64 = 0,
    events: u64 = 0,
    touched: u64 = 0,
    unretired_events: bool = false,
    finished: bool = false,

    pub fn init(a: std.mem.Allocator, batch_steps: u32) !Census {
        if (batch_steps == 0 or batch_steps > MAX_BATCH_STEPS) return error.InvalidCensusBatchSteps;
        return .{ .allocator = a, .batch_steps = batch_steps, .pages = std.AutoHashMap(u64, Page).init(a), .words = std.AutoHashMap(u64, Net).init(a) };
    }

    pub fn deinit(self: *Census) void {
        self.pages.deinit();
        self.words.deinit();
        self.stats.deinit(self.allocator);
        self.page_keys.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn observe(self: *Census, address: u64, before_word: u64, after_word: u64, write: bool) !void {
        if (self.finished) return error.CensusFinished;
        if (!write and before_word != after_word) return error.CensusLoadMutation;
        const word_address = address & ~@as(u64, 7);
        const page_index = word_address >> 12;
        const cell: usize = @intCast((word_address & 4095) >> 3);
        const mask = @as(u64, 1) << @intCast(cell % 64);
        const old_page = self.pages.getPtr(page_index);
        const new_page = old_page == null;
        const new_cell = old_page == null or old_page.?.touched[cell / 64] & mask == 0;
        const old_word = if (write) self.words.get(word_address) else null;
        if (old_word) |net| if (net.final != before_word) return error.CensusWordDiscontinuity;
        if ((new_page and self.pages.count() >= MAX_PAGES) or (new_cell and self.touched >= MAX_CELLS) or
            (write and old_word == null and self.words.count() >= MAX_CELLS)) return error.CensusResourceLimit;
        const next_events = try std.math.add(u64, self.events, 1);
        // Reserve BOTH maps before publishing keys, bitmaps or net values.
        if (new_page) try self.pages.ensureUnusedCapacity(1);
        if (write and old_word == null) try self.words.ensureUnusedCapacity(1);
        const page_entry = self.pages.getOrPutAssumeCapacity(page_index);
        if (!page_entry.found_existing) page_entry.value_ptr.* = .{};
        page_entry.value_ptr.touched[cell / 64] |= mask;
        if (write) {
            page_entry.value_ptr.written[cell / 64] |= mask;
            const net_entry = self.words.getOrPutAssumeCapacity(word_address);
            if (!net_entry.found_existing) net_entry.value_ptr.* = .{ .initial = before_word, .final = after_word } else net_entry.value_ptr.final = after_word;
        }
        self.events = next_events;
        if (new_cell) self.touched += 1;
        self.unretired_events = true;
    }

    pub fn retire(self: *Census) !void {
        return self.retireObserved(null, null);
    }

    pub fn retireOpcode(self: *Census, opcode: u8) !void {
        if (self.finished) return error.CensusFinished;
        if (opcode >= OPCODE_COUNT) return error.InvalidCensusOpcode;
        return self.retireObserved(opcode, null);
    }
    pub fn retireService(self: *Census, service: Service) !void {
        return self.retireObserved(@intFromEnum(@import("decode.zig").Opcode.ECALL), service);
    }
    fn retireObserved(self: *Census, opcode: ?u8, service: ?Service) !void {
        if (self.finished) return error.CensusFinished;
        const next_total = try std.math.add(u64, self.total_steps, 1);
        if (self.steps + 1 == self.batch_steps) try self.reserveFlush();
        self.total_steps = next_total;
        self.steps += 1;
        if (opcode) |index| self.opcode_counts[index] += 1 else self.unclassified_instructions += 1;
        if (service) |kind| self.service_counts[@intFromEnum(kind)] += 1;
        self.unretired_events = false;
        if (self.steps == self.batch_steps) try self.flush();
    }

    /// Returned storage belongs to the caller and uses the init allocator.
    /// A failed allocation preserves pending reports for a retry or deinit.
    pub fn finish(self: *Census) ![]Stats {
        if (self.finished) return error.CensusFinished;
        if (self.unretired_events) return error.UnretiredCensusEvents;
        if (self.steps != 0) try self.flush();
        const result = try self.stats.toOwnedSlice(self.allocator);
        self.finished = true;
        return result;
    }

    fn flush(self: *Census) !void {
        // All fallible actions precede changes, including retire() counters.
        try self.reserveFlush();
        var net_words = self.words.iterator();
        while (net_words.next()) |entry| {
            if (entry.value_ptr.initial == entry.value_ptr.final) continue;
            const page = self.pages.getPtr(entry.key_ptr.* >> 12).?;
            const cell: usize = @intCast((entry.key_ptr.* & 4095) >> 3);
            page.changed[cell / 64] |= @as(u64, 1) << @intCast(cell % 64);
        }
        var result = Stats{ .first_step = self.total_steps - self.steps, .end_step = self.total_steps, .instructions = self.steps, .opcode_counts = self.opcode_counts, .unclassified_instructions = self.unclassified_instructions, .keccak_calls = self.service_counts[0], .secp_add_calls = self.service_counts[1], .secp_double_calls = self.service_counts[2], .access_events = self.events, .distinct_touched_cells = self.touched, .distinct_written_cells = 0, .net_changed_cells = 0, .touched_chunks = @splat(0), .net_changed_chunks = @splat(0), .touched_internal_nodes = @splat(0), .net_changed_internal_nodes = @splat(0) };
        self.page_keys.clearRetainingCapacity();
        var key_iterator = self.pages.keyIterator();
        while (key_iterator.next()) |key| self.page_keys.appendAssumeCapacity(key.*);
        std.mem.sort(u64, self.page_keys.items, {}, std.sort.asc(u64));
        var previous_touched: [CHUNK_BYTES.len]?u64 = @splat(null);
        var previous_changed: [CHUNK_BYTES.len]?u64 = @splat(null);
        for (self.page_keys.items) |key| {
            const page = self.pages.getPtr(key).?;
            for (page.written) |bits| result.distinct_written_cells += @popCount(bits);
            for (page.changed) |bits| result.net_changed_cells += @popCount(bits);
            inline for (CHUNK_BYTES, 0..) |bytes, kind| {
                const log_bytes = std.math.log2_int(u32, bytes);
                const page_shift: u6 = 12 - log_bytes;
                const depth: u64 = 64 - @as(u64, log_bytes);
                for (0..4096 / bytes) |chunk| {
                    const index = (key << page_shift) | @as(u64, @intCast(chunk));
                    if (occupied(&page.touched, bytes, chunk)) {
                        result.touched_chunks[kind] += 1;
                        result.touched_internal_nodes[kind] += nodeIncrement(previous_touched[kind], index, depth);
                        previous_touched[kind] = index;
                    }
                    if (occupied(&page.changed, bytes, chunk)) {
                        result.net_changed_chunks[kind] += 1;
                        result.net_changed_internal_nodes[kind] += nodeIncrement(previous_changed[kind], index, depth);
                        previous_changed[kind] = index;
                    }
                }
            }
        }
        self.stats.appendAssumeCapacity(result);
        self.pages.clearRetainingCapacity();
        self.words.clearRetainingCapacity();
        self.steps = 0;
        self.opcode_counts = @splat(0);
        self.service_counts = @splat(0);
        self.unclassified_instructions = 0;
        self.events = 0;
        self.touched = 0;
    }

    fn reserveFlush(self: *Census) !void {
        try self.stats.ensureUnusedCapacity(self.allocator, 1);
        try self.page_keys.ensureTotalCapacity(self.allocator, self.pages.count());
    }
};

fn nodeIncrement(previous: ?u64, index: u64, depth: u64) u64 {
    // Adjacent ordered leaves add only parents below their highest differing
    // bit. The first leaf contributes the complete depth, including the root.
    return if (previous) |prior| std.math.log2_int(u64, prior ^ index) else depth;
}

fn occupied(bits: *const Bits, bytes: u32, chunk: usize) bool {
    const cells: usize = bytes / 8;
    const first = chunk * cells;
    if (cells <= 64) {
        const mask: u64 = if (cells == 64) std.math.maxInt(u64) else (@as(u64, 1) << @intCast(cells)) - 1;
        return (bits[first / 64] >> @intCast(first % 64)) & mask != 0;
    }
    for (bits[first / 64 ..][0 .. cells / 64]) |word| if (word != 0) return true;
    return false;
}
