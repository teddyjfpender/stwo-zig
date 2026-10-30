//! Independently derived fresh-ELF initialization partition, not proof authority.
//! No current route imports this experimental protocol.
const std = @import("std");
const M = @import("stwo_core").fields.m31.M31;
const Loader = @import("../runner/elf_loader.zig");
const Memory = @import("../runner/memory.zig").Memory;
const Sources = @import("block_v5_initial_sources_v1.zig");
pub const WORD_LIMIT: u32 = 1 << 30;
pub const TUPLE_WIDTH: usize = 6;
pub const Limits = struct {
    max_elf_bytes: usize = 32 * 1024 * 1024,
    max_segments: usize = 1024,
    max_loaded_bytes: u64 = 64 * 1024 * 1024,
    max_initialized_words: usize = 4_000_000,
    max_pages: usize = 4096,
    max_input_bytes: u32 = 4 * 1024 * 1024,
    max_intervals: usize = 8_000_032,
};
pub const Interval = struct {
    lower: u32,
    upper: u32,
    allowed: bool,
    private: bool,
    value: u32,
    pub fn tuple(self: Interval) [TUPLE_WIDTH]M {
        return .{ M.fromCanonical(self.lower), M.fromCanonical(self.upper), M.fromCanonical(@intFromBool(self.allowed)), M.fromCanonical(@intFromBool(self.private)), M.fromCanonical(self.value & 65535), M.fromCanonical(self.value >> 16) };
    }
};

pub const Owned = struct {
    a: std.mem.Allocator,
    elf_sha256: [32]u8,
    info: Loader.ElfInfo,
    intervals: []Interval,

    pub fn derive(a: std.mem.Allocator, elf: []const u8, expected_sha256: [32]u8, profile: Loader.ExecutionProfile, limits: Limits) !Owned {
        if (elf.len > limits.max_elf_bytes or !std.meta.eql(Sources.sha256(elf), expected_sha256)) return error.UntrustedV7Elf;
        try Loader.validateReleaseAbiForProfile(elf, profile);
        const addresses = try loadAddresses(a, elf, limits);
        defer a.free(addresses);
        var memory = try Memory.initFallible(a);
        defer memory.deinit();
        // The loader's mutation methods are infallible. Reserve every unique
        // touched word/page first so allocation failure remains an error here.
        try memory.prepareAlignedWordWrites(addresses);
        const info = try Loader.loadElfForProfile(elf, &memory, profile);
        try Sources.validateLayout(info.memory_layout);
        if ((info.input_start | info.input_end) & 3 != 0 or info.input_end <= info.input_start or
            info.input_end - info.input_start > limits.max_input_bytes) return error.InvalidV7PrivateInput;

        var boundaries: std.ArrayList(u32) = .empty;
        defer boundaries.deinit(a);
        // Two per initialized word, fourteen layout edges, domain endpoints.
        const cap = try std.math.add(usize, try std.math.mul(usize, addresses.len, 2), 16);
        if (cap > limits.max_intervals) return error.V7InitializationResourceLimit;
        try boundaries.ensureTotalCapacity(a, cap);
        boundaries.appendAssumeCapacity(0);
        boundaries.appendAssumeCapacity(WORD_LIMIT);
        const layout = info.memory_layout;
        inline for (.{ "program_base", "program_end", "data_base", "data_end", "stack_bottom", "stack_top", "io_base", "io_end", "input_base", "input_end" }) |name|
            boundaries.appendAssumeCapacity(@intCast((@as(u64, @field(layout, name)) + 3) / 4));
        for (addresses) |address| {
            if (!layout.isRwAddr(address) or layout.isProgramAddr(address) or layout.isInputAddr(address) or memory.readU32(address) == 0) continue;
            boundaries.appendAssumeCapacity(address / 4);
            boundaries.appendAssumeCapacity(address / 4 + 1);
        }
        std.mem.sort(u32, boundaries.items, {}, std.sort.asc(u32));
        var rows: std.ArrayList(Interval) = .empty;
        errdefer rows.deinit(a);
        var lower: u32 = 0;
        for (boundaries.items) |upper| {
            if (upper == lower) continue;
            const address = lower * 4;
            const allowed = layout.isRwAddr(address) and !layout.isProgramAddr(address);
            const private = allowed and layout.isInputAddr(address);
            const value = if (allowed and !private) memory.readU32(address) else 0;
            if (rows.items.len != 0) {
                const prior = &rows.items[rows.items.len - 1];
                if (prior.allowed == allowed and prior.private == private and prior.value == value) {
                    prior.upper = upper;
                    lower = upper;
                    continue;
                }
            }
            try rows.append(a, .{ .lower = lower, .upper = upper, .allowed = allowed, .private = private, .value = value });
            lower = upper;
        }
        try validatePartition(rows.items);
        return .{ .a = a, .elf_sha256 = expected_sha256, .info = info, .intervals = try rows.toOwnedSlice(a) };
    }

    pub fn deinit(self: *Owned) void {
        self.a.free(self.intervals);
        self.* = undefined;
    }
    pub fn validateAgainst(self: Owned, a: std.mem.Allocator, elf: []const u8, expected_sha256: [32]u8, profile: Loader.ExecutionProfile, limits: Limits) !void {
        var independent = try derive(a, elf, expected_sha256, profile, limits);
        defer independent.deinit();
        if (!std.meta.eql(self.elf_sha256, independent.elf_sha256) or !std.meta.eql(self.info, independent.info) or
            self.intervals.len != independent.intervals.len) return error.UntrustedV7Initialization;
        for (self.intervals, independent.intervals) |actual, expected|
            if (!std.meta.eql(actual, expected)) return error.UntrustedV7Initialization;
    }
    pub fn find(self: Owned, address: u32) !Interval {
        return self.intervals[try self.findIndex(address)];
    }
    /// Return the canonical provider row while searching the authenticated
    /// partition. Callers needing its multiplicity must retain this index;
    /// searching again by interval equality makes first-touch census quadratic.
    /// As with `find`, admission must validate the partition independently.
    pub fn findIndex(self: Owned, address: u32) !usize {
        if (address & 3 != 0) return error.UnalignedV7InitializationAddress;
        const word = address / 4;
        var lo: usize = 0;
        var hi = self.intervals.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (self.intervals[mid].upper <= word) lo = mid + 1 else hi = mid;
        }
        if (lo == self.intervals.len or self.intervals[lo].lower > word) return error.InvalidV7InitializationPartition;
        return lo;
    }
};

pub fn validatePartition(rows: []const Interval) !void {
    var next: u32 = 0;
    for (rows) |row| {
        if (row.lower != next or row.upper <= row.lower or row.upper > WORD_LIMIT or
            (row.private and !row.allowed) or ((!row.allowed or row.private) and row.value != 0))
            return error.InvalidV7InitializationPartition;
        next = row.upper;
    }
    if (next != WORD_LIMIT) return error.InvalidV7InitializationPartition;
}

pub fn loadAddresses(a: std.mem.Allocator, elf: []const u8, limits: Limits) ![]u32 {
    const phoff = std.mem.readInt(u32, elf[28..32], .little);
    const count = std.mem.readInt(u16, elf[44..46], .little);
    if (count > limits.max_segments or limits.max_intervals == 0) return error.V7InitializationResourceLimit;
    var addresses: std.ArrayList(u32) = .empty;
    errdefer addresses.deinit(a);
    var total: u64 = 0;
    for (0..count) |i| {
        const offset = try std.math.add(usize, phoff, i * 32);
        if (offset > elf.len or elf.len - offset < 32) return error.InvalidProgramHeader;
        const ph = elf[offset..][0..32];
        if (std.mem.readInt(u32, ph[0..4], .little) != 1) continue;
        const file_offset = std.mem.readInt(u32, ph[4..8], .little);
        const address = std.mem.readInt(u32, ph[8..12], .little);
        const file_size = std.mem.readInt(u32, ph[16..20], .little);
        const mem_size = std.mem.readInt(u32, ph[20..24], .little);
        const end = @as(u64, address) + mem_size;
        total = try std.math.add(u64, total, mem_size);
        if (file_size > mem_size or @as(u64, file_offset) + file_size > elf.len or end > (@as(u64, 1) << 32)) return error.InvalidProgramHeader;
        if (total > limits.max_loaded_bytes) return error.V7InitializationResourceLimit;
        if (mem_size == 0) continue;
        const first = address / 4;
        const last = (end + 3) / 4;
        if (last - first > limits.max_initialized_words or addresses.items.len > limits.max_initialized_words - (last - first)) return error.V7InitializationResourceLimit;
        try addresses.ensureUnusedCapacity(a, @intCast(last - first));
        for (first..@intCast(last)) |word| addresses.appendAssumeCapacity(@intCast(word * 4));
    }
    std.mem.sort(u32, addresses.items, {}, std.sort.asc(u32));
    var unique: usize = 0;
    var pages: usize = 0;
    var previous_page: ?u32 = null;
    for (addresses.items) |address| {
        if (unique != 0 and addresses.items[unique - 1] == address) continue;
        addresses.items[unique] = address;
        unique += 1;
        const page = address >> 16;
        if (previous_page == null or previous_page.? != page) pages += 1;
        previous_page = page;
    }
    if (pages > limits.max_pages) return error.V7InitializationResourceLimit;
    addresses.items.len = unique;
    return addresses.toOwnedSlice(a);
}
