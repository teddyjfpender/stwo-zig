//! Bounded static little-endian RV64 ELF admission for execution diagnostics.
//! ELF metadata does not establish instruction coverage, a proof or a guest ABI.
const std = @import("std");
const mem = @import("memory.zig");
pub const Error = mem.Error || error{ InvalidElf, UnsupportedElf, InvalidSegment, InvalidEntry, TooManySegments, MutableExecutable };
pub const Image = struct { entry: u64, load_segments: usize, mapped_bytes: u64, file_bytes: usize, initial_pages: u64 = 0 };
pub const Segment = struct { offset: u64, address: u64, file_size: u64, memory_size: u64, flags: u32 };
const PageRange = struct { first: u64, last: u64 };
pub const LoadedImage = struct {
    info: Image,
    memory: mem.Memory,

    pub fn deinit(self: *LoadedImage) void {
        self.memory.deinit();
        self.* = undefined;
    }
};

pub fn inspect(bytes: []const u8, limits: mem.Limits) Error!Image {
    if (bytes.len < 64 or !std.mem.eql(u8, bytes[0..4], "\x7fELF")) return error.InvalidElf;
    if (bytes[4] != 2 or bytes[5] != 1 or bytes[6] != 1) return error.UnsupportedElf;
    // ET_EXEC, EM_RISCV, version 1; reject RVC, floating ABI, RVE and TSO flags.
    if (read16(bytes, 16) != 2 or read16(bytes, 18) != 243 or read32(bytes, 20) != 1 or read32(bytes, 48) != 0) return error.UnsupportedElf;
    if (read16(bytes, 52) != 64 or read16(bytes, 54) != 56) return error.InvalidElf;
    const count = read16(bytes, 56);
    if (count == 0 or count > 256) return error.TooManySegments;
    const table = read64(bytes, 32);
    try fileRange(bytes, table, @as(u64, count) * 56);
    var image = Image{ .entry = read64(bytes, 24), .load_segments = 0, .mapped_bytes = 0, .file_bytes = bytes.len };
    if (image.entry & 3 != 0) return error.InvalidEntry;
    var executable_entry = false;
    var ranges: [256]PageRange = undefined;
    var range_count: usize = 0;
    for (0..count) |i| {
        const offset: usize = @intCast(table + i * 56);
        const kind = read32(bytes, offset);
        // Dynamic/interpreter/TLS segments need an ABI outside this profile.
        if (kind == 2 or kind == 3 or kind == 7) return error.UnsupportedElf;
        if (kind != 1) continue;
        const s = segment(bytes, offset);
        if (s.flags & ~@as(u32, 7) != 0 or s.file_size > s.memory_size) return error.InvalidSegment;
        try fileRange(bytes, s.offset, s.file_size);
        const alignment = read64(bytes, offset + 48);
        if (alignment > 1 and (!std.math.isPowerOfTwo(alignment) or s.address % alignment != s.offset % alignment)) return error.InvalidSegment;
        if (s.memory_size == 0) continue;
        const last = try mem.endAddress(s.address, s.memory_size);
        if (s.memory_size > limits.max_mapped_bytes - image.mapped_bytes or image.load_segments >= limits.max_regions) return error.ResourceLimit;
        for (0..i) |j| {
            const previous_offset: usize = @intCast(table + j * 56);
            if (read32(bytes, previous_offset) != 1) continue;
            const previous = segment(bytes, previous_offset);
            if (previous.memory_size == 0) continue;
            if (s.address <= try mem.endAddress(previous.address, previous.memory_size) and previous.address <= last) return error.OverlappingRegion;
        }
        if (s.flags & 1 != 0 and image.entry >= s.address and image.entry <= last and last - image.entry >= 3) executable_entry = true;
        image.load_segments += 1;
        image.mapped_bytes += s.memory_size;
        if (s.file_size != 0) {
            ranges[range_count] = .{ .first = s.address / mem.PAGE_SIZE, .last = (try mem.endAddress(s.address, s.file_size)) / mem.PAGE_SIZE };
            range_count += 1;
        }
    }
    if (!executable_entry) return error.InvalidEntry;
    std.mem.sort(PageRange, ranges[0..range_count], {}, lessPage);
    var previous_last: ?u64 = null;
    for (ranges[0..range_count]) |range| {
        const first = if (previous_last) |last| @max(range.first, last + 1) else range.first;
        if (first <= range.last) image.initial_pages += range.last - first + 1;
        previous_last = if (previous_last) |last| @max(last, range.last) else range.last;
    }
    if (image.initial_pages > limits.max_pages) return error.ResourceLimit;
    return image;
}

/// Validate before allocating; construct a fresh memory and publish only on
/// success. On any error the caller owns no partially loaded image.
pub fn load(allocator: std.mem.Allocator, bytes: []const u8, limits: mem.Limits) Error!mem.Memory {
    return (try loadImage(allocator, bytes, limits)).memory;
}

pub fn loadImage(allocator: std.mem.Allocator, bytes: []const u8, limits: mem.Limits) Error!LoadedImage {
    const info = try inspect(bytes, limits);
    return loadInspected(allocator, bytes, limits, info);
}

/// Immutable instruction ROM does not observe guest writes. The corresponding
/// proof profile must reject writable executable regions before allocation.
pub fn loadImmutableImage(allocator: std.mem.Allocator, bytes: []const u8, limits: mem.Limits) Error!LoadedImage {
    const info = try inspect(bytes, limits);
    const table = read64(bytes, 32);
    for (0..read16(bytes, 56)) |i| {
        const at: usize = @intCast(table + 56 * i);
        if (read32(bytes, at) == 1 and read64(bytes, at + 40) != 0 and read32(bytes, at + 4) & 3 == 3) return error.MutableExecutable;
    }
    return loadInspected(allocator, bytes, limits, info);
}
fn loadInspected(allocator: std.mem.Allocator, bytes: []const u8, limits: mem.Limits, info: Image) Error!LoadedImage {
    var memory = mem.Memory.init(allocator, limits);
    errdefer memory.deinit();
    const table = read64(bytes, 32);
    const count = read16(bytes, 56);
    for (0..count) |i| {
        const offset: usize = @intCast(table + i * 56);
        if (read32(bytes, offset) != 1) continue;
        const s = segment(bytes, offset);
        if (s.memory_size == 0) continue;
        try memory.map(.{ .start = s.address, .size = s.memory_size, .permissions = .{ .read = s.flags & 4 != 0, .write = s.flags & 2 != 0, .execute = s.flags & 1 != 0 } });
        const start: usize = @intCast(s.offset);
        try memory.initialize(s.address, bytes[start..][0..@intCast(s.file_size)]);
    }
    return .{ .info = info, .memory = memory };
}

fn lessPage(_: void, a: PageRange, b: PageRange) bool {
    return a.first < b.first;
}

fn segment(bytes: []const u8, offset: usize) Segment {
    return .{ .flags = read32(bytes, offset + 4), .offset = read64(bytes, offset + 8), .address = read64(bytes, offset + 16), .file_size = read64(bytes, offset + 32), .memory_size = read64(bytes, offset + 40) };
}

fn read16(bytes: []const u8, offset: usize) u16 {
    return std.mem.readInt(u16, bytes[offset..][0..2], .little);
}
fn read32(bytes: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, bytes[offset..][0..4], .little);
}
fn read64(bytes: []const u8, offset: usize) u64 {
    return std.mem.readInt(u64, bytes[offset..][0..8], .little);
}

fn fileRange(bytes: []const u8, offset: u64, size: u64) Error!void {
    if (offset > bytes.len or size > bytes.len - offset) return error.InvalidElf;
}
