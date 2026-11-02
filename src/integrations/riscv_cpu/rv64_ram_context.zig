//! Canonical public hash-receipt context. The receiver supplies its independent
//! SHA256 pin; a hash advertised alongside an untrusted context is not authority.
const std = @import("std");
const core = @import("stwo_core");
const memory = @import("stwo_riscv_frontend").rv64_air.memory;
const ram = memory.commitment;
const transition = memory.transition;
const MAGIC = "RV64RAM1";
const MAX_PAGES = 64;
pub const MAX_BYTES = 2 * 1024 * 1024;

pub const Context = struct {
    witness: transition.Witness,
    updates: []transition.NetUpdate,
    page_indices: []u64,
    pub fn deinit(self: *Context) void {
        const a = self.witness.allocator;
        a.free(self.updates);
        a.free(self.page_indices);
        self.witness.deinit();
        self.* = undefined;
    }
};

fn digest(raw: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(raw, &result, .{});
    return result;
}

fn checkShape(pages: usize, sides: usize, updates: usize) !void {
    if (pages == 0 or pages > MAX_PAGES or sides > pages * ram.PAGE_DEPTH or updates > pages * ram.PAGE_CELLS)
        return error.InvalidRamContextShape;
}

fn put32(a: std.mem.Allocator, out: *std.ArrayList(u8), value: u32) !void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    try out.appendSlice(a, &bytes);
}
fn put64(a: std.mem.Allocator, out: *std.ArrayList(u8), value: u64) !void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .little);
    try out.appendSlice(a, &bytes);
}
fn putDigest(a: std.mem.Allocator, out: *std.ArrayList(u8), value: ram.Digest) !void {
    for (value) |word| {
        if (word >= core.fields.m31.Modulus) return error.NonCanonicalDigest;
        try put32(a, out, word);
    }
}

pub fn encode(a: std.mem.Allocator, witness: *const transition.Witness, updates: []const transition.NetUpdate) ![]u8 {
    try checkShape(witness.pages.len, witness.sides.len, updates.len);
    const indices = try a.alloc(u64, witness.pages.len);
    defer a.free(indices);
    for (indices, witness.pages) |*index, page| index.* = page.index;
    try witness.validateOpenings(indices);
    try witness.validateNetUpdates(updates);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    try out.appendSlice(a, MAGIC);
    try put32(a, &out, @intCast(witness.pages.len));
    try put32(a, &out, @intCast(witness.sides.len));
    try put32(a, &out, @intCast(updates.len));
    try putDigest(a, &out, witness.before);
    try putDigest(a, &out, witness.after);
    for (witness.pages) |*page| {
        try put64(a, &out, page.index);
        for ([_]*const ram.Page{ &page.before, &page.after }) |cells| for (cells) |cell| {
            var encoded: [11]u8 = undefined;
            std.mem.writeInt(u64, encoded[0..8], cell.value, .little);
            std.mem.writeInt(u24, encoded[8..11], cell.permissions, .little);
            try out.appendSlice(a, &encoded);
        };
    }
    for (witness.sides) |side| {
        try out.append(a, side.height);
        try put64(a, &out, side.index);
        try putDigest(a, &out, side.digest);
    }
    for (updates) |update| {
        try put64(a, &out, update.address);
        try put64(a, &out, update.value);
        try out.append(a, update.byte_mask);
    }
    if (out.items.len > MAX_BYTES) return error.InvalidRamContextShape;
    return out.toOwnedSlice(a);
}

const Reader = struct {
    bytes: []const u8,
    at: usize = 0,
    fn take(self: *Reader, n: usize) ![]const u8 {
        if (n > self.bytes.len - self.at) return error.TruncatedRamContext;
        const result = self.bytes[self.at..][0..n];
        self.at += n;
        return result;
    }
    fn word(self: *Reader) !u32 {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .little);
    }
    fn wide(self: *Reader) !u64 {
        return std.mem.readInt(u64, (try self.take(8))[0..8], .little);
    }
    fn hash(self: *Reader) !ram.Digest {
        var value: ram.Digest = undefined;
        for (&value) |*limb| {
            limb.* = try self.word();
            if (limb.* >= core.fields.m31.Modulus) return error.NonCanonicalDigest;
        }
        return value;
    }
};

/// Enforce source identity before allocation or producer-selected geometry.
pub fn decode(a: std.mem.Allocator, bytes: []const u8, expected_sha256: [32]u8) !Context {
    if (bytes.len > MAX_BYTES) return error.InvalidRamContextShape;
    if (!std.meta.eql(digest(bytes), expected_sha256)) return error.RamContextDigestMismatch;
    var reader = Reader{ .bytes = bytes };
    if (!std.mem.eql(u8, try reader.take(8), MAGIC)) return error.InvalidRamContextVersion;
    const page_count = try reader.word();
    const side_count = try reader.word();
    const update_count = try reader.word();
    try checkShape(page_count, side_count, update_count);
    const expected_len = 92 + @as(usize, page_count) * (8 + 2 * ram.PAGE_CELLS * 11) + @as(usize, side_count) * 45 + @as(usize, update_count) * 17;
    if (bytes.len != expected_len) return error.InvalidRamContextShape;
    const before = try reader.hash();
    const after = try reader.hash();
    const pages = try a.alloc(transition.Opening, page_count);
    errdefer a.free(pages);
    const indices = try a.alloc(u64, page_count);
    errdefer a.free(indices);
    for (pages, indices) |*page, *index| {
        index.* = try reader.wide();
        page.index = index.*;
        for ([_]*ram.Page{ &page.before, &page.after }) |cells| for (cells) |*cell| {
            const encoded = try reader.take(11);
            cell.* = .{ .value = std.mem.readInt(u64, encoded[0..8], .little), .permissions = std.mem.readInt(u24, encoded[8..11], .little) };
        };
    }
    const sides = try a.alloc(transition.Side, side_count);
    errdefer a.free(sides);
    for (sides) |*side| {
        const height = (try reader.take(1))[0];
        if (height >= ram.PAGE_DEPTH) return error.InvalidRamContextShape;
        side.* = .{ .height = @intCast(height), .index = try reader.wide(), .digest = try reader.hash() };
        if (side.index >= @as(u64, 1) << @intCast(ram.PAGE_DEPTH - height)) return error.InvalidRamContextShape;
    }
    const updates = try a.alloc(transition.NetUpdate, update_count);
    errdefer a.free(updates);
    for (updates) |*update| update.* = .{ .address = try reader.wide(), .value = try reader.wide(), .byte_mask = (try reader.take(1))[0] };
    const result = Context{ .witness = .{ .allocator = a, .pages = pages, .sides = sides, .before = before, .after = after }, .updates = updates, .page_indices = indices };
    try result.witness.validateOpenings(indices);
    try result.witness.validateNetUpdates(updates);
    return result;
}
