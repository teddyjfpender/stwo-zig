//! Versioned experimental CAS10 four-root source-opening subproof. This wire
//! does not contain transcript-derived query positions or FRI degree tests.
//! Verification requires an external accepted root/log/query statement.
const std = @import("std");
const m31 = @import("../fields/m31.zig");
const source = @import("four_root_pair_openings_experimental.zig");

const M31 = m31.M31;
const H = source.H;
pub const magic = "S31G4P01";
pub const version: u16 = 1;
pub const max_wire_bytes: usize = 64 * 1024 * 1024;
pub const max_witness_hashes: usize = 1 << 20;

pub fn encode(
    allocator: std.mem.Allocator,
    expected: source.Expected,
    openings: [source.root_count]source.TreeOpening,
) ![]u8 {
    if (expected.column_log_sizes[3].len != source.composition_columns or
        expected.raw_queries.len == 0 or
        expected.raw_queries.len > std.math.maxInt(u32))
        return error.InvalidFourRootPairWire;
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    const w = out.writer(allocator);
    try w.writeAll(magic);
    try w.writeInt(u16, version, .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u32, 0, .little);
    try w.writeInt(u32, expected.lifting_log_size, .little);
    try w.writeInt(u32, @intCast(expected.raw_queries.len), .little);
    const pair_count = std.math.mul(usize, expected.raw_queries.len, 2) catch
        return error.InvalidFourRootPairWire;
    for (expected.roots, expected.column_log_sizes, openings) |root, logs, opening| {
        if (logs.len == 0 or logs.len > std.math.maxInt(u16) or
            opening.queried_values.len != logs.len or
            opening.hash_witness.len > max_witness_hashes)
            return error.InvalidFourRootPairWire;
        try w.writeInt(u16, @intCast(logs.len), .little);
        try w.writeInt(u16, 0, .little);
        try w.writeAll(&root);
        for (logs) |log| try w.writeInt(u32, log, .little);
        for (opening.queried_values) |values| {
            if (values.len != pair_count) return error.InvalidFourRootPairWire;
            for (values) |value| {
                if (value.v >= m31.Modulus) return error.InvalidFourRootPairWire;
                try w.writeInt(u32, value.toU32(), .little);
            }
        }
        try w.writeInt(u32, @intCast(opening.hash_witness.len), .little);
        for (opening.hash_witness) |hash| try w.writeAll(&hash);
        if (out.items.len > max_wire_bytes) return error.FourRootPairWireTooLarge;
    }
    if (out.items.len > max_wire_bytes or out.items.len > std.math.maxInt(u32))
        return error.FourRootPairWireTooLarge;
    const encoded = try out.toOwnedSlice(allocator);
    std.mem.writeInt(u32, encoded[12..16], @intCast(encoded.len), .little);
    return encoded;
}

/// Decode and verify against externally provided accepted roots, source logs,
/// lifting height and ordered raw queries. The root/profile values repeated in
/// the wire are checked against `expected` before Merkle authentication.
pub fn verifyEncoded(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    expected: source.Expected,
) !void {
    if (encoded.len > max_wire_bytes) return error.FourRootPairWireTooLarge;
    var c = Cursor{ .bytes = encoded };
    if (!std.mem.eql(u8, try c.take(magic.len), magic))
        return error.UnsupportedFourRootPairWire;
    if (try c.readU16() != version) return error.UnsupportedFourRootPairWire;
    if (try c.readU16() != 0) return error.InvalidFourRootPairWire;
    const declared = try c.readU32();
    if (declared > encoded.len) return error.TruncatedFourRootPairWire;
    if (declared != encoded.len) return error.InvalidFourRootPairWire;
    if (try c.readU32() != expected.lifting_log_size or
        try c.readU32() != expected.raw_queries.len or
        expected.raw_queries.len == 0 or
        expected.column_log_sizes[3].len != source.composition_columns)
        return error.InvalidFourRootPairWire;
    const pair_count = std.math.mul(usize, expected.raw_queries.len, 2) catch
        return error.InvalidFourRootPairWire;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var openings: [source.root_count]source.TreeOpening = undefined;
    for (expected.roots, expected.column_log_sizes, &openings) |root, logs, *opening| {
        if (logs.len == 0 or logs.len > std.math.maxInt(u16) or
            try c.readU16() != logs.len or try c.readU16() != 0)
            return error.InvalidFourRootPairWire;
        if (!std.mem.eql(u8, try c.take(@sizeOf(H.Hash)), &root))
            return error.InvalidFourRootPairWire;
        for (logs) |log| {
            if (try c.readU32() != log) return error.InvalidFourRootPairWire;
        }
        const value_count = std.math.mul(usize, logs.len, pair_count) catch
            return error.InvalidFourRootPairWire;
        const value_bytes = std.math.mul(usize, value_count, @sizeOf(M31)) catch
            return error.InvalidFourRootPairWire;
        if (value_bytes > c.bytes.len - c.at)
            return error.TruncatedFourRootPairWire;
        const values = try a.alloc([]M31, logs.len);
        for (values) |*column| {
            column.* = try a.alloc(M31, pair_count);
            for (column.*) |*value| {
                const raw = try c.readU32();
                if (raw >= m31.Modulus) return error.NonCanonicalM31;
                value.* = M31.fromCanonical(raw);
            }
        }
        const witness_count = try c.readU32();
        if (witness_count > max_witness_hashes or
            witness_count > (c.bytes.len - c.at) / @sizeOf(H.Hash))
            return error.InvalidFourRootPairWire;
        const witness = try a.alloc(H.Hash, witness_count);
        for (witness) |*hash| @memcpy(hash, try c.take(@sizeOf(H.Hash)));
        opening.* = .{ .queried_values = values, .hash_witness = witness };
    }
    if (c.at != encoded.len) return error.InvalidFourRootPairWire;
    try source.verify(a, expected, openings);
}

const Cursor = struct {
    bytes: []const u8,
    at: usize = 0,

    fn take(self: *Cursor, count: usize) ![]const u8 {
        if (count > self.bytes.len - self.at)
            return error.TruncatedFourRootPairWire;
        const result = self.bytes[self.at..][0..count];
        self.at += count;
        return result;
    }

    fn readU16(self: *Cursor) !u16 {
        const bytes = try self.take(2);
        return @as(u16, bytes[0]) | (@as(u16, bytes[1]) << 8);
    }

    fn readU32(self: *Cursor) !u32 {
        const bytes = try self.take(4);
        return @as(u32, bytes[0]) |
            (@as(u32, bytes[1]) << 8) |
            (@as(u32, bytes[2]) << 16) |
            (@as(u32, bytes[3]) << 24);
    }
};
