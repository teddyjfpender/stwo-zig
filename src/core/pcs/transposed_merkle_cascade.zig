//! Experimental multi-height transposed source tree. One root commits every
//! adjacent source height; values at height k-i enter level k-i. The byte
//! format and hash tags are distinct from XDM02 and never admitted by PCS.

const std = @import("std");
const m31 = @import("../fields/m31.zig");
const blake2 = @import("../vcs/blake2_hash.zig");
const topology = @import("transposed_merkle.zig");

pub const M31 = m31.M31;
pub const Hash = blake2.Blake2sHash;
pub const MAGIC = "S31XDM03";
pub const VERSION: u16 = 3;
pub const MAX_HEIGHTS: usize = 8;
pub const MAX_COLUMNS: usize = 64;
pub const MAX_LOG_SIZE: u32 = 16;
pub const MAX_WIRE_BYTES: usize = 64 * 1024 * 1024;

pub const Profile = struct {
    largest_log_size: u32,
    height_count: usize,
    columns: [MAX_HEIGHTS]u16,
    query_count: usize,

    pub fn validate(self: Profile) !void {
        if (self.height_count < 2 or self.height_count > MAX_HEIGHTS or
            self.largest_log_size < self.height_count + 2 or
            self.largest_log_size > MAX_LOG_SIZE or
            self.query_count == 0 or self.query_count > (1 << 14) or
            self.query_count * (@as(usize, 1) << @intCast(self.height_count)) > (1 << 16))
            return error.InvalidCascadeProfile;
        for (self.columns[0..self.height_count]) |count| {
            if (count == 0 or count > MAX_COLUMNS) return error.InvalidCascadeProfile;
        }
        for (self.columns[self.height_count..]) |count| {
            if (count != 0) return error.InvalidCascadeProfile;
        }
        var per_query_bytes: usize = 4; // encoded raw row
        for (0..self.height_count) |height|
            per_query_bytes += self.width(height) * self.columns[height] * @sizeOf(M31);
        if (self.query_count * per_query_bytes > MAX_WIRE_BYTES - 128)
            return error.InvalidCascadeProfile;
    }

    pub fn width(self: Profile, height: usize) usize {
        return @as(usize, 1) << @intCast(self.height_count - height);
    }

    pub fn bottomLevel(self: Profile) usize {
        return self.largest_log_size - @as(u32, @intCast(self.height_count)) + 1;
    }
};

pub const VerifiedOpenings = struct {
    allocator: std.mem.Allocator,
    profile: Profile,
    values: [][]M31,

    pub fn deinit(self: *VerifiedOpenings) void {
        for (self.values) |height| self.allocator.free(height);
        self.allocator.free(self.values);
        self.* = undefined;
    }

    pub fn at(self: VerifiedOpenings, height: usize, query: usize, row: usize, column: usize) M31 {
        return self.values[height][
            (query * self.profile.width(height) + row) * self.profile.columns[height] + column
        ];
    }
};

pub const Header = struct { profile: Profile, root: Hash };

pub fn hashLeaf(values: []const M31) Hash {
    var h = blake2.Blake2sHasher.init();
    h.update("S31XDL03");
    hashValues(&h, values);
    return h.finalize();
}
pub fn hashUpper(left: Hash, right: Hash) Hash {
    var h = blake2.Blake2sHasher.init();
    h.update("S31XDU03");
    h.update(&left);
    h.update(&right);
    return h.finalize();
}
pub fn hashInserted(left: Hash, right: Hash, values: []const M31) Hash {
    const pair = hashUpper(left, right);
    var h = blake2.Blake2sHasher.init();
    h.update("S31XDI03");
    h.update(&pair);
    hashValues(&h, values);
    return h.finalize();
}
fn hashValues(h: *blake2.Blake2sHasher, values: []const M31) void {
    var count: [2]u8 = undefined;
    std.mem.writeInt(u16, &count, @intCast(values.len), .little);
    h.update(&count);
    for (values) |value| {
        const bytes = value.toBytesLe();
        h.update(&bytes);
    }
}

const Cursor = struct {
    bytes: []const u8,
    at: usize = 0,
    fn take(self: *Cursor, n: usize) ![]const u8 {
        if (n > self.bytes.len - self.at) return error.TruncatedCascadeProof;
        const result = self.bytes[self.at..][0..n];
        self.at += n;
        return result;
    }
    fn readU16(self: *Cursor) !u16 {
        return std.mem.readInt(u16, (try self.take(2))[0..2], .little);
    }
    fn readU32(self: *Cursor) !u32 {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .little);
    }
    fn readM31(self: *Cursor) !M31 {
        const value = try self.readU32();
        if (value >= m31.Modulus) return error.NonCanonicalM31;
        return M31.fromCanonical(value);
    }
    fn hash(self: *Cursor) !Hash {
        var result: Hash = undefined;
        @memcpy(&result, try self.take(result.len));
        return result;
    }
};

fn parseHeader(c: *Cursor) !Header {
    if (c.bytes.len < MAGIC.len) return error.TruncatedCascadeProof;
    if (!std.mem.eql(u8, c.bytes[0..MAGIC.len], MAGIC)) return error.UnsupportedProofFormat;
    if (c.bytes.len > MAX_WIRE_BYTES) return error.CascadeProofTooLarge;
    _ = try c.take(MAGIC.len);
    if (try c.readU16() != VERSION) return error.UnsupportedProofVersion;
    if (try c.readU16() != 0) return error.InvalidCascadeProof;
    if (try c.readU32() != c.bytes.len) return error.InvalidCascadeProof;
    const log_size = try c.readU32();
    const height_count = try c.readU16();
    if (try c.readU16() != 0) return error.InvalidCascadeProof;
    const query_count = try c.readU32();
    if (height_count < 2 or height_count > MAX_HEIGHTS) return error.InvalidCascadeProfile;
    var columns = [_]u16{0} ** MAX_HEIGHTS;
    for (columns[0..height_count]) |*count| count.* = try c.readU16();
    const profile = Profile{
        .largest_log_size = log_size,
        .height_count = height_count,
        .columns = columns,
        .query_count = query_count,
    };
    try profile.validate();
    return .{ .profile = profile, .root = try c.hash() };
}

pub fn inspectHeader(encoded: []const u8) !Header {
    var c = Cursor{ .bytes = encoded };
    return parseHeader(&c);
}

/// Parse every field canonically without treating source values as trusted.
/// Outer decoders use this before transcript replay. Query agreement and the
/// Merkle root are checked separately by verifyAndCollect after sampling.
pub fn validateEncoding(
    encoded: []const u8,
    expected: Profile,
    expected_root: Hash,
) !void {
    try expected.validate();
    var c = Cursor{ .bytes = encoded };
    const header = try parseHeader(&c);
    if (!std.meta.eql(header.profile, expected)) return error.UnexpectedCascadeProfile;
    if (!std.mem.eql(u8, &header.root, &expected_root)) return error.UnexpectedCascadeRoot;
    for (0..expected.query_count) |_| {
        if (try c.readU32() >= (@as(usize, 1) << @intCast(expected.largest_log_size)))
            return error.QueryPositionOutOfRange;
        for (0..expected.height_count) |height| {
            const count = expected.width(height) * expected.columns[height];
            for (0..count) |_| _ = try c.readM31();
        }
    }
    const witness_count = try c.readU32();
    if (witness_count > (@as(usize, 1) << @intCast(expected.bottomLevel())))
        return error.InvalidCascadeProof;
    _ = try c.take(@as(usize, witness_count) * @sizeOf(Hash));
    if (c.at != encoded.len) return error.InvalidCascadeProof;
}

/// Source rows leave this function only after the complete one-root multiproof
/// matches the verifier's root and exact raw query sequence.
pub fn verifyAndCollect(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    expected: Profile,
    expected_root: Hash,
    raw_queries: []const usize,
) !VerifiedOpenings {
    try expected.validate();
    var c = Cursor{ .bytes = encoded };
    const header = try parseHeader(&c);
    if (!std.meta.eql(header.profile, expected) or raw_queries.len != expected.query_count)
        return error.UnexpectedCascadeProfile;
    if (!std.mem.eql(u8, &header.root, &expected_root)) return error.UnexpectedCascadeRoot;
    const values = try allocator.alloc([]M31, expected.height_count);
    var built: usize = 0;
    errdefer {
        for (values[0..built]) |height| allocator.free(height);
        allocator.free(values);
    }
    while (built < expected.height_count) : (built += 1)
        values[built] = try allocator.alloc(M31, expected.query_count * expected.width(built) * expected.columns[built]);
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const levels = try a.alloc([]Hash, expected.largest_log_size + 1);
    const known = try a.alloc([]bool, expected.largest_log_size + 1);
    const active = try a.alloc([]bool, expected.largest_log_size + 1);
    for (levels, known, active, 0..) |*hashes, *bits, *frontier, level| {
        const count = @as(usize, 1) << @intCast(level);
        hashes.* = try a.alloc(Hash, count);
        bits.* = try a.alloc(bool, count);
        frontier.* = try a.alloc(bool, count);
        @memset(bits.*, false);
        @memset(frontier.*, false);
    }
    const k: usize = expected.largest_log_size;
    const bottom = expected.bottomLevel();
    for (raw_queries, 0..) |raw, query| {
        if (raw >= (@as(usize, 1) << @intCast(k)) or try c.readU32() != raw)
            return error.UnexpectedCascadeQuery;
        const base = raw & ~(expected.width(0) - 1);
        for (0..expected.height_count) |height| {
            const level = k - height;
            const width = expected.width(height);
            const row_base = base >> @intCast(height);
            const cols = expected.columns[height];
            for (0..width) |j| {
                var row: [MAX_COLUMNS]M31 = undefined;
                for (row[0..cols], 0..) |*value, col| {
                    value.* = try c.readM31();
                    values[height][(query * width + j) * cols + col] = value.*;
                }
                const index = row_base + j;
                const node = if (height == 0)
                    hashLeaf(row[0..cols])
                else blk: {
                    const pair = topology.children(@intCast(level), index);
                    if (!known[level + 1][pair[0]] or !known[level + 1][pair[1]])
                        return error.InvalidCascadeProjection;
                    break :blk hashInserted(levels[level + 1][pair[0]], levels[level + 1][pair[1]], row[0..cols]);
                };
                if (known[level][index] and !std.mem.eql(u8, &levels[level][index], &node))
                    return error.DuplicateProjectedValue;
                levels[level][index] = node;
                known[level][index] = true;
                if (height + 1 == expected.height_count) active[level][index] = true;
            }
        }
    }
    const witness_count = try c.readU32();
    if (witness_count > (@as(usize, 1) << @intCast(bottom))) return error.InvalidCascadeProof;
    if (c.bytes.len - c.at < @as(usize, witness_count) * @sizeOf(Hash))
        return error.TruncatedCascadeProof;
    var used: usize = 0;
    var level = bottom;
    while (level > 0) : (level -= 1) {
        for (active[level], 0..) |is_active, index| {
            if (!is_active) continue;
            const other = topology.sibling(@intCast(level), index);
            if (!known[level][other]) {
                if (used == witness_count) return error.WitnessTooShort;
                levels[level][other] = try c.hash();
                known[level][other] = true;
                used += 1;
            }
            const parent_index = topology.parent(@intCast(level), index);
            if (!known[level - 1][parent_index]) {
                const pair = topology.children(@intCast(level - 1), parent_index);
                levels[level - 1][parent_index] =
                    hashUpper(levels[level][pair[0]], levels[level][pair[1]]);
                known[level - 1][parent_index] = true;
                active[level - 1][parent_index] = true;
            }
        }
    }
    if (used != witness_count) return error.WitnessTooLong;
    if (!known[0][0] or !std.mem.eql(u8, &levels[0][0], &expected_root))
        return error.RootMismatch;
    if (c.at != encoded.len) return error.InvalidCascadeProof;
    return .{ .allocator = allocator, .profile = expected, .values = values };
}
