//! Experimental XDM05 sparse-height source commitment/opening. An absent
//! height has zero source columns and uses the ordinary upper-parent hash;
//! it is not an inserted row of zero values. Distinct bytes leave XDM04
//! unchanged. This is not a production PCS or a CAS05 soundness theorem.

const std = @import("std");
const m31 = @import("../fields/m31.zig");
const tree = @import("transposed_merkle_cascade.zig");
const topology = @import("transposed_merkle.zig");

pub const M31 = tree.M31;
pub const Hash = tree.Hash;
pub const MAX_LOG_SIZE: u32 = 22;
// k <= 22 and at least eight rows at the final source height imply H <= 20.
pub const MAX_HEIGHTS: usize = 20;
pub const MAX_COLUMNS: usize = 256;

/// Sparse openings have O(query_count * height_count) rows. Keep their
/// admission bound separate from the older full-fiber XDM03 wire, whose
/// profile deliberately limits query_count * 2^height_count.
pub const Profile = struct {
    largest_log_size: u32,
    height_count: usize,
    columns: [MAX_HEIGHTS]u16,
    query_count: usize,

    pub fn validate(self: Profile) !void {
        if (self.height_count < 1 or self.height_count > MAX_HEIGHTS or
            self.largest_log_size < self.height_count + 2 or
            self.largest_log_size > MAX_LOG_SIZE or
            self.query_count == 0 or self.query_count > (1 << 14))
            return error.InvalidCascadeProfile;
        if (self.columns[0] == 0 or self.columns[self.height_count - 1] == 0)
            return error.InvalidCascadeProfile;
        for (self.columns[0..self.height_count]) |count|
            if (count > MAX_COLUMNS) return error.InvalidCascadeProfile;
        for (self.columns[self.height_count..]) |count|
            if (count != 0) return error.InvalidCascadeProfile;
        var per_query_bytes: usize = 4; // encoded raw position
        for (self.columns[0..self.height_count]) |count| {
            const row_bytes = std.math.mul(usize, 2 * @as(usize, count), @sizeOf(M31)) catch return error.InvalidCascadeProfile;
            per_query_bytes = std.math.add(usize, per_query_bytes, row_bytes) catch return error.InvalidCascadeProfile;
        }
        const fixed_bytes = std.math.mul(usize, self.query_count, per_query_bytes) catch return error.InvalidCascadeProfile;
        if (fixed_bytes > MAX_WIRE_BYTES - 128) return error.InvalidCascadeProfile;
    }
};
pub const MAGIC = "S31XDM05";
pub const VERSION: u16 = 5;
pub const MAX_WIRE_BYTES = tree.MAX_WIRE_BYTES;

/// Native bit-reversed pair required by the fold at source height `height`.
/// Circle doubling sends the selected raw point to either row in this pair;
/// the low sign bit is preserved while each squaring-fiber bit is removed.
pub fn pairBase(raw: usize, height: usize) usize {
    return (raw >> @intCast(height + 1)) << 1;
}

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
        return self.values[height][(query * 2 + row) * self.profile.columns[height] + column];
    }
};

const Header = struct { profile: Profile, root: Hash };

const Cursor = struct {
    bytes: []const u8,
    at: usize = 0,

    fn take(self: *Cursor, n: usize) ![]const u8 {
        if (n > self.bytes.len - self.at) return error.TruncatedSparseProof;
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
    fn felt(self: *Cursor) !M31 {
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
    if (c.bytes.len < MAGIC.len) return error.TruncatedSparseProof;
    if (!std.mem.eql(u8, c.bytes[0..MAGIC.len], MAGIC)) return error.UnsupportedProofFormat;
    if (c.bytes.len > MAX_WIRE_BYTES) return error.SparseProofTooLarge;
    _ = try c.take(MAGIC.len);
    if (try c.readU16() != VERSION) return error.UnsupportedProofVersion;
    if (try c.readU16() != 0) return error.InvalidSparseProof;
    const length = try c.readU32();
    if (length > c.bytes.len) return error.TruncatedSparseProof;
    if (length < c.bytes.len) return error.InvalidSparseProof;
    const log_size = try c.readU32();
    const height_count = try c.readU16();
    if (try c.readU16() != 0) return error.InvalidSparseProof;
    const query_count = try c.readU32();
    if (height_count < 1 or height_count > MAX_HEIGHTS) return error.InvalidCascadeProfile;
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

fn maxWitness(profile: Profile) usize {
    return profile.query_count * (4 * (profile.height_count - 1) +
        2 * @as(usize, profile.largest_log_size));
}

/// Parse the entire fragment canonically before outer transcript replay.
/// This does not authenticate rows or bind the sampled query sequence.
pub fn validateEncoding(encoded: []const u8, expected: Profile, expected_root: Hash) !void {
    var c = Cursor{ .bytes = encoded };
    const header = try parseHeader(&c);
    if (!std.meta.eql(header.profile, expected)) return error.UnexpectedSparseProfile;
    if (!std.mem.eql(u8, &header.root, &expected_root)) return error.UnexpectedSparseRoot;
    for (0..expected.query_count) |_| {
        if (try c.readU32() >= (@as(usize, 1) << @intCast(expected.largest_log_size)))
            return error.QueryPositionOutOfRange;
        for (0..expected.height_count) |height| {
            for (0..2 * expected.columns[height]) |_| {
                _ = try c.felt();
            }
        }
    }
    const count = try c.readU32();
    if (count > maxWitness(expected)) return error.InvalidSparseProof;
    _ = try c.take(@as(usize, count) * @sizeOf(Hash));
    if (c.at != encoded.len) return error.InvalidSparseProof;
}

fn key(level: usize, index: usize) u64 {
    return (@as(u64, @intCast(level)) << 32) | @as(u64, @intCast(index));
}

fn putNode(nodes: *std.AutoHashMap(u64, Hash), level: usize, index: usize, value: Hash) !void {
    const address = key(level, index);
    if (nodes.get(address)) |previous| {
        if (!std.mem.eql(u8, &previous, &value)) return error.DuplicateProjectedValue;
    } else try nodes.put(address, value);
}

fn childHash(nodes: *std.AutoHashMap(u64, Hash), c: *Cursor, level: usize, index: usize, used: *usize, count: usize) !Hash {
    if (nodes.get(key(level, index))) |known| return known;
    if (used.* == count) return error.WitnessTooShort;
    const witness = try c.hash();
    used.* += 1;
    try nodes.put(key(level, index), witness);
    return witness;
}

/// Complete sparse source authentication against an independently supplied
/// root and exact sampled raw positions. Values leave only after root check.
pub fn verifyAndCollect(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    expected: Profile,
    expected_root: Hash,
    raw_queries: []const usize,
) !VerifiedOpenings {
    var c = Cursor{ .bytes = encoded };
    const header = try parseHeader(&c);
    if (!std.meta.eql(header.profile, expected) or raw_queries.len != expected.query_count)
        return error.UnexpectedSparseProfile;
    if (!std.mem.eql(u8, &header.root, &expected_root)) return error.UnexpectedSparseRoot;
    const values = try allocator.alloc([]M31, expected.height_count);
    var built: usize = 0;
    errdefer {
        for (values[0..built]) |height| allocator.free(height);
        allocator.free(values);
    }
    while (built < expected.height_count) : (built += 1)
        values[built] = try allocator.alloc(M31, expected.query_count * 2 * expected.columns[built]);
    var first_rows = std.AutoHashMap(u64, usize).init(allocator);
    defer first_rows.deinit();
    for (raw_queries, 0..) |raw, query| {
        if (raw >= (@as(usize, 1) << @intCast(expected.largest_log_size)) or try c.readU32() != raw)
            return error.UnexpectedSparseQuery;
        for (0..expected.height_count) |height| {
            const cols = expected.columns[height];
            const base = pairBase(raw, height);
            for (0..2) |j| {
                const offset = (query * 2 + j) * cols;
                for (values[height][offset..][0..cols]) |*value| value.* = try c.felt();
                const address = key(height, base + j);
                if (first_rows.get(address)) |previous| {
                    for (values[height][previous..][0..cols], values[height][offset..][0..cols]) |left, right|
                        if (!left.eql(right)) return error.DuplicateProjectedValue;
                } else try first_rows.put(address, offset);
            }
        }
    }
    const count = try c.readU32();
    if (count > maxWitness(expected) or c.bytes.len - c.at < @as(usize, count) * @sizeOf(Hash))
        return error.InvalidSparseProof;
    var used: usize = 0;
    var nodes = std.AutoHashMap(u64, Hash).init(allocator);
    defer nodes.deinit();
    const k: usize = expected.largest_log_size;
    for (raw_queries, 0..) |raw, query| {
        const base = pairBase(raw, 0);
        for (0..2) |j| {
            const cols = expected.columns[0];
            const offset = (query * 2 + j) * cols;
            try putNode(&nodes, k, base + j, tree.hashLeaf(values[0][offset..][0..cols]));
        }
    }
    for (1..expected.height_count) |height| {
        const level = k - height;
        for (raw_queries, 0..) |raw, query| {
            const base = pairBase(raw, height);
            for (0..2) |j| {
                const index = base + j;
                const children = topology.children(@intCast(level), index);
                const left = try childHash(&nodes, &c, level + 1, children[0], &used, count);
                const right = try childHash(&nodes, &c, level + 1, children[1], &used, count);
                const cols = expected.columns[height];
                const offset = (query * 2 + j) * cols;
                try putNode(&nodes, level, index, if (cols == 0)
                    tree.hashUpper(left, right)
                else
                    tree.hashInserted(left, right, values[height][offset..][0..cols]));
            }
        }
    }
    const bottom = k - expected.height_count + 1;
    var active = std.ArrayList(usize).empty;
    defer active.deinit(allocator);
    for (raw_queries) |raw| {
        const base = pairBase(raw, expected.height_count - 1);
        try active.append(allocator, base);
        try active.append(allocator, base + 1);
    }
    var level = bottom;
    while (level > 0) : (level -= 1) {
        std.sort.heap(usize, active.items, {}, std.sort.asc(usize));
        var next = std.ArrayList(usize).empty;
        errdefer next.deinit(allocator);
        for (active.items, 0..) |index, position| {
            if (position > 0 and index == active.items[position - 1]) continue;
            const own = nodes.get(key(level, index)) orelse return error.InvalidSparseProjection;
            const sibling_index = topology.sibling(@intCast(level), index);
            _ = try childHash(&nodes, &c, level, sibling_index, &used, count);
            const parent = topology.parent(@intCast(level), index);
            const children = topology.children(@intCast(level - 1), parent);
            const left = nodes.get(key(level, children[0])) orelse return error.InvalidSparseProjection;
            const right = nodes.get(key(level, children[1])) orelse return error.InvalidSparseProjection;
            _ = own;
            try putNode(&nodes, level - 1, parent, tree.hashUpper(left, right));
            try next.append(allocator, parent);
        }
        active.deinit(allocator);
        active = next;
    }
    if (used != count) return error.WitnessTooLong;
    const root = nodes.get(key(0, 0)) orelse return error.RootMismatch;
    if (!std.mem.eql(u8, &root, &expected_root)) return error.RootMismatch;
    if (c.at != encoded.len) return error.InvalidSparseProof;
    return .{ .allocator = allocator, .profile = expected, .values = values };
}
