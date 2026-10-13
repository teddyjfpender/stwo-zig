//! Versioned experimental two-height source commitment in the transposed
//! cross-domain layout of S-two whitepaper Algorithm 1. Production PCS never
//! dispatches to this wire. Hash framing is domain separated and specific to
//! this experimental version; the topology, not byte-for-byte paper hashes,
//! follows Eq. 87.

const std = @import("std");
const m31 = @import("../fields/m31.zig");
const blake2 = @import("../vcs/blake2_hash.zig");

pub const M31 = m31.M31;
pub const Hash = blake2.Blake2sHash;
pub const MAGIC = "S31XDM02";
pub const VERSION: u16 = 2;
pub const MAX_LOG_SIZE: u32 = 16;
pub const MAX_COLUMNS: usize = 64;
pub const MAX_WIRE_BYTES: usize = 64 * 1024 * 1024;

pub const Profile = struct {
    log_size: u32,
    large_columns: usize,
    small_columns: usize,
    query_count: usize,

    pub fn validate(self: Profile) !void {
        if (self.log_size < 3 or self.log_size > MAX_LOG_SIZE or
            self.large_columns == 0 or self.large_columns > MAX_COLUMNS or
            self.small_columns == 0 or self.small_columns > MAX_COLUMNS or
            self.query_count == 0 or self.query_count > (1 << 14))
        {
            return error.InvalidCrossDomainProfile;
        }
    }
};

/// Authenticated source values. The verifier returns this only after the
/// entire multiproof and expected root have passed. Values are row-major:
/// largest domain [query][four-row bundle][column], smaller domain
/// [query][two projected rows][column].
pub const VerifiedOpenings = struct {
    allocator: std.mem.Allocator,
    profile: Profile,
    large_values: []M31,
    small_values: []M31,

    pub fn deinit(self: *VerifiedOpenings) void {
        self.allocator.free(self.large_values);
        self.allocator.free(self.small_values);
        self.* = undefined;
    }

    pub fn largeAt(self: VerifiedOpenings, query: usize, row: usize, column: usize) M31 {
        return self.large_values[(query * 4 + row) * self.profile.large_columns + column];
    }

    pub fn smallAt(self: VerifiedOpenings, query: usize, row: usize, column: usize) M31 {
        return self.small_values[(query * 2 + row) * self.profile.small_columns + column];
    }
};

/// A node at level `level` has its two preimages at the next larger circle
/// height. The native index is bit-reversed; bit 1 is the squaring-fiber bit.
pub fn children(level: u32, index: usize) [2]usize {
    if (level == 0) return .{ 0, 1 };
    const first = (index & 1) | ((index >> 1) << 2);
    return .{ first, first | 2 };
}

pub fn parent(level: u32, index: usize) usize {
    if (level == 1) return 0;
    return (index & 1) | ((index >> 2) << 1);
}

pub fn sibling(level: u32, index: usize) usize {
    return index ^ (if (level == 1) @as(usize, 1) else @as(usize, 2));
}

pub fn hashLeaf(values: []const M31) Hash {
    var h = blake2.Blake2sHasher.init();
    h.update("S31XDL02");
    hashValues(&h, values);
    return h.finalize();
}

pub fn hashUpper(left: Hash, right: Hash) Hash {
    var h = blake2.Blake2sHasher.init();
    h.update("S31XDU02");
    h.update(&left);
    h.update(&right);
    return h.finalize();
}

pub fn hashInserted(left: Hash, right: Hash, values: []const M31) Hash {
    const pair = hashUpper(left, right);
    var h = blake2.Blake2sHasher.init();
    h.update("S31XDI02");
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
        if (n > self.bytes.len - self.at) return error.TruncatedCrossDomainProof;
        const result = self.bytes[self.at..][0..n];
        self.at += n;
        return result;
    }

    fn readU16(self: *Cursor) !u16 {
        const bytes = try self.take(2);
        return std.mem.readInt(u16, &bytes[0..2].*, .little);
    }
    fn readU32(self: *Cursor) !u32 {
        const bytes = try self.take(4);
        return std.mem.readInt(u32, &bytes[0..4].*, .little);
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

/// Check one S31XDM02 source proof against an externally chosen root, geometry,
/// and Fiat-Shamir raw query sequence. Every raw query authenticates its four
/// source rows and the two projected smaller-height rows. Repeated raw queries
/// remain accepted only when all repeated values and paths authenticate.
pub fn verifyWire(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    expected: Profile,
    expected_root: Hash,
    raw_queries: []const usize,
) !void {
    return verifyImpl(allocator, encoded, expected, expected_root, raw_queries, null);
}

pub fn verifyAndCollect(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    expected: Profile,
    expected_root: Hash,
    raw_queries: []const usize,
) !VerifiedOpenings {
    try expected.validate();
    var result = VerifiedOpenings{
        .allocator = allocator,
        .profile = expected,
        .large_values = try allocator.alloc(M31, expected.query_count * 4 * expected.large_columns),
        .small_values = undefined,
    };
    errdefer allocator.free(result.large_values);
    result.small_values = try allocator.alloc(M31, expected.query_count * 2 * expected.small_columns);
    errdefer allocator.free(result.small_values);
    try verifyImpl(allocator, encoded, expected, expected_root, raw_queries, &result);
    return result;
}

fn verifyImpl(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    expected: Profile,
    expected_root: Hash,
    raw_queries: []const usize,
    output: ?*VerifiedOpenings,
) !void {
    try expected.validate();
    if (encoded.len < MAGIC.len) return error.TruncatedCrossDomainProof;
    if (!std.mem.eql(u8, encoded[0..MAGIC.len], MAGIC)) return error.UnsupportedProofFormat;
    if (encoded.len > MAX_WIRE_BYTES) return error.CrossDomainProofTooLarge;
    var c = Cursor{ .bytes = encoded };
    _ = try c.take(MAGIC.len);
    if (try c.readU16() != VERSION) return error.UnsupportedProofVersion;
    if (try c.readU16() != 0) return error.InvalidCrossDomainProof;
    if (try c.readU32() != encoded.len) return error.InvalidCrossDomainProof;
    const profile = Profile{
        .log_size = try c.readU32(),
        .large_columns = try c.readU16(),
        .small_columns = try c.readU16(),
        .query_count = try c.readU32(),
    };
    if (!std.meta.eql(profile, expected) or raw_queries.len != expected.query_count)
        return error.UnexpectedCrossDomainProfile;
    const root = try c.hash();
    if (!std.mem.eql(u8, &root, &expected_root)) return error.UnexpectedCrossDomainRoot;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const level_count: usize = profile.log_size;
    const nodes = try a.alloc([]Hash, level_count);
    const active = try a.alloc([]bool, level_count);
    const known = try a.alloc([]bool, level_count);
    for (0..level_count) |level| {
        const count = @as(usize, 1) << @intCast(level);
        nodes[level] = try a.alloc(Hash, count);
        active[level] = try a.alloc(bool, count);
        known[level] = try a.alloc(bool, count);
        @memset(active[level], false);
        @memset(known[level], false);
    }
    for (raw_queries, 0..) |raw, query_index| {
        const encoded_raw = try c.readU32();
        if (raw >= (@as(usize, 1) << @intCast(profile.log_size)) or encoded_raw != raw)
            return error.UnexpectedCrossDomainQuery;
        const base = raw & ~@as(usize, 3);
        var leaves: [4]Hash = undefined;
        for (0..4) |j| {
            var large: [MAX_COLUMNS]M31 = undefined;
            for (large[0..profile.large_columns]) |*value| value.* = try c.felt();
            if (output) |out| @memcpy(
                out.large_values[(query_index * 4 + j) * profile.large_columns ..][0..profile.large_columns],
                large[0..profile.large_columns],
            );
            leaves[j] = hashLeaf(large[0..profile.large_columns]);
        }
        for (0..2) |j| {
            var small: [MAX_COLUMNS]M31 = undefined;
            for (small[0..profile.small_columns]) |*value| value.* = try c.felt();
            if (output) |out| @memcpy(
                out.small_values[(query_index * 2 + j) * profile.small_columns ..][0..profile.small_columns],
                small[0..profile.small_columns],
            );
            const index = ((base >> 2) << 1) + j;
            const value = hashInserted(leaves[j], leaves[j + 2], small[0..profile.small_columns]);
            if (known[level_count - 1][index] and
                !std.mem.eql(u8, &nodes[level_count - 1][index], &value))
                return error.DuplicateProjectedValue;
            nodes[level_count - 1][index] = value;
            known[level_count - 1][index] = true;
            active[level_count - 1][index] = true;
        }
    }
    const witness_count = try c.readU32();
    if (witness_count > (@as(u32, 1) << @intCast(profile.log_size))) return error.InvalidCrossDomainProof;
    if (c.bytes.len - c.at < @as(usize, witness_count) * @sizeOf(Hash))
        return error.TruncatedCrossDomainProof;
    var used: usize = 0;
    var level = level_count - 1;
    while (level > 0) : (level -= 1) {
        for (active[level], 0..) |is_active, index| {
            if (!is_active) continue;
            const other = sibling(@intCast(level), index);
            if (!known[level][other]) {
                if (used == witness_count) return error.WitnessTooShort;
                nodes[level][other] = try c.hash();
                known[level][other] = true;
                used += 1;
            }
            const parent_index = parent(@intCast(level), index);
            if (!known[level - 1][parent_index]) {
                const pair = children(@intCast(level - 1), parent_index);
                nodes[level - 1][parent_index] = hashUpper(nodes[level][pair[0]], nodes[level][pair[1]]);
                known[level - 1][parent_index] = true;
                active[level - 1][parent_index] = true;
            }
        }
    }
    if (used != witness_count) return error.WitnessTooLong;
    if (!known[0][0] or !std.mem.eql(u8, &nodes[0][0], &root)) return error.RootMismatch;
    if (c.at != encoded.len) return error.InvalidCrossDomainProof;
}
