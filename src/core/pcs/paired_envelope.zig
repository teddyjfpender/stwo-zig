//! Versioned experimental source-opening envelope for paired multi-height FRI.
//!
//! This wire contract carries authenticated source openings at each height.
//! It intentionally does not claim to be a complete PCS proof by itself. A
//! separate experimental two-height outer proof wraps this source fragment
//! with one committed line layer and its opening checks. Generic height
//! cascades and production verifier admission remain unimplemented.

const std = @import("std");
const circle = @import("../circle.zig");
const m31 = @import("../fields/m31.zig");
const qm31 = @import("../fields/qm31.zig");
const blake2_merkle = @import("../vcs_lifted/blake2_merkle.zig");
const vcs_verifier = @import("../vcs_lifted/verifier.zig");
const paired = @import("paired_ensemble.zig");
const projection = @import("paired_projection.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
pub const Hasher = blake2_merkle.Blake2sMerkleHasher;
pub const Hash = Hasher.Hash;
pub const VERSION: u16 = 1;
pub const MAGIC = "S31PMH01";
const LEGACY_MAGIC = "STWOPRW1";
const TRANSCRIPT_TAG: u64 = 0x5333_3150_4d48_3031; // S31PMH01
const MAX_WIRE_BYTES: usize = 64 * 1024 * 1024;
const MAX_QUERY_COUNT: usize = 1 << 16;
const MAX_COLUMNS_PER_HEIGHT: usize = 64;
const MAX_HASH_WITNESS: usize = 1 << 20;

pub const HeightOpening = struct {
    shape: paired.Shape,
    source_root: Hash,
    sample_points: []const circle.CirclePointQM31,
    sample_values: []const QM31,
    /// Column-major, each in the projected largest-query order.
    queried_sources: []const []const M31,
    hash_witness: []Hash,
};

pub const Envelope = struct {
    largest_log_size: u32,
    query_count: u32,
    heights: []const HeightOpening,

    pub fn validate(self: Envelope) !void {
        if (self.largest_log_size < 2 or self.largest_log_size > 30 or
            self.query_count == 0 or self.query_count > MAX_QUERY_COUNT or
            self.heights.len == 0 or self.heights.len > 29 or
            self.heights[0].shape.log_domain_size != self.largest_log_size)
        {
            return error.InvalidPairedEnvelope;
        }
        self.heights[0].shape.validate() catch return error.InvalidPairedEnvelope;
        const blowup = self.heights[0].shape.log_domain_size - self.heights[0].shape.log_degree_bound;
        for (self.heights, 0..) |height, i| {
            height.shape.validate() catch return error.InvalidPairedEnvelope;
            if (height.shape.original_column_count > MAX_COLUMNS_PER_HEIGHT or
                height.shape.log_domain_size - height.shape.log_degree_bound != blowup or
                height.sample_points.len != height.shape.original_column_count or
                height.sample_values.len != height.shape.original_column_count or
                height.queried_sources.len != height.shape.original_column_count or
                height.hash_witness.len > MAX_HASH_WITNESS)
            {
                return error.InvalidPairedEnvelope;
            }
            if (i > 0 and self.heights[i - 1].shape.log_domain_size != height.shape.log_domain_size + 1)
                return error.InvalidPairedEnvelope;
            for (height.sample_points, height.queried_sources) |point, column| {
                if (!point.x.square().add(point.y.square()).eql(QM31.one()) or
                    column.len != self.query_count)
                {
                    return error.InvalidPairedEnvelope;
                }
            }
        }
    }
};

pub const Decoded = struct {
    arena: std.heap.ArenaAllocator,
    envelope: Envelope,

    pub fn deinit(self: *Decoded) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub const Prepared = struct {
    decoded: Decoded,
    challenges: paired.Challenges,

    pub fn deinit(self: *Prepared) void {
        self.decoded.deinit();
        self.* = undefined;
    }
};

/// Security-relevant geometry is chosen by the verifier, not by the proof.
pub const ExpectedProfile = struct {
    largest_log_size: u32,
    query_count: u32,
    shapes: []const paired.Shape,

    pub fn matches(self: ExpectedProfile, envelope: Envelope) bool {
        if (self.largest_log_size != envelope.largest_log_size or
            self.query_count != envelope.query_count or
            self.shapes.len != envelope.heights.len)
        {
            return false;
        }
        for (self.shapes, envelope.heights) |shape, height| {
            if (shape.log_domain_size != height.shape.log_domain_size or
                shape.log_degree_bound != height.shape.log_degree_bound or
                shape.original_column_count != height.shape.original_column_count)
            {
                return false;
            }
        }
        return true;
    }
};

/// The first eight bytes select the mode before any transcript operation.
/// Legacy proofs are explicitly directed away from this experimental decoder.
pub fn classify(encoded: []const u8) !void {
    if (encoded.len < MAGIC.len) return error.TruncatedPairedEnvelope;
    if (std.mem.eql(u8, encoded[0..MAGIC.len], LEGACY_MAGIC))
        return error.LegacyProofRequiresLegacyVerifier;
    if (!std.mem.eql(u8, encoded[0..MAGIC.len], MAGIC))
        return error.UnsupportedProofFormat;
}

pub fn encode(allocator: std.mem.Allocator, envelope: Envelope) ![]u8 {
    try envelope.validate();
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    const writer = out.writer(allocator);
    try writer.writeAll(MAGIC);
    try writer.writeInt(u16, VERSION, .little);
    try writer.writeInt(u16, 0, .little);
    try writer.writeInt(u32, 0, .little); // total length, patched below
    try writer.writeInt(u32, envelope.largest_log_size, .little);
    try writer.writeInt(u32, envelope.query_count, .little);
    try writer.writeInt(u32, @intCast(envelope.heights.len), .little);
    for (envelope.heights) |height| {
        try writer.writeInt(u32, height.shape.log_domain_size, .little);
        try writer.writeInt(u32, height.shape.log_degree_bound, .little);
        try writer.writeInt(u32, height.shape.original_column_count, .little);
        try writer.writeAll(&height.source_root);
        for (height.sample_points, height.sample_values, height.queried_sources) |point, claim, source| {
            try writeQM31(writer, point.x);
            try writeQM31(writer, point.y);
            try writeQM31(writer, claim);
            for (source) |value| try writer.writeInt(u32, value.toU32(), .little);
        }
        try writer.writeInt(u32, @intCast(height.hash_witness.len), .little);
        for (height.hash_witness) |hash| try writer.writeAll(&hash);
        if (out.items.len > MAX_WIRE_BYTES) return error.PairedEnvelopeTooLarge;
    }
    if (out.items.len > MAX_WIRE_BYTES) return error.PairedEnvelopeTooLarge;
    const bytes = try out.toOwnedSlice(allocator);
    std.mem.writeInt(u32, bytes[12..16], @intCast(bytes.len), .little);
    return bytes;
}

pub fn decode(allocator: std.mem.Allocator, encoded: []const u8) !Decoded {
    try classify(encoded);
    if (encoded.len > MAX_WIRE_BYTES) return error.PairedEnvelopeTooLarge;
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    var cursor = Cursor{ .bytes = encoded };
    _ = try cursor.readBytes(MAGIC.len);
    if (try cursor.readU16() != VERSION) return error.UnsupportedProofVersion;
    if (try cursor.readU16() != 0) return error.InvalidPairedEnvelope;
    if (try cursor.readU32() != encoded.len) return error.InvalidPairedEnvelope;
    const largest_log_size = try cursor.readU32();
    const query_count = try cursor.readU32();
    const height_count = try cursor.readU32();
    if (largest_log_size < 2 or largest_log_size > 30 or
        query_count == 0 or query_count > MAX_QUERY_COUNT or
        height_count == 0 or height_count > 29)
    {
        return error.InvalidPairedEnvelope;
    }
    const heights = try a.alloc(HeightOpening, height_count);
    for (heights) |*height| {
        const shape = paired.Shape{
            .log_domain_size = try cursor.readU32(),
            .log_degree_bound = try cursor.readU32(),
            .original_column_count = try cursor.readU32(),
        };
        shape.validate() catch return error.InvalidPairedEnvelope;
        if (shape.original_column_count > MAX_COLUMNS_PER_HEIGHT) return error.InvalidPairedEnvelope;
        var root: Hash = undefined;
        @memcpy(&root, try cursor.readBytes(root.len));
        const n_cols: usize = @intCast(shape.original_column_count);
        const points = try a.alloc(circle.CirclePointQM31, n_cols);
        const claims = try a.alloc(QM31, n_cols);
        const queried = try a.alloc([]const M31, n_cols);
        for (points, claims, queried) |*point, *claim, *column| {
            point.* = .{ .x = try cursor.readQM31(), .y = try cursor.readQM31() };
            claim.* = try cursor.readQM31();
            if (cursor.bytes.len - cursor.at < @as(usize, query_count) * @sizeOf(u32))
                return error.TruncatedPairedEnvelope;
            const values = try a.alloc(M31, query_count);
            for (values) |*value| value.* = try cursor.readM31();
            column.* = values;
        }
        const witness_count = try cursor.readU32();
        if (witness_count > MAX_HASH_WITNESS) return error.InvalidPairedEnvelope;
        if (cursor.bytes.len - cursor.at < @as(usize, witness_count) * @sizeOf(Hash))
            return error.TruncatedPairedEnvelope;
        const witnesses = try a.alloc(Hash, witness_count);
        for (witnesses) |*hash| @memcpy(hash, try cursor.readBytes(hash.len));
        height.* = .{
            .shape = shape,
            .source_root = root,
            .sample_points = points,
            .sample_values = claims,
            .queried_sources = queried,
            .hash_witness = witnesses,
        };
    }
    if (cursor.at != encoded.len) return error.InvalidPairedEnvelope;
    const envelope = Envelope{
        .largest_log_size = largest_log_size,
        .query_count = query_count,
        .heights = heights,
    };
    try envelope.validate();
    return .{ .arena = arena, .envelope = envelope };
}

/// Experimental transcript schedule. The caller must only sample FRI queries
/// after all future FRI layer commitments have been mixed. In particular,
/// this function alone does not provide a complete Fiat–Shamir protocol.
pub fn drawChallenges(channel: anytype, envelope: Envelope) !paired.Challenges {
    try envelope.validate();
    channel.mixU64(TRANSCRIPT_TAG);
    channel.mixU64(VERSION);
    channel.mixU64(envelope.largest_log_size);
    channel.mixU64(envelope.query_count);
    channel.mixU64(envelope.heights.len);
    for (envelope.heights) |height| {
        channel.mixU64((@as(u64, height.shape.log_domain_size) << 32) | height.shape.log_degree_bound);
        channel.mixU64(height.shape.original_column_count);
        blake2_merkle.Blake2sMerkleChannel.mixRoot(channel, height.source_root);
        for (height.sample_points, height.sample_values) |point, claim| {
            channel.mixFelts(&[_]QM31{ point.x, point.y, claim });
        }
    }
    return .{ .batch = channel.drawSecureFelt() };
}

/// Verifier entry point for this experimental fragment: classify and decode
/// the complete canonical envelope before touching the transcript. A rejected
/// version, malformed field, or trailing byte leaves `channel` unchanged.
pub fn decodeAndBind(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    channel: anytype,
    expected: ExpectedProfile,
) !Prepared {
    var decoded = try decode(allocator, encoded);
    errdefer decoded.deinit();
    if (!expected.matches(decoded.envelope)) return error.UnexpectedPairedProfile;
    const challenges = try drawChallenges(channel, decoded.envelope);
    return .{ .decoded = decoded, .challenges = challenges };
}

/// Construct the source verifier from this height's decoded root and exact
/// column geometry. No caller-supplied verifier can substitute another root.
/// Returns answers aligned with the largest-domain query list, including its
/// duplicates. This remains a source-opening fragment, not FRI verification.
pub fn authenticatedHeightAnswers(
    allocator: std.mem.Allocator,
    envelope: Envelope,
    height_index: usize,
    largest_positions: []const usize,
    challenges: paired.Challenges,
) ![]QM31 {
    try envelope.validate();
    if (height_index >= envelope.heights.len or largest_positions.len != envelope.query_count)
        return error.InvalidPairedEnvelope;
    const height = envelope.heights[height_index];
    const n_cols: usize = @intCast(height.shape.original_column_count);
    var logs: [MAX_COLUMNS_PER_HEIGHT]u32 = undefined;
    @memset(logs[0..n_cols], height.shape.log_domain_size);
    var verifier = try vcs_verifier.MerkleVerifierLifted(Hasher).init(
        allocator,
        height.source_root,
        logs[0..n_cols],
    );
    defer verifier.deinit(allocator);
    return projection.authenticatedProjectedAnswers(
        Hasher,
        allocator,
        largest_positions,
        envelope.largest_log_size,
        verifier,
        height.queried_sources,
        .{ .hash_witness = height.hash_witness },
        height.sample_points,
        height.sample_values,
        height.shape,
        challenges,
    );
}

fn writeQM31(writer: anytype, value: QM31) !void {
    for (value.toM31Array()) |felt| try writer.writeInt(u32, felt.toU32(), .little);
}

const Cursor = struct {
    bytes: []const u8,
    at: usize = 0,

    fn readBytes(self: *Cursor, len: usize) ![]const u8 {
        const end = std.math.add(usize, self.at, len) catch return error.TruncatedPairedEnvelope;
        if (end > self.bytes.len) return error.TruncatedPairedEnvelope;
        const result = self.bytes[self.at..end];
        self.at = end;
        return result;
    }

    fn readU16(self: *Cursor) !u16 {
        return std.mem.readInt(u16, (try self.readBytes(2))[0..2], .little);
    }

    fn readU32(self: *Cursor) !u32 {
        return std.mem.readInt(u32, (try self.readBytes(4))[0..4], .little);
    }

    fn readM31(self: *Cursor) !M31 {
        const value = try self.readU32();
        if (value >= m31.Modulus) return error.NonCanonicalM31;
        return M31.fromCanonical(value);
    }

    fn readQM31(self: *Cursor) !QM31 {
        return QM31.fromM31Array(.{
            try self.readM31(), try self.readM31(), try self.readM31(), try self.readM31(),
        });
    }
};
