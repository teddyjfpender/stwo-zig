//! Experimental complete wire container for the fixed two-height FRI slice.
//!
//! The outer magic selects this mode before any transcript replay. Production
//! PCS does not dispatch to this decoder or verifier; the protocol's published
//! soundness theorem has not been refined to these native choices.

const std = @import("std");
const circle = @import("../circle.zig");
const m31 = @import("../fields/m31.zig");
const qm31 = @import("../fields/qm31.zig");
const blake2_hash = @import("../vcs/blake2_hash.zig");
const paired = @import("paired_envelope.zig");
const two_height = @import("paired_two_height_fri.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const Hash = paired.Hash;
pub const MAGIC = "S31P2F01";
pub const VERSION: u16 = 1;
const TRANSCRIPT_TAG: u64 = 0x5333_3150_3246_3031; // S31P2F01
const ROOTS_TAG: u64 = 0x5333_3150_3252_4f54; // S31P2ROT
const CLAIMS_TAG: u64 = 0x5333_3150_3243_4c4d; // S31P2CLM
const MAX_WIRE_BYTES: usize = 64 * 1024 * 1024;
const MAX_HASH_WITNESS: usize = 1 << 20;

pub const Proof = struct {
    source_wire: []const u8,
    intermediate: two_height.IntermediateOpening,
    terminal_ordered_coeffs: []const QM31,
};

pub const Decoded = struct {
    arena: std.heap.ArenaAllocator,
    source: paired.Decoded,
    intermediate: two_height.IntermediateOpening,
    terminal_ordered_coeffs: []const QM31,

    pub fn deinit(self: *Decoded) void {
        self.source.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
};

pub const Prepared = struct {
    decoded: Decoded,
    challenges: @import("paired_ensemble.zig").Challenges,

    pub fn deinit(self: *Prepared) void {
        self.decoded.deinit();
        self.* = undefined;
    }
};

/// A caller-owned public statement. The roots and OOD values are compared to
/// the decoded proof before any verification state is published to the caller.
/// This binds the relation to an application statement; it does not confer a
/// security level on this experimental protocol.
pub const ExpectedStatement = struct {
    profile: paired.ExpectedProfile,
    source_roots: []const Hash,
    sample_values: []const []const QM31,

    pub fn matches(self: ExpectedStatement, envelope: paired.Envelope) bool {
        if (!self.profile.matches(envelope) or
            self.source_roots.len != envelope.heights.len or
            self.sample_values.len != envelope.heights.len)
        {
            return false;
        }
        for (envelope.heights, self.source_roots, self.sample_values) |height, root, claims| {
            if (!std.mem.eql(u8, &height.source_root, &root) or
                claims.len != height.sample_values.len)
            {
                return false;
            }
            for (height.sample_values, claims) |actual, expected| {
                if (!actual.eql(expected)) return false;
            }
        }
        return true;
    }
};

pub fn encode(allocator: std.mem.Allocator, proof: Proof) ![]u8 {
    var source = try paired.decode(allocator, proof.source_wire);
    defer source.deinit();
    try validateShape(source.envelope, proof.intermediate, proof.terminal_ordered_coeffs);
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    const writer = out.writer(allocator);
    try writer.writeAll(MAGIC);
    try writer.writeInt(u16, VERSION, .little);
    try writer.writeInt(u16, 0, .little);
    try writer.writeInt(u32, 0, .little); // patched total length
    try writer.writeInt(u32, @intCast(proof.source_wire.len), .little);
    try writer.writeAll(proof.source_wire);
    try writer.writeAll(&proof.intermediate.root);
    try writer.writeInt(u32, @intCast(proof.terminal_ordered_coeffs.len), .little);
    for (proof.terminal_ordered_coeffs) |value| try writeQM31(writer, value);
    const line_query_count = proof.intermediate.queried_coordinates[0].len;
    try writer.writeInt(u32, @intCast(line_query_count), .little);
    for (proof.intermediate.queried_coordinates) |column| {
        for (column) |value| try writer.writeInt(u32, value.toU32(), .little);
    }
    try writer.writeInt(u32, @intCast(proof.intermediate.hash_witness.len), .little);
    for (proof.intermediate.hash_witness) |hash| try writer.writeAll(&hash);
    if (out.items.len > MAX_WIRE_BYTES) return error.PairedProofTooLarge;
    const bytes = try out.toOwnedSlice(allocator);
    std.mem.writeInt(u32, bytes[12..16], @intCast(bytes.len), .little);
    return bytes;
}

pub fn decode(allocator: std.mem.Allocator, encoded: []const u8) !Decoded {
    if (encoded.len < MAGIC.len) return error.TruncatedPairedProof;
    if (!std.mem.eql(u8, encoded[0..MAGIC.len], MAGIC)) return error.UnsupportedProofFormat;
    if (encoded.len > MAX_WIRE_BYTES) return error.PairedProofTooLarge;
    var cursor = Cursor{ .bytes = encoded };
    _ = try cursor.readBytes(MAGIC.len);
    if (try cursor.readU16() != VERSION) return error.UnsupportedProofVersion;
    if (try cursor.readU16() != 0) return error.InvalidPairedProof;
    if (try cursor.readU32() != encoded.len) return error.InvalidPairedProof;
    const source_len = try cursor.readU32();
    const source_bytes = try cursor.readBytes(source_len);
    var source = try paired.decode(allocator, source_bytes);
    errdefer source.deinit();
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    var root: Hash = undefined;
    @memcpy(&root, try cursor.readBytes(root.len));
    const terminal_len = try cursor.readU32();
    if (terminal_len == 0 or terminal_len > 1 << 16) return error.InvalidPairedProof;
    if (cursor.bytes.len - cursor.at < @as(usize, terminal_len) * @sizeOf(QM31))
        return error.TruncatedPairedProof;
    const terminal = try a.alloc(QM31, terminal_len);
    for (terminal) |*value| value.* = try cursor.readQM31();
    const line_query_count = try cursor.readU32();
    if (line_query_count == 0 or line_query_count > 1 << 15) return error.InvalidPairedProof;
    if (cursor.bytes.len - cursor.at < @as(usize, line_query_count) * 4 * @sizeOf(M31))
        return error.TruncatedPairedProof;
    var columns: [4][]const M31 = undefined;
    for (&columns) |*column| {
        const values = try a.alloc(M31, line_query_count);
        for (values) |*value| value.* = try cursor.readM31();
        column.* = values;
    }
    const witness_count = try cursor.readU32();
    if (witness_count > MAX_HASH_WITNESS) return error.InvalidPairedProof;
    if (cursor.bytes.len - cursor.at < @as(usize, witness_count) * @sizeOf(Hash))
        return error.TruncatedPairedProof;
    const witness = try a.alloc(Hash, witness_count);
    for (witness) |*hash| @memcpy(hash, try cursor.readBytes(hash.len));
    if (cursor.at != encoded.len) return error.InvalidPairedProof;
    const intermediate = two_height.IntermediateOpening{
        .root = root,
        .queried_coordinates = columns,
        .hash_witness = witness,
    };
    try validateShape(source.envelope, intermediate, terminal);
    return .{
        .arena = arena,
        .source = source,
        .intermediate = intermediate,
        .terminal_ordered_coeffs = terminal,
    };
}

/// The expected profile comes from the verifier. No transcript operation is
/// performed until both outer and inner versions, both parsers, and the shape
/// check have succeeded.
pub fn decodeAndBind(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    channel: anytype,
    expected: paired.ExpectedProfile,
    n_queries: usize,
) !Prepared {
    var decoded = try decode(allocator, encoded);
    errdefer decoded.deinit();
    if (!expected.matches(decoded.source.envelope) or
        n_queries == 0 or n_queries > (1 << 16) / 4 or
        decoded.source.envelope.query_count != n_queries * 4)
    {
        return error.UnexpectedPairedProfile;
    }
    var staged_channel = channel.*;
    bindVersion(&staged_channel);
    const sampled_point = try drawOodPointFromRoots(&staged_channel, decoded.source.envelope);
    const challenges = try drawBatchAfterOod(
        &staged_channel,
        decoded.source.envelope,
        sampled_point,
    );
    channel.* = staged_channel;
    return .{ .decoded = decoded, .challenges = challenges };
}

/// The small fixture can bind an already serialized source fragment before
/// the FRI section is constructed. Complete verification must use the outer
/// decoder above, which selects the outer version before replay.
pub fn bindSourceEnvelope(
    allocator: std.mem.Allocator,
    encoded_source: []const u8,
    channel: anytype,
    expected: paired.ExpectedProfile,
) !paired.Prepared {
    var decoded = try paired.decode(allocator, encoded_source);
    errdefer decoded.deinit();
    if (!expected.matches(decoded.envelope)) return error.UnexpectedPairedProfile;
    var staged_channel = channel.*;
    bindVersion(&staged_channel);
    const sampled_point = try drawOodPointFromRoots(&staged_channel, decoded.envelope);
    const challenges = try drawBatchAfterOod(&staged_channel, decoded.envelope, sampled_point);
    channel.* = staged_channel;
    return .{ .decoded = decoded, .challenges = challenges };
}

/// Prover and verifier must bind the selected outer proof mode before the
/// source-envelope transcript. The verifier calls this only after both wire
/// versions and the locally expected profile have been checked.
pub fn bindVersion(channel: anytype) void {
    channel.mixU64(TRANSCRIPT_TAG);
    channel.mixU64(VERSION);
}

/// Bind source roots and public geometry, then sample the native secure-field
/// circle point. The claim and the proof's point have not influenced the draw.
pub fn drawOodPointFromRoots(
    channel: anytype,
    envelope: paired.Envelope,
) !circle.CirclePointQM31 {
    try envelope.validate();
    var staged_channel = channel.*;
    staged_channel.mixU64(ROOTS_TAG);
    staged_channel.mixU64(envelope.largest_log_size);
    staged_channel.mixU64(envelope.query_count);
    staged_channel.mixU64(envelope.heights.len);
    for (envelope.heights) |height| {
        staged_channel.mixU64((@as(u64, height.shape.log_domain_size) << 32) | height.shape.log_degree_bound);
        staged_channel.mixU64(height.shape.original_column_count);
        // The same Blake2s Merkle-channel operation, spelled generically so
        // deterministic rejection tests can inject a chosen seed.
        staged_channel.updateDigest(blake2_hash.Blake2sHasher.concatAndHash(
            staged_channel.digestBytes(),
            height.source_root,
        ));
    }
    const point = try circle.secureFieldPointFromRandomSeedChecked(staged_channel.drawSecureFelt());
    // The native conjugate-line construction divides by -2*point.y.c1.
    // For a point over CM31 that component is zero. Other sampled points can
    // still have a zero row-specific quotient determinant; checked inverses
    // in the prover/verifier reject those exact rows.
    if (point.y.c1.isZero()) return error.DegenerateOodPoint;
    channel.* = staged_channel;
    return point;
}

/// Require the encoded point for every source column to equal the point
/// sampled after source commitments. Only then bind the OOD claims and draw
/// the single batch challenge shared by all heights.
pub fn drawBatchAfterOod(
    channel: anytype,
    envelope: paired.Envelope,
    sampled_point: circle.CirclePointQM31,
) !@import("paired_ensemble.zig").Challenges {
    try envelope.validate();
    for (envelope.heights) |height| {
        for (height.sample_points) |point| {
            if (!point.eql(sampled_point)) return error.UnsampledOodPoint;
        }
    }
    channel.mixU64(CLAIMS_TAG);
    for (envelope.heights) |height| channel.mixFelts(height.sample_values);
    return .{ .batch = channel.drawSecureFelt() };
}

/// Checks a self-contained proof relation under caller-chosen geometry only.
/// Use verifyAgainstStatement when an application expects particular roots
/// and claims. Neither entry point is an admitted security profile.
pub fn verify(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    channel: anytype,
    expected: paired.ExpectedProfile,
    n_queries: usize,
) !void {
    return verifyWithStatement(allocator, encoded, channel, expected, n_queries, null);
}

pub fn verifyAgainstStatement(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    channel: anytype,
    statement: ExpectedStatement,
    n_queries: usize,
) !void {
    return verifyWithStatement(allocator, encoded, channel, statement.profile, n_queries, statement);
}

fn verifyWithStatement(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    channel: anytype,
    expected: paired.ExpectedProfile,
    n_queries: usize,
    statement: ?ExpectedStatement,
) !void {
    // Parsing, transcript replay, Merkle authentication, and fold checks form
    // one verifier transaction. A late rejection must not publish a partially
    // advanced Fiat-Shamir state to the caller.
    var staged_channel = channel.*;
    var prepared = try decodeAndBind(allocator, encoded, &staged_channel, expected, n_queries);
    defer prepared.deinit();
    if (statement) |expected_statement| {
        if (!expected_statement.matches(prepared.decoded.source.envelope))
            return error.UnexpectedPairedStatement;
    }
    const source_prepared = paired.Prepared{
        .decoded = prepared.decoded.source,
        .challenges = prepared.challenges,
    };
    try two_height.verifyAfterSourceBinding(
        allocator,
        &staged_channel,
        &source_prepared,
        prepared.decoded.intermediate,
        prepared.decoded.terminal_ordered_coeffs,
        n_queries,
    );
    channel.* = staged_channel;
}

fn validateShape(
    envelope: paired.Envelope,
    intermediate: two_height.IntermediateOpening,
    terminal: []const QM31,
) !void {
    if (envelope.heights.len != 2 or envelope.query_count == 0 or
        envelope.query_count % 4 != 0 or
        envelope.heights[1].shape.log_degree_bound == 0)
    {
        return error.InvalidPairedProof;
    }
    const line_query_count: usize = @as(usize, envelope.query_count) / 2;
    for (intermediate.queried_coordinates) |column| {
        if (column.len != line_query_count) return error.InvalidPairedProof;
    }
    if (intermediate.hash_witness.len > MAX_HASH_WITNESS or
        terminal.len != (@as(usize, 1) << @intCast(envelope.heights[1].shape.log_degree_bound - 1)))
    {
        return error.InvalidPairedProof;
    }
}

fn writeQM31(writer: anytype, value: QM31) !void {
    for (value.toM31Array()) |felt| try writer.writeInt(u32, felt.toU32(), .little);
}

const Cursor = struct {
    bytes: []const u8,
    at: usize = 0,

    fn readBytes(self: *Cursor, len: usize) ![]const u8 {
        const end = std.math.add(usize, self.at, len) catch return error.TruncatedPairedProof;
        if (end > self.bytes.len) return error.TruncatedPairedProof;
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
