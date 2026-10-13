//! Canonical experimental S31CAS04 outer wire for the one-root multi-height
//! paired FRI cascade. The only complete entry point requires an independently
//! supplied public statement and authenticates XDM03 plus every line layer.
//! Production PCS never dispatches this magic.

const std = @import("std");
const circle = @import("../circle.zig");
const m31 = @import("../fields/m31.zig");
const qm31 = @import("../fields/qm31.zig");
const xdm = @import("transposed_merkle_cascade.zig");
const cascade = @import("paired_cascade_experimental.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const Hash = xdm.Hash;
pub const MAGIC = "S31CAS04";
pub const VERSION: u16 = cascade.OUTER_VERSION;
pub const MAX_WIRE_BYTES: usize = 64 * 1024 * 1024;

pub const Decoded = struct {
    arena: std.heap.ArenaAllocator,
    proof: cascade.Proof,

    pub fn deinit(self: *Decoded) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

/// Exact byte format:
/// magic/version/reserved/total length; profile with per-height column counts;
/// one source root, sampled point, OOD claims, nested XDM03 source wire;
/// H-1 line roots, coordinate arrays and Merkle witnesses; terminal coeffs.
pub fn encode(allocator: std.mem.Allocator, proof: cascade.Proof) ![]u8 {
    try cascade.validateProof(proof);
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    const w = out.writer(allocator);
    const source = proof.profile.source;
    try w.writeAll(MAGIC);
    try w.writeInt(u16, VERSION, .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u32, 0, .little);
    try w.writeInt(u32, source.largest_log_size, .little);
    try w.writeInt(u16, @intCast(source.height_count), .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u32, proof.profile.log_blowup, .little);
    try w.writeInt(u32, @intCast(source.query_count), .little);
    for (source.columns[0..source.height_count]) |count|
        try w.writeInt(u16, count, .little);
    try w.writeAll(&proof.source_root);
    try writeQM31(w, proof.sampled_point.x);
    try writeQM31(w, proof.sampled_point.y);
    for (proof.claims) |height| for (height) |claim| try writeQM31(w, claim);
    try w.writeInt(u32, @intCast(proof.source_wire.len), .little);
    try w.writeAll(proof.source_wire);
    try w.writeInt(u16, @intCast(proof.line_openings.len), .little);
    try w.writeInt(u16, 0, .little);
    for (proof.line_openings, 0..) |opening, i| {
        try w.writeAll(&opening.root);
        const count = source.query_count * source.width(i + 1);
        try w.writeInt(u32, @intCast(count), .little);
        for (opening.queried_coordinates) |column|
            for (column) |value| try w.writeInt(u32, value.toU32(), .little);
        try w.writeInt(u32, @intCast(opening.hash_witness.len), .little);
        for (opening.hash_witness) |hash| try w.writeAll(&hash);
    }
    try w.writeInt(u32, @intCast(proof.terminal_ordered_coeffs.len), .little);
    for (proof.terminal_ordered_coeffs) |value| try writeQM31(w, value);
    if (out.items.len > MAX_WIRE_BYTES) return error.CascadeProofTooLarge;
    const encoded = try out.toOwnedSlice(allocator);
    std.mem.writeInt(u32, encoded[12..16], @intCast(encoded.len), .little);
    return encoded;
}

/// Strict shape/canonical decoder. Its result is untrusted: only
/// verifyAgainstStatement authenticates roots and fold relations.
pub fn decode(allocator: std.mem.Allocator, encoded: []const u8) !Decoded {
    if (encoded.len < MAGIC.len) return error.TruncatedCascadeProof;
    if (!std.mem.eql(u8, encoded[0..MAGIC.len], MAGIC)) return error.UnsupportedProofFormat;
    if (encoded.len > MAX_WIRE_BYTES) return error.CascadeProofTooLarge;
    var c = Cursor{ .bytes = encoded };
    _ = try c.take(MAGIC.len);
    if (try c.readU16() != VERSION) return error.UnsupportedProofVersion;
    if (try c.readU16() != 0) return error.InvalidCascadeProof;
    const declared_len = try c.readU32();
    if (declared_len > encoded.len) return error.TruncatedCascadeProof;
    if (declared_len < encoded.len) return error.InvalidCascadeProof;
    const largest_log_size = try c.readU32();
    const height_count = try c.readU16();
    if (try c.readU16() != 0) return error.InvalidCascadeProof;
    const log_blowup = try c.readU32();
    const query_count = try c.readU32();
    if (height_count < 2 or height_count > xdm.MAX_HEIGHTS)
        return error.InvalidCascadeProfile;
    var column_counts = [_]u16{0} ** xdm.MAX_HEIGHTS;
    for (column_counts[0..height_count]) |*count| count.* = try c.readU16();
    const profile = cascade.Profile{
        .source = .{
            .largest_log_size = largest_log_size,
            .height_count = height_count,
            .columns = column_counts,
            .query_count = query_count,
        },
        .log_blowup = log_blowup,
    };
    try profile.validate();
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    const root = try c.hash();
    const point = circle.CirclePointQM31{ .x = try c.qm31(), .y = try c.qm31() };
    const claims = try a.alloc([]const QM31, height_count);
    for (claims, 0..) |*height, i| {
        const values = try a.alloc(QM31, column_counts[i]);
        for (values) |*value| value.* = try c.qm31();
        height.* = values;
    }
    const source_wire = try c.take(try c.readU32());
    const line_count = try c.readU16();
    if (try c.readU16() != 0 or line_count != height_count - 1)
        return error.InvalidCascadeProof;
    const lines = try a.alloc(cascade.LineOpening, line_count);
    for (lines, 0..) |*opening, i| {
        const line_root = try c.hash();
        const count = try c.readU32();
        if (count != profile.source.query_count * profile.source.width(i + 1))
            return error.InvalidCascadeProof;
        if (c.bytes.len - c.at < @as(usize, count) * 4 * @sizeOf(M31))
            return error.TruncatedCascadeProof;
        var columns: [4][]const M31 = undefined;
        for (&columns) |*column| {
            const values = try a.alloc(M31, count);
            for (values) |*value| value.* = try c.readM31();
            column.* = values;
        }
        const witness_count = try c.readU32();
        if (witness_count > (1 << 20) or
            c.bytes.len - c.at < @as(usize, witness_count) * @sizeOf(Hash))
            return error.InvalidCascadeProof;
        const witness = try a.alloc(Hash, witness_count);
        for (witness) |*hash| hash.* = try c.hash();
        opening.* = .{ .root = line_root, .queried_coordinates = columns, .hash_witness = witness };
    }
    const terminal_count = try c.readU32();
    if (terminal_count != profile.terminalLength()) return error.InvalidCascadeProof;
    if (c.bytes.len - c.at < @as(usize, terminal_count) * @sizeOf(QM31))
        return error.TruncatedCascadeProof;
    const terminal = try a.alloc(QM31, terminal_count);
    for (terminal) |*value| value.* = try c.qm31();
    if (c.at != encoded.len) return error.InvalidCascadeProof;
    const proof = cascade.Proof{
        .profile = profile,
        .source_root = root,
        .sampled_point = point,
        .claims = claims,
        .source_wire = source_wire,
        .line_openings = lines,
        .terminal_ordered_coeffs = terminal,
    };
    try cascade.validateProof(proof);
    return .{ .arena = arena, .proof = proof };
}

/// The only complete outer-wire verification entry point. Callers must obtain
/// this statement independently, never by trusting decoded proof metadata.
pub fn verifyAgainstStatement(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    channel: anytype,
    statement: cascade.ExpectedStatement,
) !void {
    var decoded = try decode(allocator, encoded);
    defer decoded.deinit();
    try cascade.verifyAgainstStatement(allocator, decoded.proof, channel, statement);
}

fn writeQM31(w: anytype, value: QM31) !void {
    for (value.toM31Array()) |felt| try w.writeInt(u32, felt.toU32(), .little);
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
    fn qm31(self: *Cursor) !QM31 {
        return QM31.fromM31Array(.{ try self.readM31(), try self.readM31(), try self.readM31(), try self.readM31() });
    }
    fn hash(self: *Cursor) !Hash {
        var result: Hash = undefined;
        @memcpy(&result, try self.take(result.len));
        return result;
    }
};
