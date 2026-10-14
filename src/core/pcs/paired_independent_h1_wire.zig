//! Canonical experimental byte envelope for the independent H1 tracks.
//! No production PCS dispatch accepts this magic.

const std = @import("std");
const circle = @import("../circle.zig");
const m31 = @import("../fields/m31.zig");
const qm31 = @import("../fields/qm31.zig");
const channel_mod = @import("../channel/blake2s.zig");
const xdm = @import("transposed_merkle_sparse_heights_experimental.zig");
const dual = @import("paired_independent_h1_experimental.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
pub const MAGIC = "S31DIH08";
pub const MAX_WIRE_BYTES: usize = 64 * 1024 * 1024;

pub const Decoded = struct {
    arena: std.heap.ArenaAllocator,
    proof: dual.Proof,
    pub fn deinit(self: *Decoded) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

fn writeFelt(writer: anytype, value: QM31) !void {
    for (value.toM31Array()) |word| try writer.writeInt(u32, word.toU32(), .little);
}

pub fn encode(allocator: std.mem.Allocator, proof: dual.Proof) ![]u8 {
    try dual.validateProof(proof);
    const count = proof.profile.source.columns[0];
    const terminal_len = proof.profile.terminalLength();
    var expected: usize = 8 + 2 + 2 + 4 + 4 + 4 + 4 + 2 + 2 + 32 + 32 + 4 + 4;
    expected = std.math.add(usize, expected, @as(usize, count) * 16) catch return error.DualProofTooLarge;
    expected = std.math.add(usize, expected, proof.source_wire.len) catch return error.DualProofTooLarge;
    expected = std.math.add(usize, expected, terminal_len * 32) catch return error.DualProofTooLarge;
    if (expected > MAX_WIRE_BYTES or expected > std.math.maxInt(u32)) return error.DualProofTooLarge;
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    try out.ensureTotalCapacity(allocator, expected);
    const writer = out.writer(allocator);
    try writer.writeAll(MAGIC);
    try writer.writeInt(u16, dual.VERSION, .little);
    try writer.writeInt(u16, 0, .little);
    try writer.writeInt(u32, @intCast(expected), .little);
    try writer.writeInt(u32, proof.profile.source.largest_log_size, .little);
    try writer.writeInt(u32, proof.profile.log_blowup, .little);
    try writer.writeInt(u32, @intCast(proof.profile.source.query_count), .little);
    try writer.writeInt(u16, count, .little);
    try writer.writeInt(u16, 0, .little);
    try writer.writeAll(&proof.source_root);
    try writeFelt(writer, proof.sampled_point.x);
    try writeFelt(writer, proof.sampled_point.y);
    for (proof.claims[0]) |claim| try writeFelt(writer, claim);
    try writer.writeInt(u32, @intCast(proof.source_wire.len), .little);
    try writer.writeAll(proof.source_wire);
    try writer.writeInt(u32, @intCast(terminal_len), .little);
    for (proof.original_terminal) |word| try writeFelt(writer, word);
    for (proof.quotient_terminal) |word| try writeFelt(writer, word);
    std.debug.assert(out.items.len == expected);
    return out.toOwnedSlice(allocator);
}

const Cursor = struct {
    bytes: []const u8,
    at: usize = 0,

    fn take(self: *Cursor, len: usize) ![]const u8 {
        if (len > self.bytes.len - self.at) return error.TruncatedDualProof;
        const result = self.bytes[self.at..][0..len];
        self.at += len;
        return result;
    }
    fn readU16(self: *Cursor) !u16 {
        return std.mem.readInt(u16, (try self.take(2))[0..2], .little);
    }
    fn readU32(self: *Cursor) !u32 {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .little);
    }
    fn felt(self: *Cursor) !M31 {
        const word = try self.readU32();
        if (word >= m31.Modulus) return error.NonCanonicalM31;
        return M31.fromCanonical(word);
    }
    fn qm31(self: *Cursor) !QM31 {
        return QM31.fromM31Array(.{ try self.felt(), try self.felt(), try self.felt(), try self.felt() });
    }
};

pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) !Decoded {
    if (bytes.len < MAGIC.len) return error.TruncatedDualProof;
    if (!std.mem.eql(u8, bytes[0..MAGIC.len], MAGIC)) return error.UnsupportedProofFormat;
    if (bytes.len > MAX_WIRE_BYTES) return error.DualProofTooLarge;
    var cursor = Cursor{ .bytes = bytes };
    _ = try cursor.take(MAGIC.len);
    if (try cursor.readU16() != dual.VERSION) return error.UnsupportedDualVersion;
    if (try cursor.readU16() != 0) return error.InvalidDualProof;
    const declared = try cursor.readU32();
    if (declared != bytes.len) return error.InvalidDualProof;
    const k = try cursor.readU32();
    const blowup = try cursor.readU32();
    const query_count = try cursor.readU32();
    const column_count = try cursor.readU16();
    if (try cursor.readU16() != 0) return error.InvalidDualProof;
    var counts = [_]u16{0} ** xdm.MAX_HEIGHTS;
    counts[0] = column_count;
    const profile = dual.Profile{ .source = .{
        .largest_log_size = k,
        .height_count = 1,
        .columns = counts,
        .query_count = query_count,
    }, .log_blowup = blowup };
    try dual.validateProfile(profile);
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    var root: xdm.Hash = undefined;
    @memcpy(&root, try cursor.take(root.len));
    const point = circle.CirclePointQM31{ .x = try cursor.qm31(), .y = try cursor.qm31() };
    const claims = try a.alloc([]const QM31, 1);
    const claim_values = try a.alloc(QM31, column_count);
    for (claim_values) |*word| word.* = try cursor.qm31();
    claims[0] = claim_values;
    const source_wire = try cursor.take(try cursor.readU32());
    const terminal_len = try cursor.readU32();
    if (terminal_len != profile.terminalLength()) return error.InvalidDualProof;
    const originals = try a.alloc(QM31, terminal_len);
    for (originals) |*word| word.* = try cursor.qm31();
    const quotients = try a.alloc(QM31, terminal_len);
    for (quotients) |*word| word.* = try cursor.qm31();
    if (cursor.at != bytes.len) return error.InvalidDualProof;
    const proof = dual.Proof{
        .profile = profile,
        .source_root = root,
        .sampled_point = point,
        .claims = claims,
        .source_wire = source_wire,
        .original_terminal = originals,
        .quotient_terminal = quotients,
    };
    try dual.validateProof(proof);
    return .{ .arena = arena, .proof = proof };
}

pub fn verifyAgainstStatement(allocator: std.mem.Allocator, bytes: []const u8, channel: *channel_mod.Blake2sChannel, statement: dual.ExpectedStatement) !void {
    var decoded = try decode(allocator, bytes);
    defer decoded.deinit();
    try dual.verifyAgainstStatement(allocator, decoded.proof, channel, statement);
}
