//! Experimental P2F02: one XDM02 cross-domain source root, degree-corrected
//! paired answers, and two-height line/terminal FRI. This format is never
//! dispatched by production PCS. Only verifyAgainstStatement is a complete
//! checker: callers supply the expected root, claims, and degree profile.

const std = @import("std");
const circle = @import("../circle.zig");
const m31 = @import("../fields/m31.zig");
const qm31 = @import("../fields/qm31.zig");
const blake2_hash = @import("../vcs/blake2_hash.zig");
const blake2_merkle = @import("../vcs_lifted/blake2_merkle.zig");
const paired = @import("paired_ensemble.zig");
const xdm = @import("transposed_merkle.zig");
const answers = @import("transposed_paired_answers.zig");
const fri = @import("paired_two_height_fri.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const Hash = xdm.Hash;
pub const MAGIC = "S31P2F02";
pub const VERSION: u16 = 2;
const TRANSCRIPT_TAG: u64 = 0x5333_3150_3246_3032;
const ROOT_TAG: u64 = 0x5333_3150_3252_3032;
const CLAIM_TAG: u64 = 0x5333_3150_3243_3032;
const MAX_WIRE_BYTES: usize = 64 * 1024 * 1024;

pub const Profile = struct {
    largest_log_size: u32,
    log_blowup: u32,
    large_columns: usize,
    small_columns: usize,
    n_queries: usize,

    pub fn validate(self: Profile) !void {
        if (self.largest_log_size < 4 or self.largest_log_size > xdm.MAX_LOG_SIZE or
            self.log_blowup == 0 or self.log_blowup + 1 >= self.largest_log_size or
            self.large_columns == 0 or self.large_columns > xdm.MAX_COLUMNS or
            self.small_columns == 0 or self.small_columns > xdm.MAX_COLUMNS or
            self.n_queries == 0 or self.n_queries > (1 << 14))
            return error.InvalidPairedProfile;
    }

    pub fn source(self: Profile) xdm.Profile {
        return .{ .log_size = self.largest_log_size, .large_columns = self.large_columns, .small_columns = self.small_columns, .query_count = self.n_queries };
    }

    pub fn shapes(self: Profile) [2]paired.Shape {
        return .{
            .{ .log_domain_size = self.largest_log_size, .log_degree_bound = self.largest_log_size - self.log_blowup, .original_column_count = @intCast(self.large_columns) },
            .{ .log_domain_size = self.largest_log_size - 1, .log_degree_bound = self.largest_log_size - 1 - self.log_blowup, .original_column_count = @intCast(self.small_columns) },
        };
    }
};

pub const ExpectedStatement = struct {
    profile: Profile,
    source_root: Hash,
    large_claims: []const QM31,
    small_claims: []const QM31,
};

pub const Proof = struct {
    profile: Profile,
    source_root: Hash,
    sampled_point: circle.CirclePointQM31,
    large_claims: []const QM31,
    small_claims: []const QM31,
    source_wire: []const u8,
    intermediate: fri.IntermediateOpening,
    terminal_ordered_coeffs: []const QM31,
};

pub const Decoded = struct {
    arena: std.heap.ArenaAllocator,
    proof: Proof,

    pub fn deinit(self: *Decoded) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

fn checkShape(proof: Proof) !void {
    try proof.profile.validate();
    if (proof.large_claims.len != proof.profile.large_columns or
        proof.small_claims.len != proof.profile.small_columns or
        proof.terminal_ordered_coeffs.len != (@as(usize, 1) << @intCast(
            proof.profile.largest_log_size - proof.profile.log_blowup - 2,
        ))) return error.InvalidPairedProof;
    for (proof.intermediate.queried_coordinates) |column| {
        if (column.len != proof.profile.n_queries * 2) return error.InvalidPairedProof;
    }
    const source_header = try xdm.inspectHeader(proof.source_wire);
    if (!std.meta.eql(source_header.profile, proof.profile.source()) or
        !std.mem.eql(u8, &source_header.root, &proof.source_root))
        return error.InvalidPairedProof;
}

pub fn encode(allocator: std.mem.Allocator, proof: Proof) ![]u8 {
    try checkShape(proof);
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    const w = out.writer(allocator);
    try w.writeAll(MAGIC);
    try w.writeInt(u16, VERSION, .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u32, 0, .little);
    try w.writeInt(u32, proof.profile.largest_log_size, .little);
    try w.writeInt(u32, proof.profile.log_blowup, .little);
    try w.writeInt(u16, @intCast(proof.profile.large_columns), .little);
    try w.writeInt(u16, @intCast(proof.profile.small_columns), .little);
    try w.writeInt(u32, @intCast(proof.profile.n_queries), .little);
    try w.writeAll(&proof.source_root);
    try writeQM31(w, proof.sampled_point.x);
    try writeQM31(w, proof.sampled_point.y);
    for (proof.large_claims) |claim| try writeQM31(w, claim);
    for (proof.small_claims) |claim| try writeQM31(w, claim);
    try w.writeInt(u32, @intCast(proof.source_wire.len), .little);
    try w.writeAll(proof.source_wire);
    try w.writeAll(&proof.intermediate.root);
    try w.writeInt(u32, @intCast(proof.terminal_ordered_coeffs.len), .little);
    for (proof.terminal_ordered_coeffs) |value| try writeQM31(w, value);
    try w.writeInt(u32, @intCast(proof.profile.n_queries * 2), .little);
    for (proof.intermediate.queried_coordinates) |column|
        for (column) |felt| try w.writeInt(u32, felt.toU32(), .little);
    try w.writeInt(u32, @intCast(proof.intermediate.hash_witness.len), .little);
    for (proof.intermediate.hash_witness) |hash| try w.writeAll(&hash);
    if (out.items.len > MAX_WIRE_BYTES) return error.PairedProofTooLarge;
    const encoded = try out.toOwnedSlice(allocator);
    std.mem.writeInt(u32, encoded[12..16], @intCast(encoded.len), .little);
    return encoded;
}

pub fn decode(allocator: std.mem.Allocator, encoded: []const u8) !Decoded {
    if (encoded.len < MAGIC.len) return error.TruncatedPairedProof;
    if (!std.mem.eql(u8, encoded[0..MAGIC.len], MAGIC)) return error.UnsupportedProofFormat;
    if (encoded.len > MAX_WIRE_BYTES) return error.PairedProofTooLarge;
    var c = Cursor{ .bytes = encoded };
    _ = try c.take(MAGIC.len);
    if (try c.readU16() != VERSION) return error.UnsupportedProofVersion;
    if (try c.readU16() != 0 or try c.readU32() != encoded.len) return error.InvalidPairedProof;
    const profile = Profile{
        .largest_log_size = try c.readU32(),
        .log_blowup = try c.readU32(),
        .large_columns = try c.readU16(),
        .small_columns = try c.readU16(),
        .n_queries = try c.readU32(),
    };
    try profile.validate();
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    const root = try c.hash();
    const point = circle.CirclePointQM31{ .x = try c.qm31(), .y = try c.qm31() };
    const large_claims = try a.alloc(QM31, profile.large_columns);
    const small_claims = try a.alloc(QM31, profile.small_columns);
    for (large_claims) |*claim| claim.* = try c.qm31();
    for (small_claims) |*claim| claim.* = try c.qm31();
    const source_wire = try c.take(try c.readU32());
    const line_root = try c.hash();
    const terminal_len = try c.readU32();
    if (terminal_len == 0 or terminal_len > (1 << 16)) return error.InvalidPairedProof;
    const terminal = try a.alloc(QM31, terminal_len);
    for (terminal) |*value| value.* = try c.qm31();
    const line_query_count = try c.readU32();
    if (line_query_count != profile.n_queries * 2) return error.InvalidPairedProof;
    var columns: [4][]const M31 = undefined;
    for (&columns) |*column| {
        const values = try a.alloc(M31, line_query_count);
        for (values) |*value| value.* = try c.readM31();
        column.* = values;
    }
    const witness_len = try c.readU32();
    if (witness_len > (1 << 20)) return error.InvalidPairedProof;
    const witness = try a.alloc(Hash, witness_len);
    for (witness) |*hash| hash.* = try c.hash();
    if (c.at != encoded.len) return error.InvalidPairedProof;
    const proof = Proof{
        .profile = profile,
        .source_root = root,
        .sampled_point = point,
        .large_claims = large_claims,
        .small_claims = small_claims,
        .source_wire = source_wire,
        .intermediate = .{ .root = line_root, .queried_coordinates = columns, .hash_witness = witness },
        .terminal_ordered_coeffs = terminal,
    };
    try checkShape(proof);
    return .{ .arena = arena, .proof = proof };
}

pub fn matches(statement: ExpectedStatement, proof: Proof) bool {
    if (!std.meta.eql(statement.profile, proof.profile) or
        !std.mem.eql(u8, &statement.source_root, &proof.source_root) or
        statement.large_claims.len != proof.large_claims.len or
        statement.small_claims.len != proof.small_claims.len) return false;
    for (statement.large_claims, proof.large_claims) |a, b| if (!a.eql(b)) {
        return false;
    };
    for (statement.small_claims, proof.small_claims) |a, b| if (!a.eql(b)) {
        return false;
    };
    return true;
}

pub fn bindVersion(channel: anytype) void {
    channel.mixU64(TRANSCRIPT_TAG);
    channel.mixU64(VERSION);
}

/// The seed is drawn once. Degenerate points reject the whole proof; there is
/// no unmodeled retry schedule. This is a premise alignment, not a distribution
/// proof for the published theorem.
pub fn drawOodPoint(channel: anytype, profile: Profile, root: Hash) !circle.CirclePointQM31 {
    try profile.validate();
    var staged = channel.*;
    staged.mixU64(ROOT_TAG);
    staged.mixU64(profile.largest_log_size);
    staged.mixU64(profile.log_blowup);
    staged.mixU64(profile.large_columns);
    staged.mixU64(profile.small_columns);
    staged.mixU64(profile.n_queries);
    staged.updateDigest(blake2_hash.Blake2sHasher.concatAndHash(staged.digestBytes(), root));
    const point = try circle.secureFieldPointFromRandomSeedChecked(staged.drawSecureFelt());
    if (point.y.c1.isZero()) return error.DegenerateOodPoint;
    channel.* = staged;
    return point;
}

pub fn drawBatchAfterOod(channel: anytype, large_claims: []const QM31, small_claims: []const QM31) QM31 {
    channel.mixU64(CLAIM_TAG);
    channel.mixFelts(large_claims);
    channel.mixFelts(small_claims);
    return channel.drawSecureFelt();
}

/// The sole complete P2F02 verifier entry point. It authenticates XDM rows
/// internally before deriving paired answers and checks every fold. No caller
/// supplied answer slice can bypass the expected public statement.
pub fn verifyAgainstStatement(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    channel: anytype,
    statement: ExpectedStatement,
) !void {
    try statement.profile.validate();
    var decoded = try decode(allocator, encoded);
    defer decoded.deinit();
    const proof = decoded.proof;
    if (!matches(statement, proof)) return error.UnexpectedPairedStatement;
    var staged = channel.*;
    bindVersion(&staged);
    const sampled = try drawOodPoint(&staged, proof.profile, proof.source_root);
    if (!sampled.eql(proof.sampled_point)) return error.UnsampledOodPoint;
    const batch = drawBatchAfterOod(&staged, proof.large_claims, proof.small_claims);
    const alpha0 = staged.drawSecureFelt();
    blake2_merkle.Blake2sMerkleChannel.mixRoot(&staged, proof.intermediate.root);
    const alpha1 = staged.drawSecureFelt();
    staged.mixFelts(proof.terminal_ordered_coeffs);
    var schedule = try fri.sampleQuerySchedule(allocator, &staged, proof.profile.largest_log_size, proof.profile.n_queries);
    defer schedule.deinit(allocator);
    var opened = try xdm.verifyAndCollect(
        allocator,
        proof.source_wire,
        proof.profile.source(),
        proof.source_root,
        schedule.raw,
    );
    defer opened.deinit();
    var paired_answers = try answers.fromVerifiedOpenings(
        allocator,
        opened,
        schedule.raw,
        sampled,
        proof.large_claims,
        proof.small_claims,
        batch,
    );
    defer paired_answers.deinit();
    const shapes = proof.profile.shapes();
    try fri.verifyFromAuthenticatedAnswers(
        allocator,
        shapes[0],
        shapes[1],
        proof.intermediate,
        proof.terminal_ordered_coeffs,
        schedule,
        alpha0,
        alpha1,
        paired_answers.large,
        paired_answers.small,
        2,
    );
    channel.* = staged;
}

fn writeQM31(w: anytype, value: QM31) !void {
    for (value.toM31Array()) |felt| try w.writeInt(u32, felt.toU32(), .little);
}

const Cursor = struct {
    bytes: []const u8,
    at: usize = 0,
    fn take(self: *Cursor, n: usize) ![]const u8 {
        if (n > self.bytes.len - self.at) return error.TruncatedPairedProof;
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
