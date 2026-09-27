//! Bounded owned lane artifact. Independent geometry/security/source-seal
//! pins choose decode shape; bytes supply no admission or proof authority.
const std = @import("std");
const core = @import("stwo_core");
const suite = core.proof_suites.Blake3;
const postcard = @import("interop_postcard");
const Protocol = @import("block_v5_ram_lanes_protocol_v1.zig");
const Proof = @import("block_v5_ram_lanes_proof_v1.zig");
const Interaction = @import("block_v5_ram_lanes_interaction_v1.zig");
const Wire = @import("guest_precompile/proof_artifact_wire.zig");
const Q = core.fields.qm31.QM31;
pub const MAGIC = "B5RAM2A1";
pub const CLAIM_BYTES: usize = 3 * 8 + (4 + Interaction.RANGE_PLANES) * 16;
pub const HEADER_BYTES: usize = MAGIC.len + 4 * 32 + 4 + 8 + CLAIM_BYTES;
pub const Expected = struct {
    pin: Proof.Pin,
    expected_seal_digest: [32]u8,
    pub fn identity(self: Expected) ![32]u8 {
        try self.pin.validate();
        if (std.mem.allEqual(u8, &self.expected_seal_digest, 0)) return error.UntrustedV5RamLanesArtifact;
        var channel = suite.Channel{};
        channel.mixRoot(Protocol.abiId());
        channel.mixU32s(&.{ Protocol.TAG, Protocol.VERSION, 0x41525446 }); // ARTF
        channel.mixRoot(try self.pin.identity());
        channel.mixRoot(self.expected_seal_digest);
        return channel.digestBytes();
    }
};
pub const Limits = struct {
    artifact_bytes: usize = 128 << 20,
    proof_bytes: usize = 64 << 20,
    max_queries: usize = 1024,
    max_row_log: u32 = 22,
    pub fn require(self: Limits, expected: Expected) !void {
        _ = try expected.identity();
        if (self.proof_bytes == 0 or self.artifact_bytes < HEADER_BYTES or self.proof_bytes > self.artifact_bytes or
            self.max_queries == 0 or expected.pin.config.fri_config.n_queries > self.max_queries or
            expected.pin.claim.row_log > self.max_row_log) return error.V5RamLanesArtifactResourceLimit;
    }
};
fn requireProof(proof: *const Proof.Proof, expected: Expected) !void {
    _ = try Interaction.normalize(proof.claim, expected.pin.claim);
    if (proof.claim.range_count != expected.pin.request_count or
        !std.meta.eql(proof.stark.commitment_scheme_proof.config, expected.pin.config)) return error.UntrustedV5RamLanesArtifact;
    const roots = proof.stark.commitment_scheme_proof.commitments.items;
    if (roots.len != 4 or !std.meta.eql(roots[0..2].*, expected.pin.roots)) return error.UntrustedV5RamLanesArtifactRoots;
}
fn metadata(writer: *std.Io.Writer, expected: Expected, value: Interaction.Claim, length: u64) !void {
    try writer.writeAll(MAGIC);
    try writer.writeAll(&Protocol.abiId());
    try writer.writeAll(&try expected.identity());
    try writer.writeAll(&expected.expected_seal_digest);
    try writer.writeAll(&try Proof.instanceId(expected.pin));
    try Wire.writeInt(writer, u32, expected.pin.index);
    try Wire.writeInt(writer, u64, length);
    try writeClaims(writer, value);
}
pub fn writeClaims(writer: *std.Io.Writer, value: Interaction.Claim) !void {
    try Wire.writeInt(writer, u64, value.event_count);
    for ([_]Q{ value.transition_sum, value.link_sum, value.initial_sum, value.endpoint_sum } ++ value.range_sums) |sum| {
        for (sum.toM31Array()) |word| if (word.toU32() >= core.fields.m31.Modulus) return error.NonCanonicalM31;
        try Wire.writeQm31(writer, sum);
    }
    try Wire.writeInt(writer, u64, value.endpoint_count);
    try Wire.writeInt(writer, u64, value.range_count);
}
pub fn readClaims(cursor: *Wire.Cursor) !Interaction.Claim {
    const events = try cursor.readInt(u64);
    const transition = try cursor.readQm31();
    const link = try cursor.readQm31();
    const initial = try cursor.readQm31();
    const endpoint = try cursor.readQm31();
    var ranges: [Interaction.RANGE_PLANES]Q = undefined;
    for (&ranges) |*sum| sum.* = try cursor.readQm31();
    return .{ .event_count = events, .transition_sum = transition, .link_sum = link, .initial_sum = initial, .endpoint_sum = endpoint, .range_sums = ranges, .endpoint_count = try cursor.readInt(u64), .range_count = try cursor.readInt(u64) };
}
pub fn encode(a: std.mem.Allocator, proof: *const Proof.Proof, expected: Expected, limits: Limits) ![]u8 {
    try limits.require(expected);
    try requireProof(proof, expected);
    var counting = @import("block_v5_cpu_counting_writer_v1.zig").Counting.init(@min(limits.proof_bytes, limits.artifact_bytes - HEADER_BYTES));
    postcard.serializeProof(suite.Hasher, &counting.writer, proof.stark) catch |err| {
        if (counting.exceeded) return error.V5RamLanesArtifactResourceLimit;
        return err;
    };
    if (counting.count == 0) return error.UntrustedV5RamLanesArtifact;
    const total = try std.math.add(usize, HEADER_BYTES, counting.count);
    const raw = try a.alloc(u8, total);
    errdefer a.free(raw);
    var writer = std.Io.Writer.fixed(raw);
    try metadata(&writer, expected, proof.claim, counting.count);
    if (writer.buffered().len != HEADER_BYTES) return error.ChangedV5RamLanesEncoding;
    try postcard.serializeProof(suite.Hasher, &writer, proof.stark);
    if (writer.buffered().len != total) return error.ChangedV5RamLanesEncoding;
    return raw;
}
pub const Envelope = struct { claim: Interaction.Claim, proof_bytes: []const u8 };
/// Allocation-free envelope admission, independently useful before file
/// ownership moves into a bounded transport store.
pub fn envelope(raw: []const u8, expected: Expected, limits: Limits) !Envelope {
    try limits.require(expected);
    if (raw.len > limits.artifact_bytes) return error.V5RamLanesArtifactResourceLimit;
    var cursor = Wire.Cursor.init(raw);
    if (!std.mem.eql(u8, try cursor.take(MAGIC.len), MAGIC) or
        !std.mem.eql(u8, try cursor.take(32), &Protocol.abiId()) or
        !std.mem.eql(u8, try cursor.take(32), &try expected.identity()) or
        !std.mem.eql(u8, try cursor.take(32), &expected.expected_seal_digest) or
        !std.mem.eql(u8, try cursor.take(32), &try Proof.instanceId(expected.pin)) or
        try cursor.readInt(u32) != expected.pin.index) return error.UntrustedV5RamLanesArtifact;
    const length = std.math.cast(usize, try cursor.readInt(u64)) orelse return error.V5RamLanesArtifactResourceLimit;
    if (length == 0 or length > limits.proof_bytes) return error.V5RamLanesArtifactResourceLimit;
    const value = try readClaims(&cursor);
    _ = try Interaction.normalize(value, expected.pin.claim);
    if (value.range_count != expected.pin.request_count) return error.UntrustedV5RamLanesRangeCensus;
    const bytes = try cursor.take(length);
    try cursor.requireDone();
    return .{ .claim = value, .proof_bytes = bytes };
}
/// Exact shape for the shared PCS recipe. The backend derives its domain from
/// committed column logs, not PcsConfig.lifting_log_size. That optional value
/// still participates in exact config/transcript admission, but cannot enlarge
/// this lane family's actual FRI or Merkle domain.
pub fn preflightShape(expected: Expected, limits: Limits) !postcard.proof_preflight.Shape {
    try limits.require(expected);
    const config = expected.pin.config;
    return .{
        .config = .{ .pow_bits = config.pow_bits, .log_blowup_factor = config.fri_config.log_blowup_factor, .n_queries = config.fri_config.n_queries, .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound, .fold_step = config.fri_config.fold_step, .lifting_log_size = config.lifting_log_size },
        .tree_columns = .{ Protocol.FIXED_COLUMNS, Protocol.MAIN_COLUMNS, Protocol.INTERACTION_COLUMNS, @intCast(core.verifier_types.compositionColumnCount(2, core.fields.qm31.SECURE_EXTENSION_DEGREE).?) },
        .max_column_log_size = expected.pin.claim.row_log,
        .max_merkle_column_log_size = expected.pin.claim.row_log,
        .sample_width_limits = .{ 1, 2, 2, 1 },
        .hash_size = 32,
        .max_wire_bytes = limits.proof_bytes,
    };
}
pub fn decode(a: std.mem.Allocator, raw: []const u8, expected: Expected, limits: Limits) !Proof.Proof {
    const value = try envelope(raw, expected, limits);
    try postcard.proof_preflight.validate(value.proof_bytes, try preflightShape(expected, limits));
    // Preflight checks every received vector before allocations. The caller's
    // freeing host allocator supplies the aggregate live-memory budget.
    var stream = std.io.fixedBufferStream(value.proof_bytes);
    var stark = try postcard.deserializeProof(suite.Hasher, a, stream.reader());
    errdefer stark.deinit(a);
    if (stream.pos != value.proof_bytes.len) return error.TrailingV5RamLanesArtifact;
    const result = Proof.Proof{ .stark = stark, .claim = value.claim };
    try requireProof(&result, expected);
    return result;
}
pub const Entry = struct { bytes: u64, sha256: [32]u8, policy_digest: [32]u8 };
/// Borrows proof ownership. Exclusive file publication is removed on every
/// error after creation; existing files are never overwritten or deleted.
pub fn put(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, proof: *const Proof.Proof, expected: Expected, limits: Limits) !Entry {
    try requireName(name);
    const raw = try encode(a, proof, expected, limits);
    defer a.free(raw);
    const file = try dir.createFile(name, .{ .exclusive = true });
    defer file.close();
    errdefer dir.deleteFile(name) catch {};
    try file.writeAll(raw);
    try file.sync();
    return .{ .bytes = raw.len, .sha256 = sha256(raw), .policy_digest = try expected.identity() };
}
pub fn load(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, entry: Entry, expected: Expected, limits: Limits) !Proof.Proof {
    try requireName(name);
    try limits.require(expected);
    if (entry.bytes == 0 or entry.bytes > limits.artifact_bytes or !std.meta.eql(entry.policy_digest, try expected.identity()))
        return error.UntrustedV5RamLanesArtifact;
    const file = try dir.openFile(name, .{});
    defer file.close();
    if ((try file.stat()).size != entry.bytes) return error.UntrustedV5RamLanesArtifact;
    const bytes = std.math.cast(usize, entry.bytes) orelse return error.V5RamLanesArtifactResourceLimit;
    const raw = try a.alloc(u8, bytes);
    defer a.free(raw);
    if (try file.readAll(raw) != bytes) return error.UntrustedV5RamLanesArtifact;
    var extra: [1]u8 = undefined;
    if (try file.read(&extra) != 0) return error.TrailingV5RamLanesArtifact;
    if (!std.meta.eql(sha256(raw), entry.sha256)) return error.UntrustedV5RamLanesArtifactDigest;
    return decode(a, raw, expected, limits);
}
fn requireName(name: []const u8) !void {
    if (name.len == 0 or std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return error.InvalidV5RamLanesArtifactName;
    for (name) |byte| if (byte == '/' or byte == '\\' or byte == 0) return error.InvalidV5RamLanesArtifactName;
}
fn sha256(raw: []const u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(raw);
    return hash.finalResult();
}
