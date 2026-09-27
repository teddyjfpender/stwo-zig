//! Bounded execution artifact. Caller-pinned prepared geometry precedes decode;
//! the envelope's key ID is compared, never used to select a verification key.
const std = @import("std");
const core = @import("stwo_core");
const postcard = @import("interop_postcard");
const api = @import("blake3_execution_proof.zig");
const statement = @import("../air/statement.zig");
const suite = core.proof_suites.Blake3;
pub const MAGIC = "B3EXART1";
pub const HEADER_BYTES: usize = 56;
pub const MAX_PROOF_BYTES = @import("../recursion/artifact_limits.zig").MAX_CANONICAL_PROOF_BYTES;
pub fn encode(a: std.mem.Allocator, proof: *const api.Proof, prepared: anytype, expected: [32]u8) ![]u8 {
    try prepared.validate(expected);
    if (!std.mem.eql(u8, &proof.key_id, &expected)) return error.UntrustedExecutionKey;
    if (proof.stark.commitment_scheme_proof.commitments.items.len != 4) return error.InvalidExecutionProof;
    try api.admitPreprocessedRoot(prepared.key.preprocessed_root, proof.stark.commitment_scheme_proof.commitments.items[0]);
    if (proof.native_claims.n_components != prepared.shape.n_components or proof.native_claims.n_infra != prepared.shape.n_infra) return error.InvalidInteractionClaim;
    if (!std.meta.eql(proof.stark.commitment_scheme_proof.config, prepared.config)) return error.InvalidExecutionConfig;
    const count = claimCount(&prepared.shape);
    var counter = Counter{};
    try postcard.serializeProof(suite.Hasher, &counter, proof.stark);
    const body_at = HEADER_BYTES + count * 16;
    const raw = try a.alloc(u8, body_at + counter.bytes_written);
    errdefer a.free(raw);
    @memcpy(raw[0..8], MAGIC);
    std.mem.writeInt(u32, raw[8..12], 1, .little);
    @memcpy(raw[12..44], &expected);
    std.mem.writeInt(u32, raw[44..48], @intCast(count), .little);
    std.mem.writeInt(u64, raw[48..56], counter.bytes_written, .little);
    var cursor = HEADER_BYTES;
    for (prepared.shape.component_descs[0..prepared.shape.n_components], 0..) |desc, i| {
        for (try proof.native_claims.opcodeClaims(desc.family, i)) |claim| try writeClaim(raw, &cursor, claim);
    }
    for (prepared.shape.infra_descs[0..prepared.shape.n_infra], 0..) |desc, i| {
        for (try proof.native_claims.infraClaims(desc.kind, i)) |claim| try writeClaim(raw, &cursor, claim);
    }
    for (proof.hash_claims) |claim| try writeClaim(raw, &cursor, claim);
    if (cursor != body_at) return error.InvalidExecutionArtifactLength;
    var stream = std.io.fixedBufferStream(raw[body_at..]);
    try postcard.serializeProof(suite.Hasher, stream.writer(), proof.stark);
    if (stream.pos != counter.bytes_written) return error.InvalidExecutionArtifactLength;
    try postcard.proof_preflight.validate(raw[body_at..], prepared.preflight);
    return raw;
}
pub fn decode(a: std.mem.Allocator, raw: []const u8, prepared: anytype, expected: [32]u8) !api.Proof {
    try prepared.validate(expected);
    if (raw.len < HEADER_BYTES) return error.TruncatedExecutionArtifact;
    if (!std.mem.eql(u8, raw[0..8], MAGIC) or std.mem.readInt(u32, raw[8..12], .little) != 1) return error.InvalidExecutionArtifactVersion;
    if (!std.mem.eql(u8, raw[12..44], &expected)) return error.UntrustedExecutionKey;
    const count = claimCount(&prepared.shape);
    if (std.mem.readInt(u32, raw[44..48], .little) != count) return error.InvalidInteractionClaim;
    const body_at = HEADER_BYTES + count * 16;
    if (raw.len < body_at) return error.TruncatedExecutionArtifact;
    const size = std.mem.readInt(u64, raw[48..56], .little);
    if (size == 0 or size > MAX_PROOF_BYTES) return error.ExecutionArtifactTooLarge;
    if (size != raw.len - body_at) return error.InvalidExecutionArtifactLength;
    // Check all canonical claim limbs and all nested vector bounds before any
    // allocation driven by the serialized proof.
    var cursor = HEADER_BYTES;
    for (0..count) |_| _ = try readClaim(raw, &cursor);
    try postcard.proof_preflight.validate(raw[body_at..], prepared.preflight);
    const claims = try a.create(statement.RiscVInteractionClaim);
    errdefer a.destroy(claims);
    claims.initZeroInto();
    claims.n_components = prepared.shape.n_components;
    claims.n_infra = prepared.shape.n_infra;
    cursor = HEADER_BYTES;
    for (prepared.shape.component_descs[0..prepared.shape.n_components], 0..) |desc, i| {
        for (claims.opcode_claims[i][0..@import("../air/lookups/opcode_entries.zig").batchCount(desc.family)]) |*claim| claim.* = try readClaim(raw, &cursor);
    }
    for (prepared.shape.infra_descs[0..prepared.shape.n_infra], 0..) |desc, i| {
        if (desc.kind == .clock_update) {
            for (&claims.clock_claims[i]) |*claim| claim.* = try readClaim(raw, &cursor);
        } else {
            if (statement.tableKind(desc.kind) == null) return error.InvalidExecutionArtifact;
            claims.lookup_claims[i] = try readClaim(raw, &cursor);
        }
    }
    var hash_claims: [@import("blake3_commitment_components.zig").Airs.len]core.fields.qm31.QM31 = undefined;
    for (&hash_claims) |*claim| claim.* = try readClaim(raw, &cursor);
    if (cursor != body_at) return error.InvalidExecutionArtifactLength;
    var stream = std.io.fixedBufferStream(raw[body_at..]);
    var proof = try postcard.deserializeProof(suite.Hasher, a, stream.reader());
    errdefer proof.deinit(a);
    if (stream.pos != size or proof.commitment_scheme_proof.commitments.items.len != 4) return error.InvalidExecutionArtifactLength;
    if (!std.meta.eql(proof.commitment_scheme_proof.config, prepared.config)) return error.InvalidExecutionConfig;
    try api.admitPreprocessedRoot(prepared.key.preprocessed_root, proof.commitment_scheme_proof.commitments.items[0]);
    return .{ .stark = proof, .key_id = expected, .native_claims = claims, .hash_claims = hash_claims };
}
pub fn claimCount(shape: *const statement.Blake3ExecutionStatement) usize {
    var count: usize = @import("blake3_commitment_components.zig").Airs.len;
    for (shape.component_descs[0..shape.n_components]) |desc| count += @import("../air/lookups/opcode_entries.zig").batchCount(desc.family);
    for (shape.infra_descs[0..shape.n_infra]) |desc| count += statement.nClaimedSumsForInfra(desc.kind);
    return count;
}
pub fn writeClaim(raw: []u8, cursor: *usize, claim: core.fields.qm31.QM31) !void {
    for (claim.toM31Array()) |value| {
        if (value.v >= core.fields.m31.Modulus) return error.InvalidInteractionClaim;
        std.mem.writeInt(u32, raw[cursor.*..][0..4], value.v, .little);
        cursor.* += 4;
    }
}
pub fn readClaim(raw: []const u8, cursor: *usize) !core.fields.qm31.QM31 {
    var words: [4]core.fields.m31.M31 = undefined;
    for (&words) |*value| {
        const word = std.mem.readInt(u32, raw[cursor.*..][0..4], .little);
        if (word >= core.fields.m31.Modulus) return error.InvalidInteractionClaim;
        value.* = core.fields.m31.M31.fromCanonical(word);
        cursor.* += 4;
    }
    return core.fields.qm31.QM31.fromM31Array(words);
}
const Counter = struct {
    bytes_written: usize = 0,
    pub fn writeAll(self: *Counter, bytes: []const u8) !void {
        if (bytes.len > MAX_PROOF_BYTES - self.bytes_written) return error.ExecutionArtifactTooLarge;
        self.bytes_written += bytes.len;
    }
    pub fn writeByte(self: *Counter, byte: u8) !void {
        try self.writeAll(&.{byte});
    }
};
