//! Bounded full-width Ethereum envelope. Received bytes never select a key.
const std = @import("std");
const core = @import("stwo_core");
const postcard = @import("interop_postcard");
const api = @import("blake3_ethereum_proof.zig");
const native = @import("../air/statement.zig");
const base = @import("blake3_execution_codec.zig");
const extension_wire = @import("guest_precompile/ethereum_proof_artifact_wire.zig");
const Cursor = @import("guest_precompile/proof_artifact_wire.zig").Cursor;
const suite = core.proof_suites.Blake3;
pub const MAGIC = "B3EHART1";
pub const HEADER_BYTES: usize = 64;
pub const MAX_PROOF_BYTES = base.MAX_PROOF_BYTES;
pub fn encode(a: std.mem.Allocator, proof: *const api.Proof, prepared: anytype, expected: [32]u8) ![]u8 {
    try prepared.validate(expected);
    if (!std.mem.eql(u8, &proof.key_id, &expected)) return error.UntrustedExecutionKey;
    if (proof.native_claims.n_components != prepared.native.n_components or proof.native_claims.n_infra != prepared.native.n_infra) return error.InvalidInteractionClaim;
    if (!std.meta.eql(proof.stark.commitment_scheme_proof.config, prepared.config)) return error.InvalidExecutionConfig;
    if (proof.stark.commitment_scheme_proof.commitments.items.len != 4) return error.InvalidExecutionProof;
    try @import("blake3_execution_proof.zig").admitPreprocessedRoot(prepared.root, proof.stark.commitment_scheme_proof.commitments.items[0]);
    var proof_counter = Counter{};
    try postcard.serializeProof(suite.Hasher, &proof_counter, proof.stark);
    var claim_counter = Counter{};
    try extension_wire.encodeExtensionClaim(&claim_counter, &prepared.extension, &proof.extension_claims);
    const count = base.claimCount(&prepared.native);
    const extension_at = HEADER_BYTES + count * 16;
    const proof_at = try std.math.add(usize, extension_at, claim_counter.bytes_written);
    const raw = try a.alloc(u8, try std.math.add(usize, proof_at, proof_counter.bytes_written));
    errdefer a.free(raw);
    @memcpy(raw[0..8], MAGIC);
    std.mem.writeInt(u32, raw[8..12], 1, .little);
    @memcpy(raw[12..44], &expected);
    std.mem.writeInt(u32, raw[44..48], @intCast(count), .little);
    std.mem.writeInt(u32, raw[48..52], @intCast(claim_counter.bytes_written), .little);
    std.mem.writeInt(u32, raw[52..56], 0, .little);
    std.mem.writeInt(u64, raw[56..64], proof_counter.bytes_written, .little);
    var cursor = HEADER_BYTES;
    for (prepared.native.component_descs[0..prepared.native.n_components], 0..) |desc, i| for (try proof.native_claims.opcodeClaims(desc.family, i)) |claim| try base.writeClaim(raw, &cursor, claim);
    for (prepared.native.infra_descs[0..prepared.native.n_infra], 0..) |desc, i| for (try proof.native_claims.infraClaims(desc.kind, i)) |claim| try base.writeClaim(raw, &cursor, claim);
    for (proof.hash_claims) |claim| try base.writeClaim(raw, &cursor, claim);
    if (cursor != extension_at) return error.InvalidExecutionArtifactLength;
    var claims = std.io.fixedBufferStream(raw[extension_at..proof_at]);
    try extension_wire.encodeExtensionClaim(claims.writer(), &prepared.extension, &proof.extension_claims);
    if (claims.pos != claim_counter.bytes_written) return error.InvalidExecutionArtifactLength;
    var stream = std.io.fixedBufferStream(raw[proof_at..]);
    try postcard.serializeProof(suite.Hasher, stream.writer(), proof.stark);
    if (stream.pos != proof_counter.bytes_written) return error.InvalidExecutionArtifactLength;
    try postcard.proof_preflight.validate(raw[proof_at..], prepared.preflight);
    return raw;
}
pub fn decode(a: std.mem.Allocator, raw: []const u8, prepared: anytype, expected: [32]u8) !api.Proof {
    try prepared.validate(expected);
    if (raw.len < HEADER_BYTES) return error.TruncatedExecutionArtifact;
    if (!std.mem.eql(u8, raw[0..8], MAGIC) or std.mem.readInt(u32, raw[8..12], .little) != 1 or std.mem.readInt(u32, raw[52..56], .little) != 0) return error.InvalidExecutionArtifactVersion;
    if (!std.mem.eql(u8, raw[12..44], &expected)) return error.UntrustedExecutionKey;
    const count = base.claimCount(&prepared.native);
    if (std.mem.readInt(u32, raw[44..48], .little) != count) return error.InvalidInteractionClaim;
    const zero = try @import("guest_precompile/ethereum_types.zig").ExtensionClaim.zeroForStatement(&prepared.extension);
    var claim_counter = Counter{};
    try extension_wire.encodeExtensionClaim(&claim_counter, &prepared.extension, &zero);
    if (std.mem.readInt(u32, raw[48..52], .little) != claim_counter.bytes_written) return error.InvalidInteractionClaim;
    const extension_at = HEADER_BYTES + count * 16;
    const proof_at = try std.math.add(usize, extension_at, claim_counter.bytes_written);
    if (raw.len < proof_at) return error.TruncatedExecutionArtifact;
    const size = std.mem.readInt(u64, raw[56..64], .little);
    if (size == 0 or size > MAX_PROOF_BYTES) return error.ExecutionArtifactTooLarge;
    if (size != raw.len - proof_at) return error.InvalidExecutionArtifactLength;
    // Validate all field limbs, fixed-size extension claims and nested proof
    // vector bounds before allocating anything from the serialized payload.
    var cursor = HEADER_BYTES;
    for (0..count) |_| _ = try base.readClaim(raw, &cursor);
    var ext_cursor = Cursor.init(raw[extension_at..proof_at]);
    const extension = try extension_wire.decodeExtensionClaim(&ext_cursor, &prepared.extension);
    try ext_cursor.requireDone();
    try postcard.proof_preflight.validate(raw[proof_at..], prepared.preflight);
    const claims = try a.create(native.RiscVInteractionClaim);
    errdefer a.destroy(claims);
    claims.initZeroInto();
    claims.n_components = prepared.native.n_components;
    claims.n_infra = prepared.native.n_infra;
    cursor = HEADER_BYTES;
    for (prepared.native.component_descs[0..prepared.native.n_components], 0..) |desc, i| for (claims.opcode_claims[i][0..@import("../air/lookups/opcode_entries.zig").batchCount(desc.family)]) |*claim| {
        claim.* = try base.readClaim(raw, &cursor);
    };
    for (prepared.native.infra_descs[0..prepared.native.n_infra], 0..) |desc, i| {
        if (desc.kind == .clock_update) {
            for (&claims.clock_claims[i]) |*claim| claim.* = try base.readClaim(raw, &cursor);
        } else {
            if (native.tableKind(desc.kind) == null) return error.InvalidExecutionArtifact;
            claims.lookup_claims[i] = try base.readClaim(raw, &cursor);
        }
    }
    var hashes: [@import("blake3_commitment_components.zig").Airs.len]core.fields.qm31.QM31 = undefined;
    for (&hashes) |*claim| claim.* = try base.readClaim(raw, &cursor);
    if (cursor != extension_at) return error.InvalidExecutionArtifactLength;
    var stream = std.io.fixedBufferStream(raw[proof_at..]);
    var proof = try postcard.deserializeProof(suite.Hasher, a, stream.reader());
    errdefer proof.deinit(a);
    if (stream.pos != size or proof.commitment_scheme_proof.commitments.items.len != 4) return error.InvalidExecutionArtifactLength;
    if (!std.meta.eql(proof.commitment_scheme_proof.config, prepared.config)) return error.InvalidExecutionConfig;
    try @import("blake3_execution_proof.zig").admitPreprocessedRoot(prepared.root, proof.commitment_scheme_proof.commitments.items[0]);
    return .{ .stark = proof, .key_id = expected, .native_claims = claims, .hash_claims = hashes, .extension_claims = extension };
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
