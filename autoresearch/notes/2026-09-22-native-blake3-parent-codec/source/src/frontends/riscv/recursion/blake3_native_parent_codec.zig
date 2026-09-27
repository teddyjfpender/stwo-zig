//! Bounded canonical parent envelope; pinned admission precedes proof allocation.
const std = @import("std");
const core = @import("stwo_core");
const postcard = @import("interop_postcard");
const suite = @import("blake3_engine_protocol.zig");
const protocol = @import("blake3_native_parent_protocol.zig");
const artifact = @import("blake3_native_parent_artifact.zig");
const components = @import("blake3_native_parent_components.zig");
const universal = @import("air/universal_challenges.zig");
pub const MAGIC = "B3NPART2";
pub const VERSION: u32 = 1;
pub const HEADER_BYTES = 8 + 4 + 32 + artifact.CLAIM_COUNT * 16 + 8;
pub const MAX_PROOF_BYTES = @import("artifact_limits.zig").MAX_CANONICAL_PROOF_BYTES;
pub fn shape(a: std.mem.Allocator, admission: *const protocol.Admission) !postcard.proof_preflight.Shape {
    const owner = try components.Owned.init(a, admission);
    defer owner.deinit();
    try owner.bind(universal.UniversalRelations.dummy(), @splat(core.fields.qm31.QM31.zero()));
    return @import("detached_proof_preflight.zig").shapeForEncoding(a, owner.admitted(), try admission.config(), MAX_PROOF_BYTES, @sizeOf(suite.Hasher.Hash), .raw_bytes);
}
pub fn encode(a: std.mem.Allocator, owned: *const artifact.Owned, admission: *const protocol.Admission) ![]u8 {
    try owned.validate(admission);
    var counter = Counter{};
    try postcard.serializeProof(suite.Hasher, &counter, owned.proof.?);
    const size = std.math.cast(usize, counter.bytes_written) orelse return error.Blake3ParentArtifactTooLarge;
    if (size == 0 or size > MAX_PROOF_BYTES) return error.Blake3ParentArtifactTooLarge;
    const result = try a.alloc(u8, HEADER_BYTES + size);
    errdefer a.free(result);
    @memcpy(result[0..8], MAGIC);
    std.mem.writeInt(u32, result[8..12], VERSION, .little);
    @memcpy(result[12..44], &owned.key_id);
    for (owned.claims, 0..) |claim, i| for (claim.toM31Array(), 0..) |value, j| {
        std.mem.writeInt(u32, result[44 + 16 * i + 4 * j ..][0..4], value.v, .little);
    };
    std.mem.writeInt(u64, result[HEADER_BYTES - 8 ..][0..8], @intCast(size), .little);
    var stream = std.io.fixedBufferStream(result[HEADER_BYTES..]);
    try postcard.serializeProof(suite.Hasher, stream.writer(), owned.proof.?);
    if (stream.pos != size) return error.Blake3ParentArtifactLengthMismatch;
    try postcard.proof_preflight.validate(result[HEADER_BYTES..], try shape(a, admission));
    return result;
}
pub fn decode(a: std.mem.Allocator, raw: []const u8, admission: *const protocol.Admission) !artifact.Owned {
    try admission.validate();
    if (raw.len < HEADER_BYTES) return error.TruncatedBlake3ParentArtifact;
    if (raw.len > HEADER_BYTES + MAX_PROOF_BYTES) return error.Blake3ParentArtifactTooLarge;
    if (!std.mem.eql(u8, raw[0..8], MAGIC) or std.mem.readInt(u32, raw[8..12], .little) != VERSION) return error.InvalidBlake3ParentArtifactVersion;
    if (!std.mem.eql(u8, raw[12..44], &admission.expected_id)) return error.UntrustedBlake3ParentKey;
    const size = std.mem.readInt(u64, raw[HEADER_BYTES - 8 ..][0..8], .little);
    if (size == 0 or size > MAX_PROOF_BYTES) return error.Blake3ParentArtifactTooLarge;
    if (size != raw.len - HEADER_BYTES) return error.Blake3ParentArtifactLengthMismatch;
    var claims: artifact.Claims = undefined;
    for (&claims, 0..) |*claim, i| {
        var words: [4]core.fields.m31.M31 = undefined;
        for (&words, 0..) |*value, j| {
            const word = std.mem.readInt(u32, raw[44 + 16 * i + 4 * j ..][0..4], .little);
            if (word >= core.fields.m31.Modulus) return error.InvalidBlake3ParentClaims;
            value.* = core.fields.m31.M31.fromCanonical(word);
        }
        claim.* = core.fields.qm31.QM31.fromM31Array(words);
    }
    try artifact.validateClaims(claims);
    const body = raw[HEADER_BYTES..];
    try postcard.proof_preflight.validate(body, try shape(a, admission));
    var stream = std.io.fixedBufferStream(body);
    const proof = try postcard.deserializeProof(suite.Hasher, a, stream.reader());
    var owned = artifact.Owned.init(a, proof, admission.expected_id, claims);
    errdefer owned.deinit();
    if (stream.pos != body.len) return error.Blake3ParentArtifactLengthMismatch;
    if (!std.meta.eql(proof.commitment_scheme_proof.config, admission.key.config)) return error.InvalidBlake3ParentProfile;
    try owned.validate(admission);
    return owned;
}

const Counter = struct {
    bytes_written: usize = 0,
    pub fn writeAll(self: *Counter, bytes: []const u8) !void {
        if (bytes.len > MAX_PROOF_BYTES - self.bytes_written) return error.Blake3ParentArtifactTooLarge;
        self.bytes_written += bytes.len;
    }
    pub fn writeByte(self: *Counter, byte: u8) !void {
        return self.writeAll(&.{byte});
    }
};
