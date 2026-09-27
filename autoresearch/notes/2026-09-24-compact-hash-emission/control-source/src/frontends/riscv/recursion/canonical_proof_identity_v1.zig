//! Canonical proof-byte identities, independent of publication and witness preparation.
const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const channel = @import("poseidon2_channel.zig");
const protocol = @import("protocol.zig");
const NativeDigest = channel.Digest;
const Sha256Digest = [32]u8;
pub const Error = error{ EmptyProofEncoding, EmptySha256Digest, InvalidNativeDigest, ProofEncodingTooLarge, ProofEncodingLengthMismatch, ProofIdentityAlreadyFinalized };

pub const CanonicalProofIdentityV1 = struct {
    byte_count: u32,
    proof_id: NativeDigest,
    canonical_proof_sha_id: Sha256Digest,

    pub fn fromBytes(bytes: []const u8) Error!CanonicalProofIdentityV1 {
        var stream = try CanonicalProofIdentityStreamV1.init(bytes.len);
        try stream.writeAll(bytes);
        return stream.finalize();
    }

    pub fn validate(self: CanonicalProofIdentityV1) Error!void {
        if (self.byte_count == 0) return error.EmptyProofEncoding;
        try requireNativeDigest(self.proof_id);
        try requireSha256Digest(self.canonical_proof_sha_id);
    }
};

pub const CanonicalProofIdentityStreamV1 = struct {
    expected_byte_count: u32,
    observed_byte_count: u32 = 0,
    sha256: std.crypto.hash.sha2.Sha256 = std.crypto.hash.sha2.Sha256.init(.{}),
    proof_id: channel.CanonicalWordHasher,
    pending_low_byte: ?u8 = null,
    finalized: bool = false,

    pub fn init(expected_byte_count: usize) Error!CanonicalProofIdentityStreamV1 {
        if (expected_byte_count == 0) return error.EmptyProofEncoding;
        const exact_count = std.math.cast(u32, expected_byte_count) orelse
            return error.ProofEncodingTooLarge;
        if (exact_count >= m31.Modulus) return error.ProofEncodingTooLarge;
        var proof_id = channel.CanonicalWordHasher.init(protocol.PROOF_ID_DOMAIN);
        const length = [_]M31{M31.fromCanonical(exact_count)};
        proof_id.update(&length);
        return .{
            .expected_byte_count = exact_count,
            .proof_id = proof_id,
        };
    }

    pub fn write(
        self: *CanonicalProofIdentityStreamV1,
        bytes: []const u8,
    ) Error!usize {
        if (self.finalized) return error.ProofIdentityAlreadyFinalized;
        const next_count = std.math.add(
            u32,
            self.observed_byte_count,
            std.math.cast(u32, bytes.len) orelse
                return error.ProofEncodingTooLarge,
        ) catch return error.ProofEncodingTooLarge;
        if (next_count > self.expected_byte_count)
            return error.ProofEncodingLengthMismatch;

        self.sha256.update(bytes);
        var at: usize = 0;
        if (self.pending_low_byte) |low| {
            if (bytes.len != 0) {
                self.absorbByteLimb(low, bytes[0]);
                self.pending_low_byte = null;
                at = 1;
            }
        }
        while (at + 1 < bytes.len) : (at += 2)
            self.absorbByteLimb(bytes[at], bytes[at + 1]);
        if (at < bytes.len) self.pending_low_byte = bytes[at];
        self.observed_byte_count = next_count;
        return bytes.len;
    }

    pub fn writeAll(
        self: *CanonicalProofIdentityStreamV1,
        bytes: []const u8,
    ) Error!void {
        _ = try self.write(bytes);
    }

    pub fn writeByte(
        self: *CanonicalProofIdentityStreamV1,
        byte: u8,
    ) Error!void {
        const bytes = [_]u8{byte};
        _ = try self.write(&bytes);
    }

    pub fn finalize(
        self: *CanonicalProofIdentityStreamV1,
    ) Error!CanonicalProofIdentityV1 {
        if (self.finalized) return error.ProofIdentityAlreadyFinalized;
        if (self.observed_byte_count != self.expected_byte_count)
            return error.ProofEncodingLengthMismatch;
        if (self.pending_low_byte) |low| self.absorbByteLimb(low, 0);
        self.pending_low_byte = null;
        self.finalized = true;
        var canonical_proof_sha_id: Sha256Digest = undefined;
        self.sha256.final(&canonical_proof_sha_id);
        const result = CanonicalProofIdentityV1{
            .byte_count = self.expected_byte_count,
            .proof_id = self.proof_id.finalize(),
            .canonical_proof_sha_id = canonical_proof_sha_id,
        };
        try result.validate();
        return result;
    }

    fn absorbByteLimb(
        self: *CanonicalProofIdentityStreamV1,
        low: u8,
        high: u8,
    ) void {
        const limb = [_]M31{M31.fromCanonical(
            @as(u32, low) | (@as(u32, high) << 8),
        )};
        self.proof_id.update(&limb);
    }
};

pub fn requireNativeDigest(value: NativeDigest) Error!void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= m31.Modulus) return error.InvalidNativeDigest;
        aggregate |= word;
    }
    if (aggregate == 0) return error.InvalidNativeDigest;
}

pub fn requireSha256Digest(value: Sha256Digest) Error!void {
    var aggregate: u8 = 0;
    for (value) |byte| aggregate |= byte;
    if (aggregate == 0) return error.EmptySha256Digest;
}
