//! Opaque successful-verifier capability for one temporal parent proof.
//!
//! The native verifier mints this borrowed value only after the proof capture,
//! complete interaction audit, and recursive-child admission have all been
//! reconstructed locally.  Consumers can open and validate it, but no public
//! constructor can promote detached proof-shaped values into this authority.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const m31 = stwo_core.fields.m31;
const channel = frontend.recursion.poseidon2_channel;

pub const FORMAT_VERSION: u16 = 1;
pub const PUBLIC_MINT_AVAILABLE = false;
pub const HEAP_ALLOCATIONS_PER_MINT: usize = 0;

pub const Error = error{TemporalVerifierEvidenceMismatch};

/// Value-only statement sealed into the transaction-local verifier
/// capability.  `recursive_admission_sha_id` binds the exact complete-parent
/// receipt and seal that the next recursion layer will consume.
pub const BindingV1 = struct {
    canonical_proof_byte_count: u32,
    proof_id: channel.Digest,
    canonical_proof_sha_id: [32]u8,
    capture_id: channel.Digest,
    transcript_id: channel.Digest,
    cohort_authority_sha_id: [32]u8,
    manifest_sha_id: [32]u8,
    claims_sha_id: [32]u8,
    generated_interactions_sha_id: [32]u8,
    audit_sha_id: [32]u8,
    closure_receipt_sha_id: [32]u8,
    recursive_admission_sha_id: [32]u8,

    pub fn validate(self: *const BindingV1) Error!void {
        if (self.canonical_proof_byte_count == 0 or
            !nativeDigestCanonicalNonzero(self.proof_id) or
            !nativeDigestCanonicalNonzero(self.capture_id) or
            !nativeDigestCanonicalNonzero(self.transcript_id))
        {
            return error.TemporalVerifierEvidenceMismatch;
        }
        inline for (.{
            self.canonical_proof_sha_id,
            self.cohort_authority_sha_id,
            self.manifest_sha_id,
            self.claims_sha_id,
            self.generated_interactions_sha_id,
            self.audit_sha_id,
            self.closure_receipt_sha_id,
            self.recursive_admission_sha_id,
        }) |value| if (std.mem.allEqual(u8, &value, 0))
            return error.TemporalVerifierEvidenceMismatch;
    }
};

pub const EvidenceV1 = opaque {};

pub const StorageV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    verified: bool = true,
    padding: [5]u8 = [_]u8{0} ** 5,
    binding: BindingV1,
    identity: [32]u8,
};

pub fn mint(storage: *StorageV1, binding: BindingV1) Error!*const EvidenceV1 {
    try binding.validate();
    storage.* = .{ .binding = binding, .identity = undefined };
    storage.identity = identity(storage);
    return @ptrCast(storage);
}

pub fn open(evidence: *const EvidenceV1) Error!BindingV1 {
    const storage: *const StorageV1 = @ptrCast(@alignCast(evidence));
    if (storage.format_version != FORMAT_VERSION or !storage.verified or
        !std.mem.allEqual(u8, &storage.padding, 0) or
        !std.mem.eql(u8, &storage.identity, &identity(storage)))
    {
        return error.TemporalVerifierEvidenceMismatch;
    }
    try storage.binding.validate();
    return storage.binding;
}

fn identity(evidence: *const StorageV1) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/temporal-verifier-success-evidence/v1\x00");
    hashInt(&hash, u16, evidence.format_version);
    hashInt(&hash, u8, @intFromBool(evidence.verified));
    hash.update(&evidence.padding);
    const binding = evidence.binding;
    hashInt(&hash, u32, binding.canonical_proof_byte_count);
    hashNative(&hash, binding.proof_id);
    hash.update(&binding.canonical_proof_sha_id);
    hashNative(&hash, binding.capture_id);
    hashNative(&hash, binding.transcript_id);
    hash.update(&binding.cohort_authority_sha_id);
    hash.update(&binding.manifest_sha_id);
    hash.update(&binding.claims_sha_id);
    hash.update(&binding.generated_interactions_sha_id);
    hash.update(&binding.audit_sha_id);
    hash.update(&binding.closure_receipt_sha_id);
    hash.update(&binding.recursive_admission_sha_id);
    return hash.finalResult();
}

fn nativeDigestCanonicalNonzero(value: channel.Digest) bool {
    var any = false;
    for (value) |word| {
        if (word >= m31.Modulus) return false;
        any = any or word != 0;
    }
    return any;
}

fn hashNative(hash: anytype, value: channel.Digest) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (PUBLIC_MINT_AVAILABLE or HEAP_ALLOCATIONS_PER_MINT != 0)
        @compileError("temporal verifier success capability contract drifted");
}
