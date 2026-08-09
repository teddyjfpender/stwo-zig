//! Fixed wire-level types for the native, non-recursive R-007 reference.

const std = @import("std");
const hash = @import("hash.zig");

pub const Digest = hash.Digest;
pub const M31_MODULUS: u32 = 0x7fff_ffff;
pub const MAX_LEAVES: usize = 1024;
pub const MIN_LEAVES: usize = 2;
pub const RELATION_SCHEMA_ID: u32 = 12;
pub const RELATION_SCHEMA_VERSION: u16 = 1;
pub const RELATION_ARITY: u16 = 32;
pub const EXECUTION_PROFILE_ID: u16 = 1;
pub const FORMAT_VERSION: u16 = 1;
pub const AGGREGATION_PROFILE_ID: u16 = 1;
pub const GUEST_COMPONENT_PRESENT: u8 = 1;
pub const KNOWN_DESCRIPTOR_FLAGS: u8 = GUEST_COMPONENT_PRESENT;

pub const MANIFEST_MAGIC = [8]u8{
    'S', 'T', 'W', 'A', 'G', 'G', 'S', 0,
};
pub const AGGREGATION_PROFILE_TAG =
    "riscv-guest-poseidon2-paired-v1\x00";

/// SHA-256 identity of `riscv.poseidon2_m31.permute.v1`, pinned by the
/// execution-profile admission contract.
pub const EXECUTION_SEMANTIC_DIGEST = Digest{
    0x9e, 0x8c, 0x3b, 0x5a, 0xcc, 0xdc, 0x2b, 0xe3,
    0x1c, 0xf8, 0xca, 0x12, 0x8b, 0x5b, 0x27, 0xc8,
    0x76, 0x13, 0xf6, 0x91, 0xee, 0x8f, 0xd2, 0x5e,
    0x03, 0x1f, 0x42, 0x86, 0xce, 0xac, 0x81, 0xed,
};

pub const LeafRole = enum(u8) {
    core_request = 1,
    poseidon2_provider = 2,
};

pub const TreePolicy = enum(u8) {
    balanced_adjacent_position_preserving_two_to_one = 1,
};

/// Canonical `(c0.a, c0.b, c1.a, c1.b)` M31 limbs.
pub const SecureFelt = struct {
    limbs: [4]u32,

    pub fn zero() SecureFelt {
        return .{ .limbs = .{ 0, 0, 0, 0 } };
    }

    pub fn validate(self: SecureFelt) !void {
        for (self.limbs) |limb| {
            if (limb >= M31_MODULUS) return error.NonCanonicalM31;
        }
    }

    pub fn eql(lhs: SecureFelt, rhs: SecureFelt) bool {
        return std.mem.eql(u32, &lhs.limbs, &rhs.limbs);
    }

    pub fn isZero(self: SecureFelt) bool {
        return self.eql(zero());
    }

    pub fn add(lhs: SecureFelt, rhs: SecureFelt) SecureFelt {
        var limbs: [4]u32 = undefined;
        for (&limbs, lhs.limbs, rhs.limbs) |*out, left, right| {
            const sum = @as(u64, left) + right;
            out.* = @intCast(if (sum >= M31_MODULUS)
                sum - M31_MODULUS
            else
                sum);
        }
        return .{ .limbs = limbs };
    }

    pub fn neg(self: SecureFelt) SecureFelt {
        var limbs: [4]u32 = undefined;
        for (&limbs, self.limbs) |*out, limb| {
            out.* = if (limb == 0) 0 else M31_MODULUS - limb;
        }
        return .{ .limbs = limbs };
    }
};

/// Verifier-owned identities that are not inferable from a manifest.
pub const AcceptedProtocolV1 = struct {
    proof_protocol_digest: Digest,
    relation_registry_digest: Digest,

    pub fn validate(self: AcceptedProtocolV1) !void {
        if (hash.isZero(self.proof_protocol_digest) or
            hash.isZero(self.relation_registry_digest))
        {
            return error.ZeroProtocolIdentity;
        }
    }
};

pub const ManifestHeaderV1 = struct {
    magic: [8]u8 = MANIFEST_MAGIC,
    version: u16 = FORMAT_VERSION,
    aggregation_profile_id: u16 = AGGREGATION_PROFILE_ID,
    proof_protocol_digest: Digest,
    execution_profile_id: u16 = EXECUTION_PROFILE_ID,
    execution_semantic_digest: Digest = EXECUTION_SEMANTIC_DIGEST,
    relation_registry_digest: Digest,
    relation_schema_id: u32 = RELATION_SCHEMA_ID,
    relation_schema_version: u16 = RELATION_SCHEMA_VERSION,
    relation_arity: u16 = RELATION_ARITY,
    leaf_count: u32,
    request_set_digest: Digest,
    tree_policy: TreePolicy =
        .balanced_adjacent_position_preserving_two_to_one,
    reserved: [7]u8 = .{0} ** 7,
};

pub const LeafDescriptorV1 = struct {
    leaf_index: u32,
    pair_index: u32,
    role: LeafRole,
    flags: u8 = GUEST_COMPONENT_PRESENT,
    reserved: u16 = 0,
    job_digest: Digest,
    leaf_statement_digest: Digest,
    leaf_air_artifact_digest: Digest,
    preprocessed_root: Digest,
    main_root: Digest,
    guest_call_commitment: Digest,
    guest_call_count: u64,
    proof_protocol_digest: Digest,
    execution_profile_id: u16 = EXECUTION_PROFILE_ID,
    relation_schema_version: u16 = RELATION_SCHEMA_VERSION,
    execution_semantic_digest: Digest = EXECUTION_SEMANTIC_DIGEST,
    relation_registry_digest: Digest,
    relation_schema_id: u32 = RELATION_SCHEMA_ID,
    relation_arity: u16 = RELATION_ARITY,
    reserved_tail: u16 = 0,
};

pub const ManifestViewV1 = struct {
    header: ManifestHeaderV1,
    descriptors: []const LeafDescriptorV1,
};

pub fn validLeafCount(count: usize) bool {
    return count >= MIN_LEAVES and
        count <= MAX_LEAVES and
        std.math.isPowerOfTwo(count);
}

pub fn validateCallCount(count: u64) !void {
    const doubled = std.math.mul(u64, count, 2) catch
        return error.CallCountOutOfRange;
    if (doubled >= M31_MODULUS) return error.CallCountOutOfRange;
}

pub fn log2ExactPowerOfTwo(value: usize) u8 {
    std.debug.assert(value != 0 and std.math.isPowerOfTwo(value));
    return @intCast(@ctz(value));
}
