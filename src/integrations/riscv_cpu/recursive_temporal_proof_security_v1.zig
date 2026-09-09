//! Machine-readable proof-security authority for temporal recursion.
//!
//! A verifier key or opaque profile digest is not a substitute for the exact
//! transcript, PCS, and recursive-ingress policy which gives that key meaning.
//! This pointer-free descriptor is sealed into every temporal node profile so
//! the controller can reject a functional proof profile without interpreting
//! a VK or relying on comments.

const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const M31_FIELD_ID: u32 = 0x4d33_3101;
const AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-proof-security/v1\x00";

pub const KindV1 = enum(u8) {
    proofless_empty = 1,
    segment_v2_poseidon2 = 2,
    ethereum_segment_v3_blake2s = 3,
    ethereum_segment_v3_poseidon2 = 4,
    recursive_parent_functional = 5,
    recursive_parent_secure = 6,
};

pub const HashSuiteV1 = enum(u8) {
    none = 0,
    blake2s = 1,
    poseidon2_m31 = 2,
};

pub const RecursiveIngressV1 = enum(u8) {
    no_proof = 0,
    segment_v2_base = 1,
    native_only = 2,
    ethereum_segment_v3_full = 3,
    recursive_parent = 4,
};

/// Exact proof profile. `configured_pcs_bits` is the mechanical
/// `pcs_pow_bits + log_blowup_factor * query_count` ledger. The separately
/// named conjectured bound is policy, never inferred from that ledger.
pub const ProofSecurityV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    kind: KindV1,
    hash_suite: HashSuiteV1,
    recursive_ingress: RecursiveIngressV1,
    proof_present: bool,
    padding: [3]u8 = .{ 0, 0, 0 },
    field_id: u32,
    interaction_pow_bits: u32,
    pcs_pow_bits: u32,
    fri_log_blowup_factor: u32,
    fri_query_count: u32,
    fri_fold_step: u32,
    fri_log_last_layer_degree_bound: u32,
    pcs_lifting_mode: u32,
    configured_pcs_bits: u32,
    conjectured_security_bits: u32,
    identity: [32]u8,

    pub fn prooflessEmpty() ProofSecurityV1 {
        return initExact(
            .proofless_empty,
            .none,
            .no_proof,
            false,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        );
    }

    pub fn segmentV2Poseidon2() ProofSecurityV1 {
        return initExact(
            .segment_v2_poseidon2,
            .poseidon2_m31,
            .segment_v2_base,
            true,
            10,
            16,
            1,
            193,
            4,
            0,
            120,
        );
    }

    /// Existing native Ethereum product. It is intentionally not a recursive
    /// ingress profile: its Blake2s capture cannot populate the Poseidon2-M31
    /// verifier rows by relabeling.
    pub fn ethereumSegmentV3Blake2s() ProofSecurityV1 {
        return initExact(
            .ethereum_segment_v3_blake2s,
            .blake2s,
            .native_only,
            true,
            10,
            26,
            1,
            70,
            1,
            0,
            96,
        );
    }

    /// Selected production recursion profile. This is append-only relative
    /// to the native Blake artifact and requires a distinct full Ethereum V3
    /// outer manifest (base plus 14 extension claims and the global link).
    pub fn ethereumSegmentV3Poseidon2() ProofSecurityV1 {
        return initExact(
            .ethereum_segment_v3_poseidon2,
            .poseidon2_m31,
            .ethereum_segment_v3_full,
            true,
            10,
            16,
            1,
            193,
            4,
            0,
            120,
        );
    }

    pub fn recursiveParentFunctional() ProofSecurityV1 {
        return initExact(
            .recursive_parent_functional,
            .poseidon2_m31,
            .recursive_parent,
            true,
            0,
            0,
            1,
            3,
            1,
            0,
            0,
        );
    }

    pub fn recursiveParentSecure() ProofSecurityV1 {
        return initExact(
            .recursive_parent_secure,
            .poseidon2_m31,
            .recursive_parent,
            true,
            10,
            16,
            1,
            193,
            4,
            0,
            120,
        );
    }

    pub fn validate(self: *const ProofSecurityV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.mem.allEqual(u8, &self.padding, 0) or
            self.field_id != M31_FIELD_ID or self.pcs_lifting_mode != 0)
        {
            return error.InvalidProofSecurity;
        }
        const expected = expectedForKind(self.kind);
        if (!fieldsEqual(self, &expected))
            return error.InvalidProofSecurity;
        if (!std.mem.eql(u8, &self.identity, &authorityIdentity(self)))
            return error.ProofSecurityIdentityMismatch;
    }

    pub fn isProductionRecursiveProof(self: *const ProofSecurityV1) bool {
        return switch (self.kind) {
            .segment_v2_poseidon2,
            .ethereum_segment_v3_poseidon2,
            .recursive_parent_secure,
            => true,
            else => false,
        };
    }
};

fn initExact(
    kind: KindV1,
    hash_suite: HashSuiteV1,
    recursive_ingress: RecursiveIngressV1,
    proof_present: bool,
    interaction_pow_bits: u32,
    pcs_pow_bits: u32,
    fri_log_blowup_factor: u32,
    fri_query_count: u32,
    fri_fold_step: u32,
    fri_log_last_layer_degree_bound: u32,
    conjectured_security_bits: u32,
) ProofSecurityV1 {
    var result = ProofSecurityV1{
        .kind = kind,
        .hash_suite = hash_suite,
        .recursive_ingress = recursive_ingress,
        .proof_present = proof_present,
        .field_id = M31_FIELD_ID,
        .interaction_pow_bits = interaction_pow_bits,
        .pcs_pow_bits = pcs_pow_bits,
        .fri_log_blowup_factor = fri_log_blowup_factor,
        .fri_query_count = fri_query_count,
        .fri_fold_step = fri_fold_step,
        .fri_log_last_layer_degree_bound = fri_log_last_layer_degree_bound,
        .pcs_lifting_mode = 0,
        .configured_pcs_bits = pcs_pow_bits +
            fri_log_blowup_factor * fri_query_count,
        .conjectured_security_bits = conjectured_security_bits,
        .identity = undefined,
    };
    result.identity = authorityIdentity(&result);
    return result;
}

fn expectedForKind(kind: KindV1) ProofSecurityV1 {
    return switch (kind) {
        .proofless_empty => .prooflessEmpty(),
        .segment_v2_poseidon2 => .segmentV2Poseidon2(),
        .ethereum_segment_v3_blake2s => .ethereumSegmentV3Blake2s(),
        .ethereum_segment_v3_poseidon2 => .ethereumSegmentV3Poseidon2(),
        .recursive_parent_functional => .recursiveParentFunctional(),
        .recursive_parent_secure => .recursiveParentSecure(),
    };
}

fn fieldsEqual(left: *const ProofSecurityV1, right: *const ProofSecurityV1) bool {
    return left.format_version == right.format_version and
        left.schema_version == right.schema_version and left.kind == right.kind and
        left.hash_suite == right.hash_suite and
        left.recursive_ingress == right.recursive_ingress and
        left.proof_present == right.proof_present and
        std.meta.eql(left.padding, right.padding) and
        left.field_id == right.field_id and
        left.interaction_pow_bits == right.interaction_pow_bits and
        left.pcs_pow_bits == right.pcs_pow_bits and
        left.fri_log_blowup_factor == right.fri_log_blowup_factor and
        left.fri_query_count == right.fri_query_count and
        left.fri_fold_step == right.fri_fold_step and
        left.fri_log_last_layer_degree_bound ==
            right.fri_log_last_layer_degree_bound and
        left.pcs_lifting_mode == right.pcs_lifting_mode and
        left.configured_pcs_bits == right.configured_pcs_bits and
        left.conjectured_security_bits == right.conjectured_security_bits;
}

fn authorityIdentity(value: *const ProofSecurityV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(AUTHORITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromEnum(value.kind));
    hashInt(&hash, u8, @intFromEnum(value.hash_suite));
    hashInt(&hash, u8, @intFromEnum(value.recursive_ingress));
    hashInt(&hash, u8, @intFromBool(value.proof_present));
    hashInt(&hash, u32, value.field_id);
    hashInt(&hash, u32, value.interaction_pow_bits);
    hashInt(&hash, u32, value.pcs_pow_bits);
    hashInt(&hash, u32, value.fri_log_blowup_factor);
    hashInt(&hash, u32, value.fri_query_count);
    hashInt(&hash, u32, value.fri_fold_step);
    hashInt(&hash, u32, value.fri_log_last_layer_degree_bound);
    hashInt(&hash, u32, value.pcs_lifting_mode);
    hashInt(&hash, u32, value.configured_pcs_bits);
    hashInt(&hash, u32, value.conjectured_security_bits);
    return hash.finalResult();
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 1 or SCHEMA_VERSION != 1)
        @compileError("temporal proof-security contract drifted");
}
