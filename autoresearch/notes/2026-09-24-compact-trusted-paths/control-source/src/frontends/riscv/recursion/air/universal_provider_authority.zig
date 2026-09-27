//! Retained Poseidon source authority and canonical receipt validation.
const std = @import("std");
const poseidon_identity = @import("../../air/lang/typed_poseidon2_identity_codec.zig");
const geometry = @import("universal_shared_geometry.zig");
pub const Error = poseidon_identity.IdentityError || error{ProviderAuthorityMismatch};

pub const STARK_V_REVISION: [40]u8 =
    "59172a201bd01f2f4b699bc2f7d4442d8ee81597".*;
pub const STARK_V_POSEIDON_PATH = "crates/air/src/poseidon2.rs";
pub const STARK_V_AIR_FNS_PATH = "crates/stwo-macros/src/air_fns.rs";
pub const STARK_V_POSEIDON_SHA256 = hexDigest(
    "d029f2ee6b3b63b6d7c992a208038b1d451d16e9bc8f0770f49aecc8b4b17b8a",
    "invalid pinned Stark-V poseidon2.rs digest",
);
pub const STARK_V_AIR_FNS_SHA256 = hexDigest(
    "cd3922d517bb96dcb660ed25e1bd58811109ab21721936f8e56b0a74fe582e79",
    "invalid pinned Stark-V air_fns.rs digest",
);
pub const POSEIDON_SOURCE_AUTHORITY_FORMAT_VERSION: u16 = 1;
pub const POSEIDON_SOURCE_AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/recursion-poseidon2-provider-source/v1\x00";
const POSEIDON_DIRECT_CONSTRAINT_COUNT = geometry.POSEIDON_DIRECT_CONSTRAINT_COUNT;
const POSEIDON_INTERACTION_BATCH_COUNT = geometry.POSEIDON_INTERACTION_BATCH_COUNT;
const POSEIDON_INTERACTION_COLUMN_COUNT = geometry.POSEIDON_INTERACTION_COLUMN_COUNT;
const POSEIDON_MAIN_COLUMN_COUNT = geometry.POSEIDON_MAIN_COLUMN_COUNT;
const POSEIDON_PREPROCESSED_COLUMN_COUNT = geometry.POSEIDON_PREPROCESSED_COLUMN_COUNT;
const POSEIDON_PROTOCOL_CONSTRAINT_DEGREE = geometry.POSEIDON_PROTOCOL_CONSTRAINT_DEGREE;
const POSEIDON_SOURCE_AUTHORITY_DIGEST = geometry.POSEIDON_SOURCE_AUTHORITY_DIGEST;

/// Exact source, compiler, typed-program, and physical-geometry receipt for
/// Stark-V's generated general-mode Poseidon2 component.  This is separate
/// from the program identity because a backend-neutral graph alone does not
/// prove which external DSL source or component shell was reviewed.
pub const PoseidonSourceAuthority = struct {
    format_version: u16,
    revision: [40]u8,
    poseidon_source_sha256: [32]u8,
    air_fns_source_sha256: [32]u8,
    program_identity_digest: [32]u8,
    preprocessed_columns: u16,
    main_columns: u16,
    interaction_columns: u16,
    direct_constraints: u16,
    interaction_batches: u16,
    maximum_constraint_degree: u8,

    pub fn pinned() PoseidonSourceAuthority {
        return .{
            .format_version = POSEIDON_SOURCE_AUTHORITY_FORMAT_VERSION,
            .revision = STARK_V_REVISION,
            .poseidon_source_sha256 = STARK_V_POSEIDON_SHA256,
            .air_fns_source_sha256 = STARK_V_AIR_FNS_SHA256,
            .program_identity_digest = poseidon_identity.CANONICAL_COMBINED_DIGEST,
            .preprocessed_columns = POSEIDON_PREPROCESSED_COLUMN_COUNT,
            .main_columns = POSEIDON_MAIN_COLUMN_COUNT,
            .interaction_columns = POSEIDON_INTERACTION_COLUMN_COUNT,
            .direct_constraints = POSEIDON_DIRECT_CONSTRAINT_COUNT,
            .interaction_batches = POSEIDON_INTERACTION_BATCH_COUNT,
            .maximum_constraint_degree = POSEIDON_PROTOCOL_CONSTRAINT_DEGREE,
        };
    }

    pub fn validate(self: PoseidonSourceAuthority) Error!void {
        if (!std.meta.eql(self, pinned()) or
            !std.mem.eql(u8, &self.identityDigest(), &POSEIDON_SOURCE_AUTHORITY_DIGEST))
        {
            return error.ProviderAuthorityMismatch;
        }
        const identity_value = poseidon_identity.ProgramIdentity.canonical();
        try identity_value.validate();
        if (!identity_value.isCanonical() or
            !std.mem.eql(
                u8,
                &identity_value.combined_digest,
                &self.program_identity_digest,
            ))
        {
            return error.ProviderAuthorityMismatch;
        }
    }

    pub fn identityDigest(self: PoseidonSourceAuthority) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(POSEIDON_SOURCE_AUTHORITY_DOMAIN);
        hashInt(&hash, u16, self.format_version);
        hash.update(&self.revision);
        hashBytes(&hash, STARK_V_POSEIDON_PATH);
        hash.update(&self.poseidon_source_sha256);
        hashBytes(&hash, STARK_V_AIR_FNS_PATH);
        hash.update(&self.air_fns_source_sha256);
        hash.update(&self.program_identity_digest);
        hashInt(&hash, u16, self.preprocessed_columns);
        hashInt(&hash, u16, self.main_columns);
        hashInt(&hash, u16, self.interaction_columns);
        hashInt(&hash, u16, self.direct_constraints);
        hashInt(&hash, u16, self.interaction_batches);
        hashInt(&hash, u8, self.maximum_constraint_degree);
        return hash.finalResult();
    }
};

fn hashBytes(hash: anytype, value: []const u8) void {
    hashInt(hash, u32, value.len);
    hash.update(value);
}

const hashInt = @import("universal_provider_relations.zig").hashInt;

fn hexDigest(
    comptime value: []const u8,
    comptime message: []const u8,
) [32]u8 {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
