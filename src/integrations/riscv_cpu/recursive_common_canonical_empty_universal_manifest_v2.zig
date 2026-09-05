//! Universal-36 manifest for the field-native canonical-empty wrapper.
//!
//! The logical verifier roster remains the frozen universal catalog.  Its
//! rows are inactive for a canonical empty leaf.  The one semantic witness is
//! the existing native Poseidon2 provider over the exact 113-call public
//! schedule; its public request boundary is reconstructed by the cold
//! verifier.  This contract changes only component log sizes and transcript
//! policy, never a component width or equation.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const field_public =
    @import("recursive_common_canonical_empty_field_public_v2.zig");
const node_public = @import("recursive_field_node_public_v2.zig");

const recursion = frontend.recursion;
const air = recursion.air;
const channel = recursion.poseidon2_channel;
const base = air.universal_adapter_manifest;
const universal_manifest = air.universal_manifest;
const roster = air.universal_roster;
const range_bridge = air.range_check_8_8_bridge;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const COMPONENT_COUNT: usize = roster.COMPONENT_COUNT;
pub const LOGICAL_LOG_SIZE: u32 = 4;
pub const POSEIDON_LOG_SIZE: u32 =
    field_public.MINIMUM_POSEIDON_LOG_SIZE;
pub const RANGE_LOG_SIZE: u32 = range_bridge.LOG_SIZE;
pub const PROVIDER_ACTIVE_ROW_COUNT: u32 = field_public.POSEIDON_CALL_COUNT;
pub const PREPROCESSED_COLUMN_COUNT: u32 = 570;
pub const MAIN_COLUMN_COUNT: u32 = 1044;
pub const INTERACTION_COLUMN_COUNT: u32 = 560;
pub const CONSTRAINT_COUNT: u32 = 1312;

pub const TREE_COUNT = base.TREE_COUNT;
pub const PREPROCESSED_TREE_INDEX = base.PREPROCESSED_TREE_INDEX;
pub const MAIN_TREE_INDEX = base.MAIN_TREE_INDEX;
pub const INTERACTION_TREE_INDEX = base.INTERACTION_TREE_INDEX;
pub const ComponentKey = base.ComponentKey;
pub const Geometry = base.Geometry;
pub const Placement = base.Placement;
pub const AdapterBinding = base.AdapterBinding;
pub const Manifest = base.Manifest;
pub const ClaimVector = base.ClaimVector;
pub const ProofGate = base.ProofGate;
pub const COMPONENT_KEYS = std.enums.values(ComponentKey);

pub const Error = base.Error || universal_manifest.Error || error{
    CanonicalEmptyUniversalManifestMismatch,
};

const CONTRACT_DOMAIN =
    "stwo-zig/common-canonical-empty-universal-contract/v2\x00";
const PROGRAM_DOMAIN =
    "stwo-zig/common-canonical-empty-universal-program/v2\x00";
const PROFILE_DOMAIN =
    "stwo-zig/common-canonical-empty-universal-profile/v2\x00";
const PADDING_DOMAIN =
    "stwo-zig/common-canonical-empty-universal-padding/v2\x00";
const TABLE_LAYOUT_DOMAIN =
    "stwo-zig/common-canonical-empty-universal-table-layout/v2\x00";
const VERIFICATION_KEY_DOMAIN: u32 = 0x4345_5652; // "CEVR"
const NEXT_PARENT_KEY_DOMAIN: u32 = 0x4345_4e52; // "CENR"
const AIR_PROGRAM_DOMAIN: u32 = 0x4345_4152; // "CEAR"

pub fn keyIndex(key: ComponentKey) u8 {
    return base.keyIndex(key);
}

pub fn exactLogSizes() universal_manifest.LogSizes {
    var result = [_]u32{LOGICAL_LOG_SIZE} ** COMPONENT_COUNT;
    result[@intFromEnum(ComponentKey.poseidon2)] = POSEIDON_LOG_SIZE;
    result[@intFromEnum(ComponentKey.range_check_8_8)] = RANGE_LOG_SIZE;
    return result;
}

pub fn build() Error!Manifest {
    const result = try universal_manifest.build(exactLogSizes());
    try validateExact(&result);
    return result;
}

pub fn validateExact(value: *const Manifest) Error!void {
    try value.validate();
    const expected = try universal_manifest.build(exactLogSizes());
    if (!std.meta.eql(value.*, expected) or
        value.roster_count != COMPONENT_COUNT or
        value.total_preprocessed_columns != PREPROCESSED_COLUMN_COUNT or
        value.total_main_columns != MAIN_COLUMN_COUNT or
        value.total_interaction_columns != INTERACTION_COLUMN_COUNT or
        value.total_constraints != CONSTRAINT_COUNT)
    {
        return error.CanonicalEmptyUniversalManifestMismatch;
    }
    inline for (COMPONENT_KEYS, 0..) |key, ordinal| {
        const placement = try value.placement(key);
        if (placement.geometry.roster_row != ordinal or
            placement.geometry.log_size != exactLogSizes()[ordinal])
        {
            return error.CanonicalEmptyUniversalManifestMismatch;
        }
    }
}

/// Transport/circuit identity. Recursive public semantics remain the four
/// field-native Poseidon digests in NodePublicV2, not this SHA receipt.
pub fn contractIdentity() Error![32]u8 {
    const manifest = try build();
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CONTRACT_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hashInt(&hash, u32, field_public.SOURCE_DIGEST_DOMAIN);
    hashInt(&hash, u32, field_public.POSEIDON_CALL_COUNT);
    hashInt(&hash, u32, PREPROCESSED_COLUMN_COUNT);
    hashInt(&hash, u32, MAIN_COLUMN_COUNT);
    hashInt(&hash, u32, INTERACTION_COLUMN_COUNT);
    hashInt(&hash, u32, CONSTRAINT_COUNT);
    for (exactLogSizes()) |log_size| hashInt(&hash, u32, log_size);
    hash.update(&manifest.seal);
    hash.update(&node_public.abiIdentitySha256());
    hash.update(&air.universal_challenges.registryOrderDigest());
    return hash.finalResult();
}

pub fn programIdentity() Error![32]u8 {
    return domainIdentity(PROGRAM_DOMAIN);
}

pub fn profileIdentity() Error![32]u8 {
    return domainIdentity(PROFILE_DOMAIN);
}

pub fn paddingLayoutIdentity() Error![32]u8 {
    return domainIdentity(PADDING_DOMAIN);
}

/// Exact ordered tree-layout identity supplied to FixedProofShapeV3 after a
/// successful cold verification. It is not accepted in place of the capture.
pub fn tableLayoutIdentity() Error![32]u8 {
    return domainIdentity(TABLE_LAYOUT_DOMAIN);
}

pub fn verificationKeyId() Error!channel.Digest {
    return channel.hashBytes(&try contractIdentity(), VERIFICATION_KEY_DOMAIN);
}

pub fn nextParentVkId() Error!channel.Digest {
    return channel.hashBytes(&try profileIdentity(), NEXT_PARENT_KEY_DOMAIN);
}

pub fn airProgramId() Error!channel.Digest {
    return channel.hashBytes(&try programIdentity(), AIR_PROGRAM_DOMAIN);
}

fn domainIdentity(domain: []const u8) Error![32]u8 {
    const manifest = try build();
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(domain);
    hash.update(&try contractIdentity());
    hash.update(&manifest.seal);
    return hash.finalResult();
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        COMPONENT_COUNT != 36 or LOGICAL_LOG_SIZE != 4 or
        POSEIDON_LOG_SIZE != 7 or RANGE_LOG_SIZE != 16 or
        PROVIDER_ACTIVE_ROW_COUNT != 113 or
        PREPROCESSED_COLUMN_COUNT != 570 or MAIN_COLUMN_COUNT != 1044 or
        INTERACTION_COLUMN_COUNT != 560 or CONSTRAINT_COUNT != 1312 or
        PRODUCTION_ACTIVATION)
    {
        @compileError("canonical-empty universal V2 manifest drifted");
    }
    for (COMPONENT_KEYS, 0..) |key, ordinal| {
        if (keyIndex(key) != @as(u8, @intCast(ordinal)))
            @compileError("canonical-empty universal roster order drifted");
    }
}
