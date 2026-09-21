//! Excluded diagnostic 36-placement manifest for the canonical-empty wrapper.
//!
//! Every physical placement uses the already-reviewed statement-input AIR.
//! Placement zero publishes the fixed NodePublic byte projection; the other
//! placements are constrained inactive padding. This 252-preprocessed-column
//! shape is not the 570-column universal common-fold geometry and therefore
//! cannot be proved or registry-admitted as a durable wrapper child.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const input_mod =
    @import("recursive_common_canonical_empty_wrapper_input_v1.zig");
const artifact_mod = @import("recursive_node_artifact_v1.zig");

const recursion = frontend.recursion;
const air = recursion.air;
const channel = recursion.poseidon2_channel;
const base = air.universal_adapter_manifest;
const roster = air.universal_roster;
const typed_component = air.universal_typed_component;
const statement_air = air.statement_input;
const statement_relation = air.statement_input_relation;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const DIAGNOSTIC_ONLY = true;
pub const COMMON_GEOMETRY_COMPATIBLE = false;
pub const COMPONENT_COUNT: usize = roster.COMPONENT_COUNT;
pub const NODE_PUBLIC_COMPONENT: usize = 0;
pub const LOG_SIZE: u32 = 11;
pub const TRACE_SIZE: usize = 1 << LOG_SIZE;
pub const NODE_PUBLIC_SCOPE: u32 = 0x4345_5731; // "CEW1"
pub const NODE_PUBLIC_BYTE_COUNT = input_mod.NODE_PUBLIC_SCALAR_BYTE_COUNT;
pub const DIAGNOSTIC_PREPROCESSED_COLUMN_COUNT: u32 =
    @as(u32, @intCast(COMPONENT_COUNT)) *
    @as(u32, @intCast(statement_air.PREPROCESSED_COLUMN_COUNT));
pub const DIAGNOSTIC_MAIN_COLUMN_COUNT: u32 =
    @as(u32, @intCast(COMPONENT_COUNT)) *
    @as(u32, @intCast(statement_air.PHYSICAL_MAIN_COLUMN_COUNT));
pub const DIAGNOSTIC_INTERACTION_COLUMN_COUNT: u32 =
    @as(u32, @intCast(COMPONENT_COUNT)) *
    @as(u32, @intCast(statement_air.INTERACTION_COLUMN_COUNT));
pub const UNIVERSAL_COMMON_PREPROCESSED_COLUMN_COUNT: u32 = 570;
pub const UNIVERSAL_COMMON_MAIN_COLUMN_COUNT: u32 = 1044;
pub const UNIVERSAL_COMMON_INTERACTION_COLUMN_COUNT: u32 = 560;

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

pub const StatementAdapter = typed_component.Component(
    statement_air,
    statement_relation,
);

pub const Error = base.Error || error{
    CanonicalEmptyWrapperManifestMismatch,
};

const CONTRACT_DOMAIN =
    "stwo-zig/common-canonical-empty-wrapper-contract/v1\x00";
const PROGRAM_DOMAIN =
    "stwo-zig/common-canonical-empty-wrapper-program/v1\x00";
const PROFILE_DOMAIN =
    "stwo-zig/common-canonical-empty-wrapper-profile/v1\x00";
const PADDING_DOMAIN =
    "stwo-zig/common-canonical-empty-wrapper-padding/v1\x00";
const VERIFICATION_KEY_DOMAIN: u32 = 0x4345_5651; // "CEVQ"
const NEXT_PARENT_KEY_DOMAIN: u32 = 0x4345_4e51; // "CENQ"
const AIR_PROGRAM_DOMAIN: u32 = 0x4345_4151; // "CEAQ"

pub fn keyIndex(key: ComponentKey) u8 {
    return base.keyIndex(key);
}

pub fn build() Error!Manifest {
    var builder = base.Builder{};
    inline for (COMPONENT_KEYS) |key| {
        _ = try builder.append(StatementAdapter.manifestGeometry(
            key,
            LOG_SIZE,
        ));
    }
    const result = try builder.seal();
    try validateExact(&result);
    if (result.total_preprocessed_columns !=
        DIAGNOSTIC_PREPROCESSED_COLUMN_COUNT or
        result.total_main_columns != DIAGNOSTIC_MAIN_COLUMN_COUNT or
        result.total_interaction_columns !=
            DIAGNOSTIC_INTERACTION_COLUMN_COUNT)
    {
        return error.CanonicalEmptyWrapperManifestMismatch;
    }
    return result;
}

/// Base-manifest validation alone does not authenticate which typed AIR owns
/// each physical ordinal.  Every wrapper entry point therefore calls this
/// stronger reconstruction check before using the manifest.
pub fn validateExact(value: *const Manifest) Error!void {
    try value.validate();
    if (value.roster_count != COMPONENT_COUNT)
        return error.CanonicalEmptyWrapperManifestMismatch;
    inline for (COMPONENT_KEYS) |key| {
        const actual = try value.placement(key);
        const expected = StatementAdapter.manifestGeometry(key, LOG_SIZE);
        if (!std.meta.eql(actual.geometry, expected))
            return error.CanonicalEmptyWrapperManifestMismatch;
    }
    var builder = base.Builder{};
    inline for (COMPONENT_KEYS) |key| {
        _ = try builder.append(StatementAdapter.manifestGeometry(
            key,
            LOG_SIZE,
        ));
    }
    const expected = try builder.seal();
    if (!std.meta.eql(value.*, expected))
        return error.CanonicalEmptyWrapperManifestMismatch;
}

pub fn contractIdentity() Error![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CONTRACT_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hashInt(&hash, u8, COMPONENT_COUNT);
    hashInt(&hash, u32, LOG_SIZE);
    hashInt(&hash, u32, NODE_PUBLIC_SCOPE);
    hashInt(&hash, u32, NODE_PUBLIC_BYTE_COUNT);
    hash.update(&statement_air.SEMANTIC_DIGEST);
    hash.update(&air.universal_challenges.registryOrderDigest());
    hash.update(&artifact_mod.nodePublicAbiIdentity());
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

pub fn verificationKeyId() Error!channel.Digest {
    const identity = try contractIdentity();
    return channel.hashBytes(&identity, VERIFICATION_KEY_DOMAIN);
}

pub fn nextParentVkId() Error!channel.Digest {
    const identity = try profileIdentity();
    return channel.hashBytes(&identity, NEXT_PARENT_KEY_DOMAIN);
}

pub fn airProgramId() Error!channel.Digest {
    const identity = try programIdentity();
    return channel.hashBytes(&identity, AIR_PROGRAM_DOMAIN);
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
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 1 or SCHEMA_VERSION != 1 or
        COMPONENT_COUNT != 36 or NODE_PUBLIC_COMPONENT != 0 or
        LOG_SIZE != 11 or TRACE_SIZE != 2048 or
        NODE_PUBLIC_BYTE_COUNT != 1816 or PRODUCTION_ACTIVATION or
        !DIAGNOSTIC_ONLY or COMMON_GEOMETRY_COMPATIBLE or
        DIAGNOSTIC_PREPROCESSED_COLUMN_COUNT != 252 or
        DIAGNOSTIC_MAIN_COLUMN_COUNT != 72 or
        DIAGNOSTIC_INTERACTION_COLUMN_COUNT != 288 or
        UNIVERSAL_COMMON_PREPROCESSED_COLUMN_COUNT != 570 or
        UNIVERSAL_COMMON_MAIN_COLUMN_COUNT != 1044 or
        UNIVERSAL_COMMON_INTERACTION_COLUMN_COUNT != 560)
    {
        @compileError("canonical-empty wrapper manifest drifted");
    }
    for (COMPONENT_KEYS, 0..) |key, ordinal| {
        if (keyIndex(key) != @as(u8, @intCast(ordinal)))
            @compileError("canonical-empty wrapper roster order drifted");
    }
}
