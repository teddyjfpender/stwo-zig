//! Universal-36 physical manifest for the full Ethereum incremental V4 leaf.
//!
//! This contract fixes the common physical roster and column layout, but it
//! deliberately does not accept caller-authored log sizes as proof authority.
//! The real-leaf cohort must derive `LogSizesV4` from its live, verifier-owned
//! row materializers before calling this module.  Registry padding is applied
//! only after all three cold wrapper geometries exist.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const field_public =
    @import("recursive_common_ethereum_incremental_leaf_field_public_v4_schema3.zig");
const campaign_geometry =
    @import("recursive_common_ethereum_incremental_leaf_campaign_provider_geometry_v4.zig");
const complete_provider =
    @import("recursive_common_ethereum_incremental_leaf_complete_provider_geometry_v4.zig");
const public_semantics =
    @import("recursive_common_ethereum_incremental_leaf_public_semantics_v4.zig");
const role_io =
    @import("recursive_common_ethereum_incremental_leaf_role_aware_io_v4.zig");
const node_public = @import("recursive_field_node_public_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

const recursion = frontend.recursion;
const air = recursion.air;
const channel = recursion.poseidon2_channel;
const base = air.universal_adapter_manifest;
const universal_manifest = air.universal_manifest;
const roster = air.universal_roster;
const range_bridge = air.range_check_8_8_bridge;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const ROLE = registry_mod.CircuitRoleV4
    .ethereum_incremental_leaf_wrapper_v4;
pub const COMPONENT_COUNT: usize = roster.COMPONENT_COUNT;
pub const MINIMUM_PROVIDER_LOG_SIZE: u32 =
    field_public.MINIMUM_PROVIDER_LOG_SIZE;
pub const RANGE_LOG_SIZE: u32 = range_bridge.LOG_SIZE;
pub const MINIMUM_PROVIDER_ACTIVE_ROW_COUNT: u32 =
    field_public.MINIMUM_PROVIDER_ACTIVE_ROW_COUNT;
pub const PREPROCESSED_COLUMN_COUNT: u32 = 570;
pub const MAIN_COLUMN_COUNT: u32 = 1044;
pub const INTERACTION_COLUMN_COUNT: u32 = 560;
pub const CONSTRAINT_COUNT: u32 = 1312;

pub const PRODUCTION_ACTIVATION = false;
pub const CALLER_AUTHORED_LOG_SIZES_ADMITTED = false;
pub const REGISTRY_PADDING_AVAILABLE = false;
pub const CAMPAIGN_PROVIDER_GEOMETRY_FROZEN = false;
pub const UNFROZEN_GEOMETRY_ONLY_BUILD_AVAILABLE = true;
pub const PRODUCTION_IDENTITIES_REQUIRE_COMPLETE_PROVIDER = true;

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
pub const LogSizesV4 = universal_manifest.LogSizes;
pub const LiveProviderGeometryV4 = field_public.LiveProviderGeometryV4;
pub const CampaignProviderGeometryAuthorityV4 =
    campaign_geometry.OwnedCampaignProviderGeometryV4;
pub const CompleteProviderGeometryV4 =
    complete_provider.CompleteProviderGeometryV4;
pub const ConformanceCampaignProviderGeometryAuthorityV4 =
    campaign_geometry.CampaignProviderGeometryAuthorityV4;
pub const COMPONENT_KEYS = std.enums.values(ComponentKey);

pub const Error = base.Error || universal_manifest.Error ||
    field_public.Error || campaign_geometry.Error || complete_provider.Error || error{
    EthereumIncrementalUniversalManifestMismatchV4,
};

const CONTRACT_DOMAIN =
    "stwo-zig/common-ethereum-incremental-universal-contract/v4\x00";
const PROGRAM_DOMAIN =
    "stwo-zig/common-ethereum-incremental-universal-program/v4\x00";
const PROFILE_DOMAIN =
    "stwo-zig/common-ethereum-incremental-universal-profile/v4\x00";
const PADDING_DOMAIN =
    "stwo-zig/common-ethereum-incremental-universal-padding/v4\x00";
const TABLE_LAYOUT_DOMAIN =
    "stwo-zig/common-ethereum-incremental-universal-table-layout/v4\x00";
const VERIFICATION_KEY_DOMAIN: u32 = 0x4549_5652; // "EIVR"
const NEXT_PARENT_KEY_DOMAIN: u32 = 0x4549_4e52; // "EINR"
const AIR_PROGRAM_DOMAIN: u32 = 0x4549_4152; // "EIAR"

pub fn keyIndex(key: ComponentKey) u8 {
    return base.keyIndex(key);
}

/// Geometry-only builder.  A caller must not treat success as admission; the
/// future real cohort supplies only logs recomputed from its live sources.
pub fn buildForDerivedLogSizes(log_sizes: LogSizesV4) Error!Manifest {
    try validateDerivedLogSizes(log_sizes);
    const result = try universal_manifest.build(log_sizes);
    try validateExact(&result, log_sizes);
    return result;
}

/// Exact schema-3 builder for one live provider measurement. This remains an
/// audit-only result until one capacity is frozen from every authenticated
/// cold leaf in the runtime-count campaign.
pub fn buildForLiveProviderGeometry(
    log_sizes: LogSizesV4,
    provider: LiveProviderGeometryV4,
) Error!Manifest {
    try validateLiveProviderGeometry(log_sizes, provider);
    const result = try buildForDerivedLogSizes(log_sizes);
    try validateExactForLiveProvider(&result, log_sizes, provider);
    return result;
}

/// Publication-only audit seam.  It deliberately cannot mint any production
/// role-0 identity because row 34 also owns transcript and verifier-core calls.
pub fn buildForCampaignPublicationAudit(
    log_sizes: LogSizesV4,
    authority: *const CampaignProviderGeometryAuthorityV4,
) Error!Manifest {
    try authority.validateStructure();
    return buildForLiveProviderGeometry(
        log_sizes,
        authority.provider_geometry,
    );
}

/// Exact role-0 manifest builder.  The campaign authority fixes the shared
/// publication capacity; `complete` must come from the live native owner and
/// binds the transcript + publication + verifier-core call inventory.
pub fn buildForCampaignAuthority(
    log_sizes: LogSizesV4,
    authority: *const CampaignProviderGeometryAuthorityV4,
    complete: CompleteProviderGeometryV4,
) Error!Manifest {
    try validateCampaignAndCompleteProvider(
        log_sizes,
        authority,
        complete,
    );
    const result = try buildForDerivedLogSizes(log_sizes);
    try validateExactForCampaignAuthority(
        &result,
        log_sizes,
        authority,
        complete,
    );
    return result;
}

pub fn validateDerivedLogSizes(log_sizes: LogSizesV4) Error!void {
    for (log_sizes) |log_size| if (log_size < 4 or log_size >= 31)
        return error.EthereumIncrementalUniversalManifestMismatchV4;
    if (log_sizes[@intFromEnum(ComponentKey.poseidon2)] <
        MINIMUM_PROVIDER_LOG_SIZE or
        log_sizes[@intFromEnum(ComponentKey.range_check_8_8)] !=
            RANGE_LOG_SIZE)
    {
        return error.EthereumIncrementalUniversalManifestMismatchV4;
    }
}

pub fn validateExact(
    value: *const Manifest,
    log_sizes: LogSizesV4,
) Error!void {
    try validateDerivedLogSizes(log_sizes);
    try value.validate();
    const expected = try universal_manifest.build(log_sizes);
    if (!std.meta.eql(value.*, expected) or
        value.roster_count != COMPONENT_COUNT or
        value.total_preprocessed_columns != PREPROCESSED_COLUMN_COUNT or
        value.total_main_columns != MAIN_COLUMN_COUNT or
        value.total_interaction_columns != INTERACTION_COLUMN_COUNT or
        value.total_constraints != CONSTRAINT_COUNT)
    {
        return error.EthereumIncrementalUniversalManifestMismatchV4;
    }
    inline for (COMPONENT_KEYS, 0..) |key, ordinal| {
        const placement = try value.placement(key);
        if (placement.geometry.roster_row != ordinal or
            placement.geometry.log_size != log_sizes[ordinal])
        {
            return error.EthereumIncrementalUniversalManifestMismatchV4;
        }
    }
}

pub fn validateExactForLiveProvider(
    value: *const Manifest,
    log_sizes: LogSizesV4,
    provider: LiveProviderGeometryV4,
) Error!void {
    try validateLiveProviderGeometry(log_sizes, provider);
    try validateExact(value, log_sizes);
}

fn validateLiveProviderGeometry(
    log_sizes: LogSizesV4,
    provider: LiveProviderGeometryV4,
) Error!void {
    try provider.validate();
    try validateDerivedLogSizes(log_sizes);
    if (log_sizes[@intFromEnum(ComponentKey.poseidon2)] !=
        provider.provider_log_size)
    {
        return error.EthereumIncrementalUniversalManifestMismatchV4;
    }
}

pub fn validateExactForCampaignAuthority(
    value: *const Manifest,
    log_sizes: LogSizesV4,
    authority: *const CampaignProviderGeometryAuthorityV4,
    complete: CompleteProviderGeometryV4,
) Error!void {
    try validateCampaignAndCompleteProvider(log_sizes, authority, complete);
    try validateExact(value, log_sizes);
}

fn validateCampaignAndCompleteProvider(
    log_sizes: LogSizesV4,
    authority: *const CampaignProviderGeometryAuthorityV4,
    complete: CompleteProviderGeometryV4,
) Error!void {
    try authority.validateStructure();
    try complete.validate();
    const publication = authority.provider_geometry;
    try publication.validate();
    try validateDerivedLogSizes(log_sizes);
    if (complete.field_publication_call_count !=
        publication.provider_active_row_count or
        complete.provider_log_size < publication.provider_log_size or
        log_sizes[@intFromEnum(ComponentKey.poseidon2)] !=
            complete.provider_log_size)
    {
        return error.EthereumIncrementalUniversalManifestMismatchV4;
    }
}

/// Transport/circuit identities only.  No SHA value returned here can mint a
/// fresh proof capability or replace the live log-size derivation.
pub fn contractIdentity(
    log_sizes: LogSizesV4,
    authority: *const CampaignProviderGeometryAuthorityV4,
    complete: CompleteProviderGeometryV4,
) Error![32]u8 {
    try authority.validateStructure();
    try complete.validate();
    const provider = authority.provider_geometry;
    const manifest = try buildForCampaignAuthority(
        log_sizes,
        authority,
        complete,
    );
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CONTRACT_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hashInt(&hash, u8, @intFromEnum(ROLE));
    hashInt(&hash, u32, field_public.SOURCE_DIGEST_DOMAIN);
    hashInt(&hash, u32, provider.role_io_tuple_capacity);
    hashInt(&hash, u32, provider.role_io_word_count);
    hashInt(&hash, u32, provider.role_io_call_count);
    hashInt(&hash, u32, provider.fixed_call_count);
    hashInt(&hash, u32, provider.provider_active_row_count);
    hashInt(&hash, u32, provider.provider_log_size);
    hashInt(&hash, u32, provider.provider_row_capacity);
    hash.update(&authority.geometry_identity_sha256);
    hashInt(&hash, u32, complete.stage101_transcript_call_count);
    hashInt(&hash, u32, complete.child_claim_hash_call_count);
    hashInt(&hash, u32, complete.child_io_hash_call_count);
    hashInt(&hash, u32, complete.field_publication_call_count);
    hashInt(&hash, u32, complete.verifier_core_call_count);
    hashInt(&hash, u32, complete.total_call_count);
    hashInt(&hash, u32, complete.provider_log_size);
    hash.update(&complete.schedule_identity_sha256);
    hash.update(&complete.call_buffer_identity_sha256);
    hash.update(&complete.identity_sha256);
    hashInt(&hash, u32, PREPROCESSED_COLUMN_COUNT);
    hashInt(&hash, u32, MAIN_COLUMN_COUNT);
    hashInt(&hash, u32, INTERACTION_COLUMN_COUNT);
    hashInt(&hash, u32, CONSTRAINT_COUNT);
    for (log_sizes) |log_size| hashInt(&hash, u32, log_size);
    hash.update(&manifest.seal);
    hash.update(&node_public.abiIdentitySha256());
    hash.update(&public_semantics.programIdentity());
    hash.update(&role_io.programIdentity());
    hash.update(&air.universal_challenges.registryOrderDigest());
    return hash.finalResult();
}

pub fn programIdentity(
    log_sizes: LogSizesV4,
    authority: *const CampaignProviderGeometryAuthorityV4,
    complete: CompleteProviderGeometryV4,
) Error![32]u8 {
    return domainIdentity(PROGRAM_DOMAIN, log_sizes, authority, complete);
}

pub fn profileIdentity(
    log_sizes: LogSizesV4,
    authority: *const CampaignProviderGeometryAuthorityV4,
    complete: CompleteProviderGeometryV4,
) Error![32]u8 {
    return domainIdentity(PROFILE_DOMAIN, log_sizes, authority, complete);
}

pub fn paddingLayoutIdentity(
    log_sizes: LogSizesV4,
    authority: *const CampaignProviderGeometryAuthorityV4,
    complete: CompleteProviderGeometryV4,
) Error![32]u8 {
    return domainIdentity(PADDING_DOMAIN, log_sizes, authority, complete);
}

pub fn tableLayoutIdentity(
    log_sizes: LogSizesV4,
    authority: *const CampaignProviderGeometryAuthorityV4,
    complete: CompleteProviderGeometryV4,
) Error![32]u8 {
    return domainIdentity(TABLE_LAYOUT_DOMAIN, log_sizes, authority, complete);
}

pub fn verificationKeyId(
    log_sizes: LogSizesV4,
    authority: *const CampaignProviderGeometryAuthorityV4,
    complete: CompleteProviderGeometryV4,
) Error!channel.Digest {
    return channel.hashBytes(
        &try contractIdentity(log_sizes, authority, complete),
        VERIFICATION_KEY_DOMAIN,
    );
}

pub fn nextParentVkId(
    log_sizes: LogSizesV4,
    authority: *const CampaignProviderGeometryAuthorityV4,
    complete: CompleteProviderGeometryV4,
) Error!channel.Digest {
    return channel.hashBytes(
        &try profileIdentity(log_sizes, authority, complete),
        NEXT_PARENT_KEY_DOMAIN,
    );
}

pub fn airProgramId(
    log_sizes: LogSizesV4,
    authority: *const CampaignProviderGeometryAuthorityV4,
    complete: CompleteProviderGeometryV4,
) Error!channel.Digest {
    return channel.hashBytes(
        &try programIdentity(log_sizes, authority, complete),
        AIR_PROGRAM_DOMAIN,
    );
}

fn domainIdentity(
    domain: []const u8,
    log_sizes: LogSizesV4,
    authority: *const CampaignProviderGeometryAuthorityV4,
    complete: CompleteProviderGeometryV4,
) Error![32]u8 {
    const manifest = try buildForCampaignAuthority(
        log_sizes,
        authority,
        complete,
    );
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(domain);
    hash.update(&try contractIdentity(log_sizes, authority, complete));
    hash.update(&manifest.seal);
    return hash.finalResult();
}

/// Diagnostic identity for per-leaf/source tests before the campaign
/// authority exists. Production registry and proof code never consume it.
pub fn unfrozenContractIdentity(
    log_sizes: LogSizesV4,
    provider: LiveProviderGeometryV4,
) Error![32]u8 {
    const manifest = try buildForLiveProviderGeometry(log_sizes, provider);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/unfrozen-ethereum-incremental-manifest/v4-schema3\x00");
    hashInt(&hash, u32, provider.role_io_tuple_capacity);
    hashInt(&hash, u32, provider.provider_active_row_count);
    hashInt(&hash, u32, provider.provider_log_size);
    for (log_sizes) |log_size| hashInt(&hash, u32, log_size);
    hash.update(&manifest.seal);
    return hash.finalResult();
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or
        @intFromEnum(ROLE) != 0 or COMPONENT_COUNT != 36 or
        MINIMUM_PROVIDER_LOG_SIZE != 8 or RANGE_LOG_SIZE != 16 or
        MINIMUM_PROVIDER_ACTIVE_ROW_COUNT != 129 or
        PREPROCESSED_COLUMN_COUNT != 570 or MAIN_COLUMN_COUNT != 1044 or
        INTERACTION_COLUMN_COUNT != 560 or CONSTRAINT_COUNT != 1312 or
        PRODUCTION_ACTIVATION or CALLER_AUTHORED_LOG_SIZES_ADMITTED or
        REGISTRY_PADDING_AVAILABLE or CAMPAIGN_PROVIDER_GEOMETRY_FROZEN or
        !UNFROZEN_GEOMETRY_ONLY_BUILD_AVAILABLE or
        !PRODUCTION_IDENTITIES_REQUIRE_COMPLETE_PROVIDER)
    {
        @compileError("Ethereum incremental universal V4 manifest drifted");
    }
    for (COMPONENT_KEYS, 0..) |key, ordinal| {
        if (keyIndex(key) != @as(u8, @intCast(ordinal)))
            @compileError("Ethereum incremental universal roster drifted");
    }
}
