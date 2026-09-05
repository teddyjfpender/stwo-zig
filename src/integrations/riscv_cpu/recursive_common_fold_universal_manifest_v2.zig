//! Universal-36 geometry authority for the field-native common fold.
//!
//! The common fold is its own registered circuit.  It never borrows the
//! canonical-empty program identity and it never relabels a temporal parent.
//! Its padded log sizes are accepted only from the schema-4 registry parity
//! minted over all three independently cold-derived wrapper geometries.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const field_public = @import("recursive_common_fold_field_public_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

const air = frontend.recursion.air;
const channel = frontend.recursion.poseidon2_channel;
const base = air.universal_adapter_manifest;
const range_bridge = air.range_check_8_8_bridge;
const roster = air.universal_roster;
const universal_manifest = air.universal_manifest;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const COMPONENT_COUNT: usize = roster.COMPONENT_COUNT;
pub const COMMON_FOLD_ROLE =
    registry_mod.CircuitRoleV1.common_fold_field_v2;
pub const POSEIDON_ROW: usize = @intFromEnum(roster.Component.poseidon2);
pub const RANGE_ROW: usize = @intFromEnum(roster.Component.range_check_8_8);

pub const PRODUCTION_ACTIVATION = false;
pub const REQUIRES_THREE_COLD_GEOMETRIES = true;
pub const SERIALIZABLE_GEOMETRY_CAPABILITY = false;

const AUTHORITY_DOMAIN =
    "stwo-zig/recursive-common-fold-universal-authority/v2\x00";
const CONTRACT_DOMAIN =
    "stwo-zig/recursive-common-fold-universal-contract/v2\x00";
const PROGRAM_DOMAIN =
    "stwo-zig/recursive-common-fold-universal-program/v2\x00";
const PROFILE_DOMAIN =
    "stwo-zig/recursive-common-fold-universal-profile/v2\x00";
const PADDING_DOMAIN =
    "stwo-zig/recursive-common-fold-universal-padding/v2\x00";
const TABLE_LAYOUT_DOMAIN =
    "stwo-zig/recursive-common-fold-universal-table-layout/v2\x00";
const VERIFICATION_KEY_DOMAIN: u32 = 0x4346_5652; // "CFVR"
const NEXT_PARENT_KEY_DOMAIN: u32 = 0x4346_4e52; // "CFNR"
const AIR_PROGRAM_DOMAIN: u32 = 0x4346_4152; // "CFAR"

pub const Manifest = air.universal_adapter_manifest.Manifest;
pub const TREE_COUNT = base.TREE_COUNT;
pub const PREPROCESSED_TREE_INDEX = base.PREPROCESSED_TREE_INDEX;
pub const MAIN_TREE_INDEX = base.MAIN_TREE_INDEX;
pub const INTERACTION_TREE_INDEX = base.INTERACTION_TREE_INDEX;
pub const ComponentKey = base.ComponentKey;
pub const Geometry = base.Geometry;
pub const Placement = base.Placement;
pub const AdapterBinding = base.AdapterBinding;
pub const ClaimVector = base.ClaimVector;
pub const ProofGate = base.ProofGate;
pub const COMPONENT_KEYS = std.enums.values(ComponentKey);
pub const LogSizes = universal_manifest.LogSizes;
pub const Registry = registry_mod.RecursiveCircuitRegistryV1;
pub const AuthenticatedGeometry = registry_mod.AuthenticatedGeometryV1;
pub const PaddingParity = registry_mod.PaddingParityV1;

pub const Error = registry_mod.Error || universal_manifest.Error || error{
    CommonFoldGeometryAuthorityMismatch,
    CommonFoldManifestMismatch,
    CommonFoldPaddingUnavailable,
};

pub fn keyIndex(key: ComponentKey) u8 {
    return base.keyIndex(key);
}

pub fn validateExact(
    value: *const Manifest,
    authority: *const AuthorityV2,
) Error!void {
    try authority.validate();
    if (!std.meta.eql(value.*, authority.manifest_value))
        return error.CommonFoldManifestMismatch;
}

/// Non-admitting manifest builder used by the isolated q193 bootstrap.  The
/// row sizes must come from the authenticated fixed source; success does not
/// mint geometry, registry parity, or a production capability.
pub fn buildForDerivedLogSizes(log_sizes: LogSizes) Error!Manifest {
    try validateDerivedLogSizes(log_sizes);
    const result = try universal_manifest.build(log_sizes);
    try validateForDerivedLogSizes(&result, log_sizes);
    return result;
}

pub fn validateForDerivedLogSizes(
    manifest: *const Manifest,
    log_sizes: LogSizes,
) Error!void {
    try validateDerivedLogSizes(log_sizes);
    try manifest.validate();
    const expected = try universal_manifest.build(log_sizes);
    if (!std.meta.eql(manifest.*, expected) or
        manifest.roster_count != COMPONENT_COUNT)
    {
        return error.CommonFoldManifestMismatch;
    }
    for (std.enums.values(roster.Component), 0..) |component, ordinal| {
        const placement = try manifest.placement(component);
        if (placement.geometry.roster_row != ordinal or
            placement.geometry.log_size != log_sizes[ordinal])
        {
            return error.CommonFoldManifestMismatch;
        }
    }
}

pub fn contractIdentityForDerivedManifest(
    manifest: *const Manifest,
    log_sizes: LogSizes,
) Error![32]u8 {
    try validateForDerivedLogSizes(manifest, log_sizes);
    return domainIdentityForManifest(CONTRACT_DOMAIN, manifest, log_sizes);
}

pub fn programIdentityForDerivedManifest(
    manifest: *const Manifest,
    log_sizes: LogSizes,
) Error![32]u8 {
    try validateForDerivedLogSizes(manifest, log_sizes);
    return domainIdentityForManifest(PROGRAM_DOMAIN, manifest, log_sizes);
}

pub fn profileIdentityForDerivedManifest(
    manifest: *const Manifest,
    log_sizes: LogSizes,
) Error![32]u8 {
    try validateForDerivedLogSizes(manifest, log_sizes);
    return domainIdentityForManifest(PROFILE_DOMAIN, manifest, log_sizes);
}

pub fn paddingIdentityForDerivedManifest(
    manifest: *const Manifest,
    log_sizes: LogSizes,
) Error![32]u8 {
    try validateForDerivedLogSizes(manifest, log_sizes);
    return domainIdentityForManifest(PADDING_DOMAIN, manifest, log_sizes);
}

pub fn tableLayoutIdentityForDerivedManifest(
    manifest: *const Manifest,
    log_sizes: LogSizes,
) Error![32]u8 {
    try validateForDerivedLogSizes(manifest, log_sizes);
    return domainIdentityForManifest(TABLE_LAYOUT_DOMAIN, manifest, log_sizes);
}

pub fn verificationKeyIdForDerivedManifest(
    manifest: *const Manifest,
    log_sizes: LogSizes,
) Error!channel.Digest {
    return channel.hashBytes(
        &try contractIdentityForDerivedManifest(manifest, log_sizes),
        VERIFICATION_KEY_DOMAIN,
    );
}

pub fn nextParentVkIdForDerivedManifest(
    manifest: *const Manifest,
    log_sizes: LogSizes,
) Error!channel.Digest {
    return channel.hashBytes(
        &try profileIdentityForDerivedManifest(manifest, log_sizes),
        NEXT_PARENT_KEY_DOMAIN,
    );
}

pub fn airProgramIdForDerivedManifest(
    manifest: *const Manifest,
    log_sizes: LogSizes,
) Error!channel.Digest {
    return channel.hashBytes(
        &try programIdentityForDerivedManifest(manifest, log_sizes),
        AIR_PROGRAM_DOMAIN,
    );
}

/// Process-local geometry boundary.  The pointers must remain owned by the
/// three role-specific cold verifiers.  This value deliberately has no codec.
pub const AuthorityV2 = struct {
    registry: *const Registry,
    geometries: *const [registry_mod.ROLE_COUNT]AuthenticatedGeometry,
    parity: *const PaddingParity,
    manifest_value: Manifest,
    log_sizes: LogSizes,
    identity_sha256: [32]u8,

    pub fn init(
        registry: *const Registry,
        geometries: *const [registry_mod.ROLE_COUNT]AuthenticatedGeometry,
        parity: *const PaddingParity,
    ) Error!AuthorityV2 {
        try parity.validate(registry, geometries);
        const log_sizes = try exactLogSizes(parity);
        const manifest_value = try universal_manifest.build(log_sizes);
        try validateManifest(&manifest_value, log_sizes, parity);
        var result = AuthorityV2{
            .registry = registry,
            .geometries = geometries,
            .parity = parity,
            .manifest_value = manifest_value,
            .log_sizes = log_sizes,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = authorityIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const AuthorityV2) Error!void {
        try self.parity.validate(self.registry, self.geometries);
        const expected_logs = try exactLogSizes(self.parity);
        const expected_manifest = try universal_manifest.build(expected_logs);
        try validateManifest(
            &self.manifest_value,
            self.log_sizes,
            self.parity,
        );
        const common_geometry = self.commonFoldGeometry();
        if (!std.meta.eql(self.log_sizes, expected_logs) or
            !std.meta.eql(self.manifest_value, expected_manifest) or
            common_geometry.role != COMMON_FOLD_ROLE or
            !std.mem.eql(
                u8,
                &common_geometry.circuit_identity_sha256,
                &domainIdentityForManifest(
                    CONTRACT_DOMAIN,
                    &self.manifest_value,
                    self.log_sizes,
                ),
            ) or !std.mem.eql(
            u8,
            &common_geometry.program_identity_sha256,
            &domainIdentityForManifest(
                PROGRAM_DOMAIN,
                &self.manifest_value,
                self.log_sizes,
            ),
        ) or !std.mem.eql(
            u8,
            &common_geometry.profile_identity_sha256,
            &domainIdentityForManifest(
                PROFILE_DOMAIN,
                &self.manifest_value,
                self.log_sizes,
            ),
        ) or !std.mem.eql(
            u8,
            &common_geometry.padding_layout_identity_sha256,
            &domainIdentityForManifest(
                PADDING_DOMAIN,
                &self.manifest_value,
                self.log_sizes,
            ),
        ) or !std.mem.eql(
            u8,
            &common_geometry.proof_shape.table_layout_identity_sha256,
            &domainIdentityForManifest(
                TABLE_LAYOUT_DOMAIN,
                &self.manifest_value,
                self.log_sizes,
            ),
        ) or !std.mem.eql(
            u8,
            common_geometry.padded_component_log_sizes[0..COMPONENT_COUNT],
            self.parity.target_component_log_sizes[0..COMPONENT_COUNT],
        ) or
            !std.mem.eql(
                u8,
                &self.identity_sha256,
                &authorityIdentity(self),
            )) return error.CommonFoldGeometryAuthorityMismatch;
    }

    pub fn manifest(self: *const AuthorityV2) *const Manifest {
        return &self.manifest_value;
    }

    pub fn commonFoldGeometry(
        self: *const AuthorityV2,
    ) *const AuthenticatedGeometry {
        return &self.geometries[@intFromEnum(COMMON_FOLD_ROLE)];
    }

    pub fn contractIdentity(self: *const AuthorityV2) Error![32]u8 {
        try self.validate();
        return domainIdentityForManifest(
            CONTRACT_DOMAIN,
            &self.manifest_value,
            self.log_sizes,
        );
    }

    pub fn programIdentity(self: *const AuthorityV2) Error![32]u8 {
        try self.validate();
        return domainIdentityForManifest(
            PROGRAM_DOMAIN,
            &self.manifest_value,
            self.log_sizes,
        );
    }

    pub fn profileIdentity(self: *const AuthorityV2) Error![32]u8 {
        try self.validate();
        return domainIdentityForManifest(
            PROFILE_DOMAIN,
            &self.manifest_value,
            self.log_sizes,
        );
    }

    pub fn paddingLayoutIdentity(self: *const AuthorityV2) Error![32]u8 {
        try self.validate();
        return domainIdentityForManifest(
            PADDING_DOMAIN,
            &self.manifest_value,
            self.log_sizes,
        );
    }

    pub fn tableLayoutIdentity(self: *const AuthorityV2) Error![32]u8 {
        try self.validate();
        return domainIdentityForManifest(
            TABLE_LAYOUT_DOMAIN,
            &self.manifest_value,
            self.log_sizes,
        );
    }

    pub fn verificationKeyId(self: *const AuthorityV2) Error!channel.Digest {
        return channel.hashBytes(
            &try self.contractIdentity(),
            VERIFICATION_KEY_DOMAIN,
        );
    }

    pub fn nextParentVkId(self: *const AuthorityV2) Error!channel.Digest {
        return channel.hashBytes(
            &try self.profileIdentity(),
            NEXT_PARENT_KEY_DOMAIN,
        );
    }

    pub fn airProgramId(self: *const AuthorityV2) Error!channel.Digest {
        return channel.hashBytes(
            &try self.programIdentity(),
            AIR_PROGRAM_DOMAIN,
        );
    }
};

fn exactLogSizes(parity: *const PaddingParity) Error!LogSizes {
    if (parity.component_count != COMPONENT_COUNT)
        return error.CommonFoldPaddingUnavailable;
    var result: LogSizes = undefined;
    for (&result, parity.target_component_log_sizes[0..COMPONENT_COUNT]) |
        *destination,
        log_size,
    | {
        if (log_size == 0) return error.CommonFoldPaddingUnavailable;
        destination.* = log_size;
    }
    if (result[POSEIDON_ROW] < field_public.MINIMUM_POSEIDON_LOG_SIZE or
        result[RANGE_ROW] != range_bridge.LOG_SIZE)
    {
        return error.CommonFoldPaddingUnavailable;
    }
    return result;
}

fn validateDerivedLogSizes(log_sizes: LogSizes) Error!void {
    for (log_sizes) |log_size| if (log_size < 4 or log_size >= 31)
        return error.CommonFoldPaddingUnavailable;
    if (log_sizes[POSEIDON_ROW] < field_public.MINIMUM_POSEIDON_LOG_SIZE or
        log_sizes[RANGE_ROW] != range_bridge.LOG_SIZE)
    {
        return error.CommonFoldPaddingUnavailable;
    }
}

fn validateManifest(
    manifest: *const Manifest,
    log_sizes: LogSizes,
    parity: *const PaddingParity,
) Error!void {
    try manifest.validate();
    const expected = try universal_manifest.build(log_sizes);
    if (!std.meta.eql(manifest.*, expected) or
        manifest.roster_count != COMPONENT_COUNT or
        manifest.total_preprocessed_columns !=
            @as(u32, parity.preprocessed_column_count))
    {
        return error.CommonFoldManifestMismatch;
    }
    for (std.enums.values(roster.Component), 0..) |component, ordinal| {
        const placement = try manifest.placement(component);
        if (placement.geometry.roster_row != ordinal or
            placement.geometry.log_size != log_sizes[ordinal])
        {
            return error.CommonFoldManifestMismatch;
        }
    }
}

fn authorityIdentity(value: *const AuthorityV2) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(AUTHORITY_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hashInt(&hash, u8, @intFromEnum(COMMON_FOLD_ROLE));
    hashInt(&hash, u32, field_public.POSEIDON_CALL_COUNT);
    hash.update(&value.registry.identity_sha256);
    hash.update(&value.parity.identity_sha256);
    for (value.geometries) |geometry|
        hash.update(&geometry.authority_identity_sha256);
    for (value.log_sizes) |log_size| hashInt(&hash, u32, log_size);
    hash.update(&value.manifest_value.seal);
    return hash.finalResult();
}

fn domainIdentityForManifest(
    domain: []const u8,
    manifest: *const Manifest,
    log_sizes: LogSizes,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(domain);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hashInt(&hash, u8, @intFromEnum(COMMON_FOLD_ROLE));
    hashInt(&hash, u32, COMPONENT_COUNT);
    for (log_sizes) |log_size| hashInt(&hash, u32, log_size);
    hash.update(&manifest.seal);
    hashInt(&hash, u32, field_public.POSEIDON_CALL_COUNT);
    return hash.finalResult();
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        COMPONENT_COUNT != 36 or POSEIDON_ROW != 34 or RANGE_ROW != 35 or
        field_public.POSEIDON_CALL_COUNT != 116 or PRODUCTION_ACTIVATION or
        !REQUIRES_THREE_COLD_GEOMETRIES or SERIALIZABLE_GEOMETRY_CAPABILITY)
    {
        @compileError("common-fold universal manifest contract drifted");
    }
}
