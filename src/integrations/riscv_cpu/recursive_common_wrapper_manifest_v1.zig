//! Authenticated target manifest for the common recursive-wrapper geometry.
//!
//! Native V4 Ethereum leaf proofs remain inputs to the real-leaf wrapper and
//! are never relabeled as that wrapper. This target is about the two durable
//! leaf wrappers and the single common fold. A target can be derived only
//! from three opaque cold-wrapper geometry leases. No production mint for
//! those leases exists in this tranche.

const std = @import("std");
const builtin = @import("builtin");
const frontend = @import("stwo_riscv_frontend");

const artifact_mod = @import("recursive_node_artifact_v1.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

const roster = frontend.recursion.air.universal_roster;
const universal = frontend.recursion.air.universal_challenges;
const outer_statement = frontend.recursion.outer_parent_statement_air_source;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 2;
pub const PRODUCTION_ACTIVATION = false;
pub const PADDING_PARITY_AVAILABLE = false;
pub const CANDIDATE_TARGET_ONLY = true;
pub const REMINT_REQUIRED_ON_GEOMETRY_GROWTH = true;
pub const COMPONENT_COUNT: usize = roster.COMPONENT_COUNT;
pub const ROLE_COUNT: usize = registry_mod.ROLE_COUNT;
pub const MAX_COMPONENT_COUNT = registry_mod.MAX_COMPONENT_COUNT;
pub const MAX_PREPROCESSED_COLUMN_COUNT =
    registry_mod.MAX_PREPROCESSED_COLUMN_COUNT;

const TARGET_DOMAIN =
    "stwo-zig/recursive-common-wrapper-target/v2\x00";

pub const Error = registry_mod.Error || error{
    ColdWrapperAuthorityUnavailable,
    CommonWrapperTargetMismatch,
    InvalidCommonWrapperContract,
    InvalidCommonWrapperTarget,
    InvalidRoleOrder,
    PaddingTargetMismatch,
    SecurePcsRequired,
};

pub const WrapperRoleV1 = registry_mod.CircuitRoleV1;
pub const COMMON_FOLD_ROLE = WrapperRoleV1.common_fold_field_v2;

/// Registry-visible proof circuits accepted by the one durable binary fold.
/// H1 versus upper height is task authority, never a circuit-family selector.
pub const RegisteredChildCircuitV1 = enum(u8) {
    real_leaf_wrapper = 0,
    empty_leaf_wrapper = 1,
    common_fold = 2,

    pub fn registryRole(self: RegisteredChildCircuitV1) WrapperRoleV1 {
        return switch (self) {
            .real_leaf_wrapper => .ethereum_incremental_leaf_wrapper_v4,
            .empty_leaf_wrapper => .canonical_empty_field_v2,
            .common_fold => COMMON_FOLD_ROLE,
        };
    }
};

/// Child ordering is proof-semantic. Height and index remain in the public
/// task coordinate and are intentionally absent from this circuit-kind pair.
pub const OrderedChildCircuitPairV1 = struct {
    left: RegisteredChildCircuitV1,
    right: RegisteredChildCircuitV1,

    pub fn registryRoles(
        self: OrderedChildCircuitPairV1,
    ) [2]WrapperRoleV1 {
        return .{ self.left.registryRole(), self.right.registryRole() };
    }
};

/// The durable proof role. H1 versus upper height is task authority, not a
/// second parent-proof family. The common fold consumes any ordered pair of
/// already registered common-geometry child circuits.
pub const RoleInputKindV1 = enum(u8) {
    verifier_minted_incremental_ethereum_leaf_v4 = 1,
    canonical_empty_statement = 2,
    ordered_registered_children = 3,
};

pub const LeaseConsumptionV1 = enum(u8) {
    none = 0,
    both_or_neither = 1,
};

/// Canonical role surface for the future long-lived worker. Handles remain
/// process-local. A successful fold reports both consumed handle IDs; every
/// error before commit consumes neither.
pub const RoleInputContractV1 = struct {
    role: WrapperRoleV1,
    input_kind: RoleInputKindV1,
    durable_input_count: u8,
    live_child_lease_count: u8,
    native_input_proof_required: bool,
    output_proof_required: bool = true,
    node_public_derived_in_air: bool = true,
    success_reports_consumed_handles: bool,
    lease_consumption: LeaseConsumptionV1,

    pub fn canonical(role: WrapperRoleV1) RoleInputContractV1 {
        return switch (role) {
            .ethereum_incremental_leaf_wrapper_v4 => .{
                .role = role,
                .input_kind = .verifier_minted_incremental_ethereum_leaf_v4,
                .durable_input_count = 1,
                .live_child_lease_count = 0,
                .native_input_proof_required = true,
                .success_reports_consumed_handles = false,
                .lease_consumption = .none,
            },
            .canonical_empty_field_v2 => .{
                .role = role,
                .input_kind = .canonical_empty_statement,
                .durable_input_count = 1,
                .live_child_lease_count = 0,
                .native_input_proof_required = false,
                .success_reports_consumed_handles = false,
                .lease_consumption = .none,
            },
            COMMON_FOLD_ROLE => .{
                .role = role,
                .input_kind = .ordered_registered_children,
                .durable_input_count = 2,
                .live_child_lease_count = 2,
                // This directly verifies two child proofs; it does not wrap
                // a separately produced native parent proof.
                .native_input_proof_required = false,
                .success_reports_consumed_handles = true,
                .lease_consumption = .both_or_neither,
            },
        };
    }

    pub fn validate(self: RoleInputContractV1) Error!void {
        if (!std.meta.eql(self, canonical(self.role)))
            return error.InvalidCommonWrapperContract;
    }
};

/// Exact blockers. Native proof/capture geometry is not listed as missing:
/// those authorities exist, but they are migration inputs rather than common
/// wrapper geometry.
pub const MissingAuthorityV1 = enum(u8) {
    ethereum_incremental_leaf_cold_wrapper = 1,
    proof_bearing_canonical_empty_cold_wrapper = 2,
    common_fold_cold_wrapper = 3,
    component_padding_air_owner = 4,
    node_public_air_derivation = 5,
    cold_wrapper_geometry_extractor = 6,
    retained_eight_leaf_minitree = 7,
    authenticated_target_fit = 8,
};

pub const CurrentAuthorityStatusV1 = struct {
    incremental_ethereum_v4_native_capture_authenticated: bool = true,
    canonical_empty_program_authenticated: bool = true,
    ethereum_incremental_leaf_cold_wrapper_available: bool = false,
    proof_bearing_empty_cold_wrapper_available: bool = false,
    common_fold_cold_wrapper_available: bool = false,
    padding_parity_available: bool = PADDING_PARITY_AVAILABLE,
    first_missing: MissingAuthorityV1 =
        .ethereum_incremental_leaf_cold_wrapper,

    pub fn validate(self: CurrentAuthorityStatusV1) Error!void {
        if (!std.meta.eql(self, currentAuthorityStatus()))
            return error.InvalidCommonWrapperContract;
    }
};

pub fn currentAuthorityStatus() CurrentAuthorityStatusV1 {
    return .{};
}

/// Exact reuse point for the parent circuit. The existing binary cohort owns
/// the universal 36-row verifier and this statement source mirrors the native
/// multiverifier binding. It is still substrate until adapted into and cold
/// verified as the one common wrapper circuit.
pub const CommonFoldReuseStatusV1 = struct {
    universal_component_count: u16 = COMPONENT_COUNT,
    verifier_statement_words_published: bool =
        outer_statement.NATIVE_VERIFIER_PUBLISHES_STATEMENT_WORDS,
    complete_parent_stark_verified: bool =
        outer_statement.COMPLETE_PARENT_STARK_VERIFIED,
    authenticated_common_wrapper_available: bool = false,
    production_activation: bool = PRODUCTION_ACTIVATION,
    first_missing: MissingAuthorityV1 = .common_fold_cold_wrapper,

    pub fn validate(self: CommonFoldReuseStatusV1) Error!void {
        if (!std.meta.eql(self, commonFoldReuseStatus()))
            return error.InvalidCommonWrapperContract;
    }
};

pub fn commonFoldReuseStatus() CommonFoldReuseStatusV1 {
    return .{};
}

/// Non-serializable capability. A future kind-specific cold verifier owns the
/// only production constructor. A self-sealed `AuthenticatedGeometryV1` is not
/// sufficient to obtain this type.
pub const ColdWrapperGeometryLeaseV1 = opaque {
    pub fn geometry(
        self: *const ColdWrapperGeometryLeaseV1,
    ) *const registry_mod.AuthenticatedGeometryV1 {
        return &leaseStorageConst(self).geometry;
    }

    pub fn role(self: *const ColdWrapperGeometryLeaseV1) WrapperRoleV1 {
        return self.geometry().role;
    }
};

const ColdWrapperGeometryStorageV1 = struct {
    geometry: registry_mod.AuthenticatedGeometryV1,
};

/// Candidate target over wrapper geometry only. Distinct circuit identities
/// and preprocessed roots stay in registry entries and are intentionally
/// absent from this equality projection. Derivation succeeds only when every
/// authenticated wrapper already exposes the pointwise maximum padded vector;
/// a larger real wrapper therefore fails instead of being truncated or
/// squeezed and requires a reminted/versioned target.
pub const ManifestV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    role_count: u8 = ROLE_COUNT,
    component_count: u16 = COMPONENT_COUNT,
    preprocessed_column_count: u16,
    trace_log_size: u8,
    reserved: [3]u8 = .{ 0, 0, 0 },
    padded_component_log_sizes: [MAX_COMPONENT_COUNT]u8,
    preprocessed_column_log_sizes: [MAX_PREPROCESSED_COLUMN_COUNT]u8,
    pcs: registry_mod.PcsConfigV1,
    output_abi: registry_mod.OutputAbiV1,
    padding_layout_identity_sha256: [32]u8,
    roster_identity_sha256: [32]u8,
    geometry_authority_identities: [ROLE_COUNT][32]u8,
    identity_sha256: [32]u8,

    pub fn derive(
        leases: [ROLE_COUNT]*const ColdWrapperGeometryLeaseV1,
    ) Error!ManifestV1 {
        return deriveCore(leases);
    }

    fn deriveCore(
        leases: [ROLE_COUNT]*const ColdWrapperGeometryLeaseV1,
    ) Error!ManifestV1 {
        var geometries: [ROLE_COUNT]*const registry_mod.AuthenticatedGeometryV1 =
            undefined;
        for (leases, &geometries, 0..) |lease, *destination, ordinal| {
            destination.* = lease.geometry();
            try (destination.*).validate();
            if (@intFromEnum(destination.*.role) != ordinal)
                return error.InvalidRoleOrder;
        }
        const first = geometries[0];
        if (first.component_count != COMPONENT_COUNT)
            return error.InvalidCommonWrapperTarget;
        const secure_pcs = registry_mod.PcsConfigV1.secureTemporalParent();
        if (!std.meta.eql(first.pcs, secure_pcs))
            return error.SecurePcsRequired;
        try first.output_abi.validate();

        var target = [_]u8{0} ** MAX_COMPONENT_COUNT;
        for (0..COMPONENT_COUNT) |component| {
            for (geometries) |geometry| {
                if (geometry.component_count != COMPONENT_COUNT)
                    return error.InvalidCommonWrapperTarget;
                target[component] = @max(
                    target[component],
                    geometry.active_component_log_sizes[component],
                );
            }
        }
        var maximum_log: u8 = 0;
        for (target[0..COMPONENT_COUNT]) |log_size|
            maximum_log = @max(maximum_log, log_size);
        if (maximum_log != first.trace_log_size)
            return error.InvalidCommonWrapperTarget;

        for (geometries) |geometry| {
            if (geometry.component_count != COMPONENT_COUNT or
                geometry.trace_log_size != first.trace_log_size or
                geometry.preprocessed_column_count !=
                    first.preprocessed_column_count or
                !std.mem.eql(
                    u8,
                    geometry.padded_component_log_sizes[0..COMPONENT_COUNT],
                    target[0..COMPONENT_COUNT],
                ) or !std.mem.eql(
                u8,
                geometry.preprocessed_column_log_sizes[0..geometry.preprocessed_column_count],
                first.preprocessed_column_log_sizes[0..first.preprocessed_column_count],
            ) or !std.meta.eql(geometry.pcs, first.pcs) or
                !std.meta.eql(geometry.output_abi, first.output_abi) or
                !std.mem.eql(
                    u8,
                    &geometry.padding_layout_identity_sha256,
                    &first.padding_layout_identity_sha256,
                )) return error.PaddingTargetMismatch;
        }

        var result = ManifestV1{
            .preprocessed_column_count = first.preprocessed_column_count,
            .trace_log_size = first.trace_log_size,
            .padded_component_log_sizes = target,
            .preprocessed_column_log_sizes = first.preprocessed_column_log_sizes,
            .pcs = first.pcs,
            .output_abi = first.output_abi,
            .padding_layout_identity_sha256 = first.padding_layout_identity_sha256,
            .roster_identity_sha256 = universal.registryOrderDigest(),
            .geometry_authority_identities = .{
                geometries[0].authority_identity_sha256,
                geometries[1].authority_identity_sha256,
                geometries[2].authority_identity_sha256,
            },
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = manifestIdentity(&result);
        try result.validateSelfConsistency();
        return result;
    }

    pub fn validateAgainst(
        self: *const ManifestV1,
        leases: [ROLE_COUNT]*const ColdWrapperGeometryLeaseV1,
    ) Error!void {
        try self.validateSelfConsistency();
        const expected = try deriveCore(leases);
        if (!std.meta.eql(self.*, expected))
            return error.CommonWrapperTargetMismatch;
    }

    pub fn validateSelfConsistency(self: *const ManifestV1) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or self.role_count != ROLE_COUNT or
            self.component_count != COMPONENT_COUNT or
            self.preprocessed_column_count == 0 or
            self.preprocessed_column_count > MAX_PREPROCESSED_COLUMN_COUNT or
            self.trace_log_size == 0 or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            !std.mem.allEqual(
                u8,
                self.padded_component_log_sizes[COMPONENT_COUNT..],
                0,
            ) or !std.mem.allEqual(
            u8,
            self.preprocessed_column_log_sizes[self.preprocessed_column_count..],
            0,
        ) or std.mem.allEqual(
            u8,
            &self.padding_layout_identity_sha256,
            0,
        )) return error.InvalidCommonWrapperTarget;
        const roster_identity = universal.registryOrderDigest();
        if (!std.mem.eql(
            u8,
            &self.roster_identity_sha256,
            &roster_identity,
        )) return error.InvalidCommonWrapperTarget;
        try self.pcs.validate();
        if (!std.meta.eql(
            self.pcs,
            registry_mod.PcsConfigV1.secureTemporalParent(),
        )) return error.SecurePcsRequired;
        try self.output_abi.validate();
        var maximum_log: u8 = 0;
        for (self.padded_component_log_sizes[0..COMPONENT_COUNT]) |log_size| {
            if (log_size == 0 or log_size > self.trace_log_size)
                return error.InvalidCommonWrapperTarget;
            maximum_log = @max(maximum_log, log_size);
        }
        if (maximum_log != self.trace_log_size)
            return error.InvalidCommonWrapperTarget;
        for (self.preprocessed_column_log_sizes[0..self.preprocessed_column_count]) |log_size| if (log_size == 0 or log_size > self.trace_log_size)
            return error.InvalidCommonWrapperTarget;
        for (self.geometry_authority_identities) |identity|
            if (std.mem.allEqual(u8, &identity, 0))
                return error.InvalidCommonWrapperTarget;
        if (!std.mem.eql(
            u8,
            &self.identity_sha256,
            &manifestIdentity(self),
        )) return error.InvalidCommonWrapperTarget;
    }
};

fn leaseStorageConst(
    value: *const ColdWrapperGeometryLeaseV1,
) *const ColdWrapperGeometryStorageV1 {
    return @ptrCast(@alignCast(value));
}

fn leaseHandle(
    value: *const ColdWrapperGeometryStorageV1,
) *const ColdWrapperGeometryLeaseV1 {
    return @ptrCast(value);
}

fn manifestIdentity(value: *const ManifestV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(TARGET_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, value.role_count);
    hashInt(&hash, u16, value.component_count);
    hashInt(&hash, u16, value.preprocessed_column_count);
    hashInt(&hash, u8, value.trace_log_size);
    hash.update(&value.padded_component_log_sizes);
    hash.update(&value.preprocessed_column_log_sizes);
    hash.update(&value.pcs.identity_sha256);
    hash.update(&value.output_abi.identity_sha256);
    hash.update(&value.padding_layout_identity_sha256);
    hash.update(&value.roster_identity_sha256);
    for (value.geometry_authority_identities) |identity| hash.update(&identity);
    return hash.finalResult();
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

/// Test-only capability mint. Production code has no constructor until each
/// role owns a canonical wrapper proof and cold verifier.
pub const testing = if (builtin.is_test) struct {
    pub const OwnedColdWrapperGeometryV1 = struct {
        storage: ColdWrapperGeometryStorageV1,

        pub fn init(
            geometry: registry_mod.AuthenticatedGeometryV1,
        ) Error!OwnedColdWrapperGeometryV1 {
            try geometry.validate();
            return .{ .storage = .{ .geometry = geometry } };
        }

        pub fn lease(
            self: *const OwnedColdWrapperGeometryV1,
        ) *const ColdWrapperGeometryLeaseV1 {
            return leaseHandle(&self.storage);
        }
    };
} else struct {};

comptime {
    if (PRODUCTION_ACTIVATION or PADDING_PARITY_AVAILABLE or
        !CANDIDATE_TARGET_ONLY or !REMINT_REQUIRED_ON_GEOMETRY_GROWTH or
        COMPONENT_COUNT != 36 or ROLE_COUNT != 3 or
        artifact_mod.STATEMENT_WORD_COUNT != 412 or
        !outer_statement.NATIVE_VERIFIER_PUBLISHES_STATEMENT_WORDS or
        outer_statement.COMPLETE_PARENT_STARK_VERIFIED)
    {
        @compileError("common wrapper target contract drifted");
    }
}
