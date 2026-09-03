//! Fail-closed geometry and semantic gap for the canonical-empty wrapper.
//!
//! The first attempted native circuit repeated the statement-input AIR in all
//! 36 roster positions. That circuit is internally typed, but it is not the
//! common recursive circuit: its four-tree widths differ from the universal
//! roster before any row-size choice is considered. This authority keeps the
//! mismatch executable and prevents that diagnostic circuit from reaching a
//! q193 proof or registry admission.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const diagnostic =
    @import("recursive_common_canonical_empty_wrapper_manifest_v1.zig");

const air = frontend.recursion.air;
const universal_manifest = air.universal_manifest;
const roster = air.universal_roster;
const range_bridge = air.range_check_8_8_bridge;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const PROOF_ROUTE_AVAILABLE = false;
pub const UNIVERSAL_REFERENCE_ONLY = true;
pub const COMPONENT_COUNT: usize = roster.COMPONENT_COUNT;

pub const Error = diagnostic.Error || universal_manifest.Error || error{
    CanonicalEmptyCommonGeometryUnavailable,
    CanonicalEmptyGapAuthorityMismatch,
};

/// Relations which host reconstruction currently computes with SHA-256 but
/// no admitted recursion AIR derives. The Poseidon subtree digest is not in
/// this list because the universal roster already has an authenticated
/// Poseidon provider; its role-specific source linkage is still missing.
pub const MissingSemanticAuthorityV1 = enum(u8) {
    empty_leaf_authority_sha256 = 1,
    leaf_envelope_authority_sha256 = 2,
    statement_identity_sha256 = 3,
    subtree_identity_sha256 = 4,
    wrapper_authority_sha256 = 5,
    node_public_output_sha256 = 6,
};

pub const GeometryV1 = struct {
    component_count: u16,
    preprocessed_columns: u32,
    main_columns: u32,
    interaction_columns: u32,
    constraint_columns: u32,
};

/// Pointer-free diagnostic only. It is deliberately not a registry geometry
/// and has no seal constructor that could be confused with proof admission.
pub const GapAuthorityV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    proof_route_available: bool = PROOF_ROUTE_AVAILABLE,
    diagnostic: GeometryV1,
    universal_reference: GeometryV1,
    missing_sha_authority_count: u8,
    first_missing: MissingSemanticAuthorityV1,
    universal_native_trace_materializer_available: bool,
    role_specific_node_public_owner_available: bool,

    pub fn inspect() Error!GapAuthorityV1 {
        const diagnostic_manifest = try diagnostic.build();
        const reference = try referenceUniversalManifest();
        var result = GapAuthorityV1{
            .diagnostic = geometry(&diagnostic_manifest),
            .universal_reference = geometry(&reference),
            .missing_sha_authority_count = @typeInfo(
                MissingSemanticAuthorityV1,
            ).@"enum".fields.len,
            .first_missing = .empty_leaf_authority_sha256,
            .universal_native_trace_materializer_available = false,
            .role_specific_node_public_owner_available = false,
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: *const GapAuthorityV1) Error!void {
        const diagnostic_manifest = try diagnostic.build();
        const reference = try referenceUniversalManifest();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or self.proof_route_available or
            !std.meta.eql(self.diagnostic, geometry(&diagnostic_manifest)) or
            !std.meta.eql(self.universal_reference, geometry(&reference)) or
            self.diagnostic.preprocessed_columns != 252 or
            self.diagnostic.main_columns != 72 or
            self.diagnostic.interaction_columns != 288 or
            self.universal_reference.preprocessed_columns != 570 or
            self.universal_reference.main_columns != 1044 or
            self.universal_reference.interaction_columns != 560 or
            self.diagnostic.preprocessed_columns ==
                self.universal_reference.preprocessed_columns or
            self.missing_sha_authority_count != 6 or
            self.first_missing != .empty_leaf_authority_sha256 or
            self.universal_native_trace_materializer_available or
            self.role_specific_node_public_owner_available)
        {
            return error.CanonicalEmptyGapAuthorityMismatch;
        }
    }

    pub fn requireProofRoute(self: *const GapAuthorityV1) Error!void {
        try self.validate();
        return error.CanonicalEmptyCommonGeometryUnavailable;
    }
};

/// Column counts and semantic row owners are independent of the illustrative
/// logs. These values exist only to make `universal_manifest.build` replay the
/// full catalog; they are not the future cold-derived wrapper log authority.
fn referenceUniversalManifest() universal_manifest.Error!air
    .universal_adapter_manifest.Manifest {
    var logs = [_]u32{11} ** COMPONENT_COUNT;
    logs[@intFromEnum(roster.Component.range_check_8_8)] =
        range_bridge.LOG_SIZE;
    return universal_manifest.build(logs);
}

fn geometry(value: anytype) GeometryV1 {
    return .{
        .component_count = value.roster_count,
        .preprocessed_columns = value.total_preprocessed_columns,
        .main_columns = value.total_main_columns,
        .interaction_columns = value.total_interaction_columns,
        .constraint_columns = value.total_constraints,
    };
}

comptime {
    if (FORMAT_VERSION != 1 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or PROOF_ROUTE_AVAILABLE or
        !UNIVERSAL_REFERENCE_ONLY or COMPONENT_COUNT != 36 or
        @typeInfo(MissingSemanticAuthorityV1).@"enum".fields.len != 6)
    {
        @compileError("canonical-empty common-wrapper gap drifted");
    }
}
