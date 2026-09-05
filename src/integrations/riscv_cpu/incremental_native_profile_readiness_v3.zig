//! Fail-closed readiness contract for the full-state incremental V3 profile.
//!
//! The host boundary contract is necessary but not proof authority.  This
//! snapshot names every typed owner that must exist before a native leaf or a
//! recursive wrapper may admit the profile.  It deliberately has no mutable
//! activation booleans and no digest-as-authority escape hatch.

const std = @import("std");

pub const PRODUCTION_ACTIVE = false;
pub const SCHEMA = "stwo.ethereum.incremental-native-profile-readiness.v3";

pub const AvailabilityV3 = enum(u8) {
    unavailable = 0,
    structural_contract_only = 1,
};

pub const MissingAuthorityV3 = enum(u8) {
    full_state_statement_family,
    opened_inventory_clock_join,
    split_boundary_air,
    public_abi_link_air,
    bridge_statement_kind,
    native_profile_geometry,
    prover_trace_and_interaction_assembly,
    proof_artifact_codec,
    cold_verifier_capture,
    common_leaf_wrapper_admission,
};

pub const Error = error{
    NativeIncrementalProfileUnavailable,
    ReadinessContractDrift,
};

/// Frozen observation of the current tree.  Future capability must be minted
/// by a new version after each typed authority is implemented and gated; no
/// caller can turn one of these fields on.
pub const ReadinessV3 = struct {
    role_derived_host_contract: AvailabilityV3,
    full_state_statement_family: AvailabilityV3,
    opened_inventory_clock_join: AvailabilityV3,
    split_boundary_air: AvailabilityV3,
    public_abi_link_air: AvailabilityV3,
    bridge_statement_kind: AvailabilityV3,
    native_profile_geometry: AvailabilityV3,
    prover_trace_and_interaction_assembly: AvailabilityV3,
    proof_artifact_codec: AvailabilityV3,
    cold_verifier_capture: AvailabilityV3,
    common_leaf_wrapper_admission: AvailabilityV3,

    pub fn validateCurrent(self: ReadinessV3) Error!void {
        if (!std.meta.eql(self, current())) return error.ReadinessContractDrift;
    }

    pub fn missingAuthorities(
        self: ReadinessV3,
        destination: []MissingAuthorityV3,
    ) Error!usize {
        try self.validateCurrent();
        if (destination.len < ALL_MISSING.len)
            return error.ReadinessContractDrift;
        @memcpy(destination[0..ALL_MISSING.len], &ALL_MISSING);
        return ALL_MISSING.len;
    }

    pub fn requireNativeProofAdmission(
        self: ReadinessV3,
    ) Error!void {
        try self.validateCurrent();
        return error.NativeIncrementalProfileUnavailable;
    }
};

pub const ALL_MISSING = [_]MissingAuthorityV3{
    .full_state_statement_family,
    .opened_inventory_clock_join,
    .split_boundary_air,
    .public_abi_link_air,
    .bridge_statement_kind,
    .native_profile_geometry,
    .prover_trace_and_interaction_assembly,
    .proof_artifact_codec,
    .cold_verifier_capture,
    .common_leaf_wrapper_admission,
};

pub fn current() ReadinessV3 {
    return .{
        .role_derived_host_contract = .structural_contract_only,
        .full_state_statement_family = .unavailable,
        .opened_inventory_clock_join = .unavailable,
        .split_boundary_air = .unavailable,
        .public_abi_link_air = .unavailable,
        .bridge_statement_kind = .unavailable,
        .native_profile_geometry = .unavailable,
        .prover_trace_and_interaction_assembly = .unavailable,
        .proof_artifact_codec = .unavailable,
        .cold_verifier_capture = .unavailable,
        .common_leaf_wrapper_admission = .unavailable,
    };
}
