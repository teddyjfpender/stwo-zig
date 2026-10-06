//! Versioned security floor for a future production V3 base leaf.
//!
//! This is a profile admission check, not proof verification. The native V2
//! verifier and the 39-row outer prover/verifier must each use these exact
//! transcript parameters and bind the profile to independently pinned keys
//! before a V3 wrapper may publish a recursive result.

const std = @import("std");
const core = @import("stwo_core");
const target = @import("protocol.zig");
const outer = @import("outer_parent_child_admission_profile.zig");
const native_transcript = @import("../air/transcript/protocol.zig");
const native_prover = @import("../prover.zig");

pub const VERSION: u32 = 1;
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const REQUIRED_PCS_CONFIG = target.PCS_CONFIG;
pub const REQUIRED_INTERACTION_POW_BITS = target.INTERACTION_POW_BITS;

pub const Error = error{
    InvalidSecurityPolicyVersion,
    NativePcsProfileMismatch,
    NativeInteractionPowMismatch,
    OuterPcsProfileMismatch,
    OuterInteractionPowMismatch,
};

/// Values are configuration facts only. A caller cannot manufacture proof
/// authority by constructing this record with the required numbers.
pub const ProfileV1 = struct {
    version: u32 = VERSION,
    native_pcs: core.pcs.PcsConfig,
    native_interaction_pow_bits: u32,
    outer_pcs: core.pcs.PcsConfig,
    outer_interaction_pow_bits: u32,

    pub fn validate(self: ProfileV1) Error!void {
        if (self.version != VERSION) return error.InvalidSecurityPolicyVersion;
        if (!std.meta.eql(self.native_pcs, REQUIRED_PCS_CONFIG) or
            self.native_pcs.securityBits() < target.MIN_CONFIGURED_PCS_BITS)
            return error.NativePcsProfileMismatch;
        if (self.native_interaction_pow_bits != REQUIRED_INTERACTION_POW_BITS)
            return error.NativeInteractionPowMismatch;
        if (!std.meta.eql(self.outer_pcs, REQUIRED_PCS_CONFIG) or
            self.outer_pcs.securityBits() < target.MIN_CONFIGURED_PCS_BITS)
            return error.OuterPcsProfileMismatch;
        if (self.outer_interaction_pow_bits != REQUIRED_INTERACTION_POW_BITS)
            return error.OuterInteractionPowMismatch;
    }
};

pub const required = ProfileV1{
    .native_pcs = REQUIRED_PCS_CONFIG,
    .native_interaction_pow_bits = REQUIRED_INTERACTION_POW_BITS,
    .outer_pcs = REQUIRED_PCS_CONFIG,
    .outer_interaction_pow_bits = REQUIRED_INTERACTION_POW_BITS,
};

/// Static implementation audit; currently fails at the native V2 preset.
/// Keep this separate from `ProfileV1.validate`: actual verifier transactions
/// must pass their own pinned key/config, not trust a caller-supplied record.
pub fn requireCurrentImplementation() Error!void {
    try (ProfileV1{
        .native_pcs = native_prover.SECURE_PCS_CONFIG,
        .native_interaction_pow_bits = native_transcript.INTERACTION_POW_BITS,
        .outer_pcs = outer.OUTER_PCS_CONFIG,
        .outer_interaction_pow_bits = outer.INTERACTION_POW_BITS,
    }).validate();
}

test "V3 production security policy rejects current native and outer presets" {
    try required.validate();
    try std.testing.expectError(error.NativePcsProfileMismatch, requireCurrentImplementation());

    var profile = required;
    profile.native_pcs = native_prover.SECURE_PCS_CONFIG;
    try std.testing.expectError(error.NativePcsProfileMismatch, profile.validate());

    profile = required;
    profile.outer_pcs = outer.OUTER_PCS_CONFIG;
    profile.outer_interaction_pow_bits = outer.INTERACTION_POW_BITS;
    try std.testing.expectError(error.OuterPcsProfileMismatch, profile.validate());
    profile.outer_pcs = REQUIRED_PCS_CONFIG;
    try std.testing.expectError(error.OuterInteractionPowMismatch, profile.validate());

    profile = required;
    profile.native_interaction_pow_bits = 0;
    try std.testing.expectError(error.NativeInteractionPowMismatch, profile.validate());
    profile = required;
    profile.version += 1;
    try std.testing.expectError(error.InvalidSecurityPolicyVersion, profile.validate());
}
