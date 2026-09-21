//! Compatibility exports for the shared recursion owner.
const owner = @import("stwo_riscv_frontend").recursion.detached_segment_protocol_fixture_v1;
pub const VERSION = owner.VERSION;
pub const DEVELOPMENT_ONLY = owner.DEVELOPMENT_ONLY;
pub const PCS_CONFIG = owner.PCS_CONFIG;
pub const INTERACTION_POW_BITS = owner.INTERACTION_POW_BITS;
pub const ProfileV1 = owner.ProfileV1;
pub const KeyV1 = owner.KeyV1;
pub const FixedAdmissionV1 = owner.FixedAdmissionV1;
pub const PayloadSourceV1 = owner.PayloadSourceV1;
pub const mixAdmission = owner.mixAdmission;
pub const mixInteractionPow = owner.mixInteractionPow;
pub const mixClaimsAndBoundary = owner.mixClaimsAndBoundary;
pub const testing = owner.testing;

test "SegmentV2 detached fixed projection excludes source seals and pins circuit facts" {
    try owner.testFixedProjection();
}

test "SegmentV2 detached transcript binds dynamic expected wire without specializing the key" {
    try owner.testDynamicExpectedWire();
}

test "SegmentV2 detached claims share fixed lowering and expected row36 closure" {
    try owner.testClaimsClosure();
}

test "SegmentV2 detached profiles bind security and interaction work" {
    try owner.testProfiles();
}
