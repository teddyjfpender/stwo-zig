//! Compatibility exports for the shared recursion owner.
const owner = @import("stwo_riscv_frontend").recursion.detached_segment_recording_components_v1;
pub const Relations = owner.Relations;
pub const AdmissionParametersV1 = owner.AdmissionParametersV1;
pub const ClaimsV1 = owner.ClaimsV1;
pub const OwnedComponentsV1 = owner.OwnedComponentsV1;

test "SegmentV2 witness-free verifier owns all39 canonical adapters and untrusted claims" {
    try owner.testCanonicalAdapters();
}

test "SegmentV2 witness-free verifier rejects malformed admission and inactive or provider claims" {
    try owner.testMalformedAdmission();
}

test "SegmentV2 witness-free verifier releases its owner after initial definition allocation failure" {
    try owner.testAllocationFailure();
}

test "SegmentV2 witness-free recording keeps all39 claims and two provider partials symbolic" {
    try owner.testSymbolicClaims();
}
