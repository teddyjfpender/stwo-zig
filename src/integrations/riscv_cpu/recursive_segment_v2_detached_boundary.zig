//! Compatibility exports for the shared recursion owner.
const owner = @import("stwo_riscv_frontend").recursion.detached_boundary_preparation_v1;
pub const SectionProfileV1 = owner.SectionProfileV1;
pub const MemoryProfileV1 = owner.MemoryProfileV1;
pub const VERSION = owner.VERSION;
pub const InputSource = owner.InputSource;
pub const InputBinding = owner.InputBinding;
pub const ProviderBinding = owner.ProviderBinding;
pub const OwnedV1 = owner.OwnedV1;
pub const testFromVerifiedChild = owner.testFromVerifiedChild;
pub const testing = owner.testing;

test "SegmentV2 expected boundary shares native hashes and keeps dynamic values out of graph" {
    try owner.testExpectedBoundary();
}
