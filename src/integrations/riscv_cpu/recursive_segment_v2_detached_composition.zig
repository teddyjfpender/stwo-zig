//! Compatibility exports for the shared recursion owner.
const owner = @import("stwo_riscv_frontend").recursion.detached_composition_preparation_v1;
pub const OwnedV1 = owner.OwnedV1;
pub const recordDetached = owner.recordDetached;
pub const testFromVerifiedChild = owner.testFromVerifiedChild;
