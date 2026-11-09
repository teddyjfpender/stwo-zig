//! Compatibility exports for the shared recursion owner.
const owner = @import("stwo_riscv_frontend").recursion.detached_pcs_rows_v1;
pub const View = owner.View;
pub const OwnedV1 = owner.OwnedV1;
pub const testFromVerifiedChild = owner.testFromVerifiedChild;
