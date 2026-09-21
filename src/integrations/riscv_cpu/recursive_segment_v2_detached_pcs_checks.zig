//! Compatibility exports; PCS/FRI preparation is owned by shared recursion.
const shared = @import("stwo_riscv_frontend").recursion.detached_pcs_preparation_v1;
pub const View = shared.View;
pub const OwnedV1 = shared.OwnedV1;
pub const testFromVerifiedChild = shared.testFromVerifiedChild;
pub const checkLogicalRows = shared.checkLogicalRows;
