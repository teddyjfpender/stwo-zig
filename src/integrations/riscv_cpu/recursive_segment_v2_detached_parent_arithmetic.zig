//! Compatibility exports for the shared recursion owner.
const owner = @import("stwo_riscv_frontend").recursion.detached_parent_arithmetic_v1;
pub const COMPOSITION_IDS = owner.COMPOSITION_IDS;
pub const BOUNDARY_IDS = owner.BOUNDARY_IDS;
pub const PARENT_ID = owner.PARENT_ID;
pub const PUBLIC_SCOPE = owner.PUBLIC_SCOPE;
pub const Children = owner.Children;
pub const View = owner.View;
pub const OwnedV1 = owner.OwnedV1;
