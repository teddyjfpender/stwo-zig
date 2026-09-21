//! Compatibility exports for the shared verifier-derived authority boundary.
const owner = @import("stwo_riscv_frontend").recursion.detached_segment_authority_boundary_v1;
pub const DescriptorsV1 = owner.DescriptorsV1;
pub const BoundaryV1 = owner.BoundaryV1;
pub const derive = owner.derive;
