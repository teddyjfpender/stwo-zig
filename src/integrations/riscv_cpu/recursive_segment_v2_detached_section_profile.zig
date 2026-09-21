//! Compatibility exports for the shared recursion owner.
const owner = @import("stwo_riscv_frontend").recursion.detached_section_profile_v1;
pub const SectionV1 = owner.SectionV1;
pub const SectionProfileV1 = owner.SectionProfileV1;
