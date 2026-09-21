//! Compatibility exports for the shared recursion owner.
const owner = @import("stwo_riscv_frontend").recursion.detached_memory_profile_v1;
pub const MemoryProfileV1 = owner.MemoryProfileV1;
pub const ByteIterator = owner.ByteIterator;
