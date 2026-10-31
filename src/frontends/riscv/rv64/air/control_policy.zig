//! Versioned control representation; native RV64 addresses remain full u64.
pub const Policy = enum(u32) { bytes_v1 = 1, limbs24_v2 = 2 };
