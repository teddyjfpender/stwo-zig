//! Explicit boundaries that combine frontends with concrete backends.

pub const cairo_metal = @import("stwo_cairo_metal_integration");
pub const cairo_cpu = @import("stwo_cairo_cpu_integration");
pub const cairo_cuda = @import("stwo_cairo_cuda_integration");
pub const native_cuda = @import("stwo_native_cuda_integration");
pub const riscv_cpu = @import("stwo_riscv_cpu_integration");
