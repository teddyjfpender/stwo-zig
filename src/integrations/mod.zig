//! Explicit boundaries that combine frontends with concrete backends.

pub const cairo_metal = @import("cairo_metal/mod.zig");
pub const cairo_cpu = @import("cairo_cpu/mod.zig");
pub const cairo_cuda = @import("cairo_cuda/mod.zig");
pub const native_cuda = @import("native_cuda/mod.zig");
pub const riscv_cpu = @import("riscv_cpu/mod.zig");
