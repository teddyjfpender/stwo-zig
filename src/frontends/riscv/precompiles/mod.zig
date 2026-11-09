//! stwo_riscv_precompiles canonical package root.

pub const modules = @import("providers.zig");

test { _ = @import("tests/root.zig"); }
