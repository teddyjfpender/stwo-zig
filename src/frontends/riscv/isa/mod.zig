//! stwo_riscv_isa canonical package root.

pub const modules = @import("providers.zig");

test { _ = @import("tests/root.zig"); }
