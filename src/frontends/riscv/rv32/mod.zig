//! stwo_riscv_rv32 canonical package root.

pub const modules = @import("providers.zig");
pub const assets = @import("assets.zig");

test { _ = @import("tests/root.zig"); }
