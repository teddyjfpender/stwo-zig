//! stwo_riscv_memory canonical package root.

pub const modules = @import("providers.zig");
pub const assets = @import("assets.zig");

test { _ = @import("tests/root.zig"); }
