//! stwo_riscv_testing: canonical source interfaces consumed across package owners.

pub const compatibility = @import("compatibility.zig");

test { _ = @import("tests/root.zig"); }
