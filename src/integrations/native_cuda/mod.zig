//! Zig-owned Native CUDA frontend/backend integrations.

pub const wide_fibonacci = @import("wide_fibonacci/mod.zig");
pub const xor = @import("xor/mod.zig");

test {
    _ = wide_fibonacci;
    _ = xor;
}
