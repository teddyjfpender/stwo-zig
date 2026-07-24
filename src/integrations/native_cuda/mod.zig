//! Zig-owned Native CUDA frontend/backend integrations.

pub const wide_fibonacci = @import("wide_fibonacci/mod.zig");

test {
    _ = wide_fibonacci;
}
