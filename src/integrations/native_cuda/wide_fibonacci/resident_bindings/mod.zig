//! Exact typed binding of a prepared wide-Fibonacci plan to a CUDA arena.

pub const types = @import("types.zig");
pub const Views = types.Views;
pub const bind = @import("bind.zig").bind;

test {
    _ = types;
    _ = @import("bind.zig");
}
