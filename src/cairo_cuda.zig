//! Focused module root for the Cairo CUDA product.

pub const backend = @import("backends/cuda/mod.zig");
pub const frontend = @import("frontends/cairo/mod.zig");
pub const integration = @import("integrations/cairo_cuda/mod.zig");

pub const executor = integration.executor;

test {
    _ = backend;
    _ = frontend;
    _ = integration;
}
