//! Focused module root for the Cairo CUDA product.

pub const backend = @import("stwo_cuda_backend");
pub const frontend = @import("stwo_cairo_frontend");
pub const integration = @import("integrations/cairo_cuda/mod.zig");

pub const executor = integration.executor;

test {
    _ = backend;
    _ = frontend;
    _ = integration;
}
