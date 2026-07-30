//! Narrow, exact C ABI modules for the resident CUDA product.

pub const aot = @import("aot.zig");
pub const compact_source = @import("compact_source.zig");
pub const field = @import("field.zig");
pub const runtime = @import("runtime.zig");
pub const schema = @import("schema.zig");
pub const stages = @import("stages/mod.zig");
pub const types = @import("types.zig");

test {
    _ = aot;
    _ = compact_source;
    _ = field;
    _ = runtime;
    _ = schema;
    _ = stages;
    _ = types;
}
