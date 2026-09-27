//! Shared typed implementation with unchanged explicit legacy exports.
const Impl = @import("block_v5_cpu_assembly_impl_v1.zig");
pub const ForCapacity = Impl.ForCapacity;
const Legacy = ForCapacity(false);
pub const Assembly = Legacy.Assembly;
pub const assemble = Legacy.assemble;
