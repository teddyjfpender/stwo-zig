//! Shared typed implementation with unchanged explicit legacy exports.
const Impl = @import("block_v5_program_fused_first_round_impl_v1.zig");
pub const ForCapacity = Impl.ForCapacity;
const Legacy = ForCapacity(false);
pub const add = Legacy.add;
