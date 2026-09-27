//! Canonical node receiver is summary-only: exact same genuine Parent proof,
//! no inactive descendant preparation or witness resurrection.
const Impl = @import("block_v5_ram_range_forest_summary_receiver_v1.zig");
pub const Fresh = Impl.Fresh;
pub const Policy = Impl.Policy;
pub const verify = Impl.verify;
pub const verifyRoot = Impl.verifyRoot;
