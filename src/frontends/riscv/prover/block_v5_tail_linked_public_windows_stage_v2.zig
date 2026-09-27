//! Actual typed producer and fresh standalone receiver through one kernel.
const Impl = @import("block_v5_wide_public_windows_stage_impl_v1.zig").ForModules(@import("../recursion/block_v5_tail_linked_public_windows_v2.zig"), @import("../recursion/block_v5_tail_linked_public_windows_receiver_v2.zig"), @import("../recursion/block_v5_tail_linked_public_windows_preparation_v2.zig"), @import("../recursion/block_v5_reusable_tail_linked_public_windows_protocol_v2.zig"), @import("../recursion/block_v5_tail_linked_public_windows_bus_v2.zig"));
pub const Limits = Impl.Limits;
pub const ForBackend = Impl.ForBackend;
