//! Actual fresh parent verifier reconstructs all original independent carrier
//! and bounded-window public policy, then verifies the real combined proof.
const Impl = @import("block_v5_wide_public_windows_receiver_impl_v1.zig").ForModules(@import("block_v5_input_tail_ancestor_bus_v1.zig"), @import("block_v5_input_tail_ancestor_protocol_v1.zig"), @import("block_v5_input_tail_ancestor_bus_v1.zig"));
pub const Policy = Impl.Policy;
pub const Fresh = Impl.Fresh;
pub const verify = Impl.verify;
