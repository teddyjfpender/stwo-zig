//! Genuine original parent verifier of the final two-root transition graph.
//! Canonical driver/global authority and positive proof qualification pending.
const Public = @import("block_v5_requester_memory_public_v1.zig");
const Protocol = @import("block_v5_requester_memory_protocol_v1.zig");
const Impl = @import("block_v5_wide_public_windows_receiver_impl_v1.zig").ForModules(Public, Protocol, Public);
pub const Policy = Impl.Policy;
pub const Fresh = Impl.Fresh;
pub const verify = Impl.verify;
pub const complete_block_authority = false;
