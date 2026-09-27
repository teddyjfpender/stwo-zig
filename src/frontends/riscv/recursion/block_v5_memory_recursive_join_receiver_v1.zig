//! Fresh original parent proof of OPEN memory join. Native/caller transitions,
//! register/public compensation and complete block authority are not discharged.
const Public = @import("block_v5_memory_recursive_join_public_v1.zig");
const Protocol = @import("block_v5_memory_recursive_join_protocol_v1.zig");
const Impl = @import("block_v5_wide_public_windows_receiver_impl_v1.zig").ForModules(Public, Protocol, Public);
pub const Policy = Impl.Policy;
pub const Fresh = Impl.Fresh;
pub const verify = Impl.verify;
pub const complete_block_authority = false;
