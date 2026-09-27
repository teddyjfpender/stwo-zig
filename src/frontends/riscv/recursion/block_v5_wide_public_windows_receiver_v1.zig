//! Fresh independently typed receiver; no host-verification token.
const Impl = @import("block_v5_wide_public_windows_receiver_impl_v1.zig").ForModules(@import("block_v5_wide_public_windows_v1.zig"), @import("block_v5_reusable_wide_public_windows_protocol_v1.zig"), @import("block_v5_wide_public_windows_bus_v1.zig"));
pub const Policy = Impl.Policy;
pub const Fresh = Impl.Fresh;
pub const verify = Impl.verify;
