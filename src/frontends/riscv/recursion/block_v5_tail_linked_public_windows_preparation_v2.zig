//! Same-parent original B5PD prefix-fold constraints, genuine original child
//! verifier rows, public compensation, and shared B5SS challenge equations.
const Impl = @import("block_v5_wide_public_windows_preparation_impl_v1.zig").ForModules(@import("block_v5_tail_linked_public_windows_v2.zig"), @import("block_v5_tail_linked_public_windows_bus_v2.zig"), @import("air/block_v5_tail_linked_public_windows_composition_v2.zig"), @import("block_v5_reusable_tail_linked_public_windows_protocol_v2.zig"), @import("air/block_v5_tail_linked_public_binding_v2.zig"));
pub const Limits = Impl.Limits;
pub const Prepared = Impl.Prepared;
pub const prepare = Impl.prepare;
