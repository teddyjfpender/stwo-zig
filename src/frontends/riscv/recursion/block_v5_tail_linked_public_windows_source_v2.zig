//! Lazy actual original public-root bytes; no legacy H conversion.
const Impl = @import("block_v5_wide_public_windows_source_impl_v1.zig").ForModules(@import("block_v5_tail_linked_public_windows_receiver_v2.zig"), @import("block_v5_reusable_tail_linked_public_windows_protocol_v2.zig"), 4_300_260);
pub const PUBLIC_CIRCUIT = Impl.PUBLIC_CIRCUIT;
pub const Coordinate = Impl.Coordinate;
pub const Window = Impl.Window;
pub const Source = Impl.Source;
pub const Admission = Impl.Admission;
pub const publicPrefix = Impl.prefix;
