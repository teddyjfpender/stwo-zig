//! Original B5WM/v1 rows; exact child and compensation kernels are shared.
const NoBinding = struct {
    pub fn attach(_: @import("std").mem.Allocator, _: anytype, _: anytype, _: anytype, _: anytype, _: anytype, _: usize) !void {}
};
const Impl = @import("block_v5_wide_public_windows_preparation_impl_v1.zig").ForModules(@import("block_v5_wide_public_windows_v1.zig"), @import("block_v5_wide_public_windows_bus_v1.zig"), @import("air/block_v5_wide_public_windows_composition_v1.zig"), @import("block_v5_reusable_wide_public_windows_protocol_v1.zig"), NoBinding);
pub const Limits = Impl.Limits;
pub const Prepared = Impl.Prepared;
pub const prepare = Impl.prepare;
