//! Explicit selected CPU source-memory publication/reconstruction. No Driver
//! default changes or complete-block token. Successful publication consumes
//! the genuine PAGE Built; failure retains it, even if base reader consumed.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Owned = @import("block_v5_ram_range_forest_policy_owner_v1.zig");
const Manifest = @import("block_v5_ram_range_forest_manifest_v1.zig");
const Page = @import("block_v5_memory_source_page_forest_policy_owner_v1.zig");
const Bundle = @import("block_v5_cpu_bundle_store_v1.zig").ForCapacity(true);
pub const Selection = struct {
    page: *Page.Built,
    originals: *Bundle.Store,
    memory: @import("block_v5_ram_lanes_receiver_v1.zig").Pins,
    sealed: @import("block_v5_source_seal_v1.zig").Sealed,
    profile: @import("../recursion/blake3_execution_parent_protocol.zig").Profile,
    limits: Owned.Limits = .{},
};
pub const Built = Owned.Built;
pub const complete_block_authority = false;
pub fn publish(a: std.mem.Allocator, dir: std.fs.Dir, selection: Selection) !Built {
    return Owned.ForBackend(Cpu).build(a, dir, selection.originals, selection.memory, selection.sealed, selection.page, selection.profile, selection.limits, .publish);
}
pub fn reconstruct(a: std.mem.Allocator, dir: std.fs.Dir, selection: Selection, manifest: Manifest.FilePin) !Built {
    return Owned.ForBackend(Cpu).build(a, dir, selection.originals, selection.memory, selection.sealed, selection.page, selection.profile, selection.limits, .{ .reconstruct = manifest });
}
