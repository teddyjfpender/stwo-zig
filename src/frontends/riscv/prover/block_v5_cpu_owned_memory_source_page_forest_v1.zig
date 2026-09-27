//! Explicit typed CPU PAGE forest selection. Canonical Driver defaults remain
//! unchanged. Independent Global pins and PAGE policy select original sources;
//! durable hashes and setup-owner identities never confer proof authority.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Owned = @import("block_v5_memory_source_page_forest_policy_owner_v1.zig");
const Policy = @import("block_v5_memory_source_page_policy_file_v1.zig");
const Global = @import("block_v5_capacity_global_receiver_v1.zig");
const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
pub const Selection = struct { independently_expected: Policy.Pin, globals: Global.Pins, profile: Base.Profile, limits: Owned.Limits = .{} };
pub const Built = Owned.Built;
pub fn publish(a: std.mem.Allocator, dir: std.fs.Dir, selection: Selection) !Built {
    return Owned.ForBackend(Cpu).build(a, dir, selection.independently_expected, selection.globals, selection.profile, selection.limits, .publish);
}
pub fn reconstruct(a: std.mem.Allocator, dir: std.fs.Dir, selection: Selection, existing: Owned.Existing) !Built {
    return Owned.ForBackend(Cpu).build(a, dir, selection.independently_expected, selection.globals, selection.profile, selection.limits, .{ .reconstruct = existing });
}
