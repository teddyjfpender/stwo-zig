//! Actual typed CPU selection with independently reconstructed durable recipes.
//! Existing Driver/SourcePages/default routes remain unchanged. No key is read
//! from transport; standalone reconstruction repeats real original verifiers.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Snapshot = @import("../recursion/block_v5_input_request_policy_snapshot_v1.zig");
const Setup = @import("block_v5_closed_input_request_policy_owner_v2.zig");
pub const Selection = struct {
    snapshot: *Snapshot.Owner,
    independently_expected: Snapshot.Pins,
    loader: Setup.Loader,
    profile: @import("../recursion/blake3_execution_parent_protocol.zig").Profile,
    limits: Setup.Limits = .{},
};
pub const Built = Setup.Built;
pub const complete_block_authority = false;
/// Publication transfers a real root capture together with the stable original
/// Prepared/key/schedule owner. It does not verify the same published root twice.
pub fn publish(a: std.mem.Allocator, dir: std.fs.Dir, selection: Selection) !Built {
    return Setup.ForBackend(Cpu).build(a, dir, selection.snapshot, selection.independently_expected, selection.loader, selection.profile, selection.limits, .publish);
}
/// Only independently reconstructed original policies and actual file bytes
/// determine the expected root recipe. Files supply no admitted templates.
pub fn reconstruct(a: std.mem.Allocator, dir: std.fs.Dir, selection: Selection, proposed_files: Setup.Existing) !Built {
    return Setup.ForBackend(Cpu).build(a, dir, selection.snapshot, selection.independently_expected, selection.loader, selection.profile, selection.limits, .{ .reconstruct = proposed_files });
}
