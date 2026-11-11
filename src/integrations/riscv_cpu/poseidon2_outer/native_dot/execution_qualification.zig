//! R7 adapter to the SAME full source/global/terminal attack corpus as R6.
const std = @import("std");
const Shared = @import("../pure_p2_root_attack_corpus.zig");
const Receiver = @import("../pure_p2_op_root_receiver.zig");
const Runtime = @import("../pure_p2_op_runtime.zig");
const Topology = @import("execution_topology.zig").Topology;
fn verify(raw: *const anyopaque, a: std.mem.Allocator, plan: *const Receiver.Plan, bytes: []const u8) !void {
    const topology: *const Topology = @ptrCast(@alignCast(raw));
    return @import("execution_receiver.zig").verifyPlan(a, plan, topology, bytes);
}
pub fn run(a: std.mem.Allocator, source: Runtime.SourceDirectory, metadata: Receiver.Metadata, plan: *const Receiver.Plan, topology: *const Topology, root: []const u8) !void {
    return Shared.run(a, source, metadata, plan, .{ .context = topology, .verify = verify, .expected = @import("execution_receiver.zig").expectedRoot, .format = .r7 }, root, false);
}
