//! R6 adapter to the common source/global/terminal root qualification corpus.
const std = @import("std");
const Shared = @import("../pure_p2_root_attack_corpus.zig");
const Receiver = @import("../pure_p2_op_root_receiver.zig");
const Runtime = @import("../pure_p2_op_runtime.zig");
const Topology = @import("topology.zig").Topology;
fn verify(raw: *const anyopaque, a: std.mem.Allocator, plan: *const Receiver.Plan, bytes: []const u8) !void {
    const topology: *const Topology = @ptrCast(@alignCast(raw));
    return @import("receiver.zig").verifyPlan(a, plan, topology, bytes);
}
fn expected(a: std.mem.Allocator, plan: *const Receiver.Plan) !@import("fold.zig").Digest {
    return plan.expectedRoot(a);
}
pub fn run(a: std.mem.Allocator, source: Runtime.SourceDirectory, metadata: Receiver.Metadata, plan: *const Receiver.Plan, topology: *const Topology, root: []const u8) !void {
    return Shared.run(a, source, metadata, plan, .{ .context = topology, .verify = verify, .expected = expected, .format = .r6 }, root, false);
}
pub fn runMiller(a: std.mem.Allocator, source: Runtime.SourceDirectory, metadata: Receiver.Metadata, plan: *const Receiver.Plan, topology: *const Topology, root: []const u8) !void {
    return Shared.run(a, source, metadata, plan, .{ .context = topology, .verify = verify, .expected = expected, .format = .r6 }, root, true);
}
