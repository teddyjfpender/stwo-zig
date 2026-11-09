//! The complete R7 receiver reuses the native source-image, terminal,
//! adjacency, manifest and RAM/KIO/Wire admission in Receiver.prepare.
const std = @import("std");
const Plan = @import("../pure_p2_op_root_receiver.zig").Plan;
const T = @import("execution_topology.zig").Topology;
const Fold = @import("fold.zig");
pub fn expectedRoot(a: std.mem.Allocator, plan: *const Plan) !Fold.Digest {
    const values = try plan.expectedLeaves(a);
    defer a.free(values);
    var n = values.len;
    if (n == 0) return error.R7TopologyCoverage;
    while (n > 1) {
        var next: usize = 0;
        var i: usize = 0;
        while (i + 1 < n) : (i += 2) {
            values[next] = try Fold.digest(values[i], values[i + 1]);
            next += 1;
        }
        if (i < n) {
            values[next] = values[i];
            next += 1;
        }
        n = next;
    }
    return values[0];
}
pub fn verifyPlan(a: std.mem.Allocator, plan: *const Plan, topology: *const T, bytes: []const u8) !void {
    if (!std.mem.eql(u8, &topology.execution, &plan.inventory.execution) or topology.bindings.len != plan.inventory.workers.len or topology.formats.len != topology.bindings.len) return error.R7TopologyCoverage;
    if (topology.profile != plan.inventory.workers[0].profile) return error.R7TopologyProfile;
    for (topology.bindings, topology.formats, plan.inventory.workers, 0..) |binding, format, expected, i| {
        const kind: @FieldType(@import("execution_source.zig").Binding, "kind") = if (i < plan.inventory.cpu_count) .cpu else if (i < plan.inventory.cpu_count + plan.inventory.truth_count) .catalog else .miller;
        if (binding.ordinal != i or binding.kind != kind or !std.mem.eql(u8, &binding.native_identity, &expected.fixed_identity)) return error.R7LeafSourceAuthority;
        if (i < plan.inventory.cpu_count) {
            if (format != .r7) return error.R7TopologyFormat;
        } else if (format != .r6) return error.R7TopologyFormat;
    }
    if (topology.final != .r7) return error.R7TopologyFormat;
    if (topology.final.profile() != topology.profile or topology.final.nOutputs() != 9) return error.R7TopologyProfile;
    try topology.final.verify(a, &try expectedRoot(a, plan), bytes);
}
