//! Complete root authentication for the explicit six-table outer schema.
const std = @import("std");
const Plan = @import("../pure_p2_op_root_receiver.zig").Plan;
const Topology = @import("topology.zig");
pub fn verifyPlan(a: std.mem.Allocator, plan: *const Plan, topology: *const Topology.Topology, bytes: []const u8) !void {
    if (!std.mem.eql(u8, &topology.execution, &plan.inventory.execution) or topology.leaf_count != plan.inventory.workers.len or topology.leaf_bindings.len != plan.inventory.workers.len) return error.OpRootTopologyCoverage;
    if (topology.profile != plan.inventory.workers[0].profile) return error.OpRootTopologyProfile;
    for (topology.leaf_bindings, plan.inventory.workers, 0..) |binding, expected, i| {
        const kind: @FieldType(Topology.Binding, "kind") = if (i < plan.inventory.cpu_count) .cpu else if (i < plan.inventory.cpu_count + plan.inventory.truth_count) .catalog else .miller;
        if (binding.ordinal != i or binding.kind != kind or !std.mem.eql(u8, &binding.native_identity, &expected.fixed_identity)) return error.OpRootLeafSourceAuthority;
    }
    const key = topology.key();
    if (key.base.n_outputs != 9 or key.base.profile != topology.profile) return error.OpRootTopologyProfile;
    const expected = try plan.expectedRoot(a);
    try @import("proof.zig").verify(a, key, &expected, bytes);
}
