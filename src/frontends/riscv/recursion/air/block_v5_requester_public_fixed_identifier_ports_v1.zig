//! Original identifier-only fusion port for already authenticated graphs.
//! No private evaluations/main columns or proposed identifier arrays are read.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Arena = @import("stable_graph_arena_v1.zig").Owned;
const Graph = @import("composition_circuit.zig").CircuitGraph;
const Lower = @import("verifier_arithmetic_lowering.zig");
const Namespace = @import("block_v5_recursive_fixed_namespace_v1.zig");
pub const Owned = struct {
    allocator: std.mem.Allocator,
    lease: ?*Budget,
    arena: Arena,
    reference: Lower.Reference,
    plan: Lower.Plan,
    /// Graph owners must remain live and immutable until this port is destroyed.
    pub fn init(a: std.mem.Allocator, graphs: []const Graph, circuits: []const u32) !Owned {
        if (graphs.len == 0 or graphs.len > 3 or graphs.len != circuits.len) return error.InvalidRequesterPublicIdentifierPorts;
        const lease = if (Budget.fromAllocator(a)) |budget| budget.retain() else null;
        errdefer if (lease) |budget| budget.destroy();
        var arena = try Arena.init(a);
        errdefer arena.deinit();
        const lanes = try arena.allocator().alloc(Lower.Lane, 2 * graphs.len);
        for (graphs, circuits, 0..) |graph, circuit, i| {
            try graph.validate();
            if (circuit == 0 or circuit >= @import("stwo_core").fields.m31.Modulus - 1) return error.InvalidRequesterPublicIdentifierPorts;
            lanes[2 * i] = .{ .circuit_id = circuit, .active_in = .segment, .circuit_identity = graph.identity_digest, .graph = graph };
            lanes[2 * i + 1] = lanes[2 * i];
            lanes[2 * i + 1].circuit_id += 1;
            lanes[2 * i + 1].active_in = .binary;
        }
        const reference = try Lower.Reference.seal(lanes);
        var plan = try Lower.Plan.init(a, reference);
        errdefer plan.deinit();
        return .{ .allocator = a, .lease = lease, .arena = arena, .reference = reference, .plan = plan };
    }
    pub fn port(self: *const Owned) !Namespace.ArithmeticPort {
        try self.reference.validateAuthority();
        try self.plan.validateAgainst(self.reference);
        return .{ .plan = &self.plan, .reference = self.reference, .kind = .segment_leaf };
    }
    pub fn deinit(self: *Owned) void {
        const lease = self.lease;
        self.plan.deinit();
        self.arena.deinit();
        self.* = undefined;
        if (lease) |budget| budget.destroy();
    }
};
