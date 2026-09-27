//! Original DEEP/FRI operation DAGs and fixed arithmetic without witness values.
//! This is a partial setup artifact, not a complete parent key. Composition,
//! transcript, paths and public boundary still need their original compilers.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Shape = @import("../block_v5_recursive_parent_shape_v1.zig").Shape;
const deep = @import("pcs_deep_circuit.zig");
const fri = @import("fri_verifier_circuit.zig");
const lowering = @import("verifier_arithmetic_lowering.zig");
const fusion = @import("arithmetic_fusion_rows.zig");
pub const Limits = struct { max_inputs: usize = 1 << 24 };
pub const Owned = struct {
    allocator: std.mem.Allocator,
    budget: ?*Budget,
    shape_id: [32]u8,
    deep_graph: deep.Circuit,
    fri_graph: fri.Circuit,
    pub fn init(a: std.mem.Allocator, shape: *const Shape, limits: Limits) !*Owned {
        try shape.validate();
        const inputs = try std.math.add(usize, try shape.deepProfile().inputCount(), try fri.expectedInputCount(shape.friProfile()));
        if (inputs > limits.max_inputs) return error.RecursiveParentFixedArithmeticResourceLimit;
        const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
        errdefer if (lease) |owner| owner.destroy();
        const self = try a.create(Owned);
        errdefer a.destroy(self);
        var dg = try deep.build(a, shape.deepProfile());
        errdefer dg.deinit();
        const fg = try fri.build(a, shape.friProfile());
        self.* = .{ .allocator = a, .budget = lease, .shape_id = shape.seal, .deep_graph = dg, .fri_graph = fg };
        return self;
    }
    pub fn validateAgainst(self: *const Owned, shape: *const Shape) !void {
        try shape.validate();
        try self.deep_graph.validate();
        try self.fri_graph.validate();
        if (!std.meta.eql(self.shape_id, shape.seal) or
            !std.meta.eql(self.deep_graph.profile().identityDigest(), shape.deepProfile().identityDigest()) or
            !std.meta.eql(self.fri_graph.profile().identityDigest(), shape.friProfile().identityDigest()))
            return error.UntrustedRecursiveParentFixedArithmetic;
    }
    /// The enclosing original compiler supplies the COMPLETE reference with
    /// exact exports, namespaces and both proof modes. This wrapper refuses a
    /// reference which silently omits either original arithmetic graph.
    pub fn materializeFixed(self: *const Owned, a: std.mem.Allocator, plan: *const lowering.Plan, reference: lowering.Reference, kind: lowering.ProofKind) !fusion.Fixed {
        try self.deep_graph.validate();
        try self.fri_graph.validate();
        try reference.validateAuthority();
        var found_deep = false;
        var found_fri = false;
        const selected: lowering.Mode = switch (kind) {
            .segment_leaf => .segment,
            .binary_node => .binary,
            else => return error.UnsupportedArithmeticFusionKind,
        };
        for (reference.lanes) |lane| if (lane.active_in == selected) {
            found_deep = found_deep or std.meta.eql(lane.graph.identity_digest, self.deep_graph.graph_digest);
            found_fri = found_fri or std.meta.eql(lane.graph.identity_digest, self.fri_graph.graph_digest);
        };
        if (!found_deep or !found_fri) return error.MissingRecursiveParentFixedArithmetic;
        return fusion.materializeFixed(a, plan, reference, kind);
    }
    pub fn deinit(self: *Owned) void {
        const a = self.allocator;
        const lease = self.budget;
        self.fri_graph.deinit();
        self.deep_graph.deinit();
        a.destroy(self);
        if (lease) |owner| owner.destroy();
    }
};
