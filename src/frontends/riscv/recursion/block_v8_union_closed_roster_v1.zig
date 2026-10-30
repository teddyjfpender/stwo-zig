//! Independent fixed roster for original verifier plus constrained native /
//! provider closure. Existing V7 sources are reused without reinterpretation.
const std = @import("std");
const core = @import("stwo_core");
const Public = @import("block_v8_union_closed_public_v1.zig");
const Graph = @import("air/block_v8_union_closed_graph_v1.zig");
const V7 = @import("block_v7_union_fixed_roster_v1.zig");
const Attach = @import("air/block_v5_recursive_fixed_graph_attach_v1.zig");
const Namespace = @import("air/block_v5_recursive_fixed_namespace_v1.zig");
const Lower = @import("air/verifier_arithmetic_lowering.zig");
const Rebase = @import("air/blake3_parent_rebase.zig");
const Storage = @import("air/blake3_parent_row_storage.zig");
const LiveGraph = @import("air/block_v5_heterogeneous_scoped_graph_rows_v1.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
pub const Owned = struct {
    allocator: std.mem.Allocator,
    base: V7.Owned,
    closure: Attach.Owned,
    closure_namespace: Namespace.Plan,
    fixed: Storage.FixedTuple(false),
    wires: []Public.Wire,
    context: Base.Context,
    identity: [32]u8,
    pub fn derive(a: std.mem.Allocator, capsule: *const @import("block_v7_union_compiler_capsule_v1.zig").Capsule, graph: *const Graph.Prepared, capacity: u32, limits: V7.Limits) !Owned {
        var base = try V7.Owned.deriveFromCapsule(a, capsule, capacity, limits);
        errdefer base.deinit();
        var closure = try Attach.Owned.derive(a, &graph.circuit, graph.sources);
        errdefer closure.deinit();
        const lane = Lower.Lane{ .circuit_id = Attach.CIRCUIT, .active_in = .segment, .circuit_identity = graph.circuit.identity_digest, .graph = graph.circuit.graph() };
        var binary = lane;
        binary.circuit_id += 1;
        binary.active_in = .binary;
        const lanes = [_]Lower.Lane{ lane, binary };
        const reference = try Lower.Reference.seal(&lanes);
        var lowering = try Lower.Plan.init(a, reference);
        defer lowering.deinit();
        var closure_namespace = try Namespace.prepareForArithmetic(a, closure.fixed, try base.namespace.end(), .{ .plan = &lowering, .reference = reference, .kind = .segment_leaf });
        errdefer closure_namespace.deinit();
        try closure_namespace.requireIndependentMainPort();
        try Namespace.apply(&base.fixed, &base.namespace, try base.namespace.identity());
        try Namespace.apply(&closure.fixed, &closure_namespace, try closure_namespace.identity());
        var fixed: Storage.FixedTuple(false) = undefined;
        inline for (0..Storage.Airs.len) |air| fixed[air] = &.{};
        errdefer inline for (0..Storage.Airs.len) |air| a.free(fixed[air]);
        inline for (Storage.Airs, 0..) |Air, air| {
            fixed[air] = try a.alloc(Storage.FixedRow(Air), try std.math.add(usize, base.fixed[air].len, closure.fixed[air].len));
            @memcpy(fixed[air][0..base.fixed[air].len], base.fixed[air]);
            @memcpy(fixed[air][base.fixed[air].len..], closure.fixed[air]);
        }
        const wires = try a.alloc(Public.Wire, try std.math.add(usize, base.wires.len, closure.wires.len));
        errdefer a.free(wires);
        for (wires[0..base.wires.len], base.wires) |*out, original| {
            var wire = original;
            wire.circuit = base.namespace.original.map(wire.circuit) orelse return error.MissingClosedUnionNamespace;
            out.* = .{ .original = wire };
        }
        for (wires[base.wires.len..], closure.wires) |*out, original| {
            var wire = original;
            wire.circuit = closure_namespace.original.map(wire.circuit) orelse return error.MissingClosedUnionNamespace;
            out.* = .{ .closure = wire };
        }
        sort(wires);
        _ = try Public.scheduleDigest(wires);
        var id = core.proof_suites.Blake3.Channel{};
        id.mixU32s(&.{ 0x42384346, 1 });
        id.mixRoot(capsule.profile().seal);
        id.mixRoot(graph.circuit.identity_digest);
        id.mixRoot(closure.identity);
        id.mixRoot(try base.namespace.identity());
        id.mixRoot(try closure_namespace.identity());
        const identity = id.digestBytes();
        var context = base.context;
        context.child_key_id = identity;
        return .{ .allocator = a, .base = base, .closure = closure, .closure_namespace = closure_namespace, .fixed = fixed, .wires = wires, .context = context, .identity = identity };
    }
    pub fn deinit(self: *Owned) void {
        inline for (0..Storage.Airs.len) |air| self.allocator.free(self.fixed[air]);
        self.allocator.free(self.wires);
        self.closure_namespace.deinit();
        self.closure.deinit();
        self.base.deinit();
        self.* = undefined;
    }
    /// Independent raw source admission precedes rebasing. Actual closure
    /// MAIN columns are materialized and every final fixed row is compared.
    pub fn attach(self: *const Owned, a: std.mem.Allocator, ready: *@import("block_v7_union_preparation_v1.zig").Prepared, graph: *const Graph.Prepared, values: Public.Values) ![]Public.Wire {
        if (!std.meta.eql(ready.recursive.context, self.base.context) or ready.wires.len != self.base.wires.len) return error.UntrustedClosedUnionSource;
        for (ready.wires, self.base.wires) |actual, expected| if (!std.meta.eql(actual, expected)) return error.UntrustedClosedUnionSource;
        try ready.recursive.rows.partitionHashRows();
        try self.base.namespace.validateLive(&ready.recursive.rows);
        var lowered = try LiveGraph.materializeLocallyAdmittedFor(a, graph.graph(), Public.ClosureView{ .values = values });
        defer lowered.deinit();
        try self.closure_namespace.validateLive(&lowered.rows);
        const wires = try a.alloc(Public.Wire, try std.math.add(usize, ready.wires.len, lowered.wires.len));
        errdefer a.free(wires);
        for (wires[0..ready.wires.len], ready.wires) |*out, original| {
            var wire = original;
            wire.circuit = self.base.namespace.original.map(wire.circuit) orelse return error.MissingClosedUnionNamespace;
            out.* = .{ .original = wire };
        }
        for (wires[ready.wires.len..], lowered.wires) |*out, original| {
            var wire = original;
            wire.circuit = self.closure_namespace.original.map(wire.circuit) orelse return error.MissingClosedUnionNamespace;
            out.* = .{ .closure = wire };
        }
        sort(wires);
        if (wires.len != self.wires.len) return error.UntrustedClosedUnionSchedule;
        for (wires, self.wires) |actual, expected| if (!std.meta.eql(actual, expected)) return error.UntrustedClosedUnionSchedule;
        try Rebase.apply(&ready.recursive.rows, &self.base.namespace.original, try self.base.namespace.identity());
        try Rebase.apply(&lowered.rows, &self.closure_namespace.original, try self.closure_namespace.identity());
        const joined = try @import("air/blake3_parent_join.zig").joinDraining(a, &ready.recursive.rows, &lowered.rows, .{
            .{ .first = 1, .end = try self.base.namespace.end() },
            .{ .first = try self.base.namespace.end(), .end = try self.closure_namespace.end() },
        });
        ready.recursive.rows.deinit();
        ready.recursive.rows = joined;
        ready.recursive.context = self.context;
        inline for (0..Storage.Airs.len) |air| {
            if (self.fixed[air].len != ready.recursive.rows.fixed[air].len) return error.UntrustedClosedUnionFixedRows;
            for (self.fixed[air], ready.recursive.rows.fixed[air]) |expected, actual| if (!std.meta.eql(expected, actual)) return error.UntrustedClosedUnionFixedRows;
        }
        return wires;
    }
};
fn sort(wires: []Public.Wire) void {
    std.mem.sort(Public.Wire, wires, {}, struct {
        fn less(_: void, left: Public.Wire, right: Public.Wire) bool {
            return Public.circuit(left) < Public.circuit(right) or Public.circuit(left) == Public.circuit(right) and Public.node(left) < Public.node(right);
        }
    }.less);
}
