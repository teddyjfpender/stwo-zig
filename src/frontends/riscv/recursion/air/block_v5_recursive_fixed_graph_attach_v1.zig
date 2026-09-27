//! Fixed-only counterpart of the ORIGINAL scoped graph lowering. The graph and
//! its public source descriptors must be independently reconstructed by policy.
//! No evaluation, proof capture, graph success token or MAIN columns exist here.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Circuit = @import("composition_graph_recorder.zig").Circuit;
const Lower = @import("verifier_arithmetic_lowering.zig");
const Fusion = @import("arithmetic_fusion_rows.zig");
const Original = @import("block_v5_heterogeneous_scoped_graph_rows_v1.zig");
const Storage = @import("blake3_parent_row_storage.zig");
const Bus = @import("../block_v5_heterogeneous_scoped_public_bus_v1.zig");
const Boundary = @import("blake3_boundary.zig");
pub const CIRCUIT = Original.CIRCUIT;
pub const Owned = struct {
    allocator: std.mem.Allocator,
    lease: ?*Budget,
    fixed: Storage.FixedTuple(false),
    wires: []Bus.Wire,
    identity: [32]u8,
    pub fn derive(a: std.mem.Allocator, graph: *const Circuit, sources: []const Bus.Wire) !Owned {
        try graph.validate();
        if (sources.len != graph.input_count) return error.InvalidHeterogeneousGraphShape;
        const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
        errdefer if (lease) |owner| owner.destroy();
        var fixed: Storage.FixedTuple(false) = undefined;
        inline for (0..Storage.Airs.len) |i| fixed[i] = &.{};
        errdefer inline for (0..Storage.Airs.len) |i| a.free(fixed[i]);
        const lane = Lower.Lane{ .circuit_id = CIRCUIT, .active_in = .segment, .circuit_identity = graph.identity_digest, .graph = graph.graph() };
        var binary = lane;
        binary.circuit_id += 1;
        binary.active_in = .binary;
        const lanes = [_]Lower.Lane{ lane, binary };
        const reference = try Lower.Reference.seal(&lanes);
        var plan = try Lower.Plan.init(a, reference);
        defer plan.deinit();
        var fused = try Fusion.materializeFixed(a, &plan, reference, .segment_leaf);
        defer fused.deinit();
        inline for (.{ 18, 3, 4, 5 }, 0..) |slot, i| fixed[slot] = try a.dupe(Storage.FixedRow(Storage.Airs[slot]), fused.fixed[i]);
        var boundaries: std.ArrayList(Storage.FixedRow(Boundary)) = .empty;
        defer boundaries.deinit(a);
        for (plan.public_terms) |term| if (term.active_in == .segment) {
            if (term.role == .request) return error.InvalidHeterogeneousGraphBoundary;
            const weight = core.fields.m31.M31.fromCanonical(term.multiplicity);
            try boundaries.append(a, Storage.compactFixed(Boundary, try Boundary.logicalCoordinates(term.circuit_id, term.node_id, if (term.role == .emit) weight else weight.neg(), term.value.toM31Array())));
        };
        fixed[2] = try boundaries.toOwnedSlice(a);
        const counts = try a.alloc(u32, graph.nodes.len);
        defer a.free(counts);
        const uses = try Lower.computeLaneUseCountsInto(lane, counts);
        var wires: std.ArrayList(Bus.Wire) = .empty;
        defer wires.deinit(a);
        for (sources, 0..) |source, node| if (uses[node] != 0) {
            var wire = source;
            wire.circuit = CIRCUIT;
            wire.wire = @intCast(node);
            wire.uses = uses[node];
            wire.negative = false;
            try wires.append(a, wire);
        };
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x42355a45, 1, CIRCUIT });
        channel.mixRoot(graph.identity_digest);
        channel.mixRoot(reference.authority_digest);
        for (sources) |source| channel.mixU32s(&.{ @intFromEnum(source.kind), source.child, source.coordinate, if (source.part) |part| part else 4 });
        return .{ .allocator = a, .lease = lease, .fixed = fixed, .wires = try wires.toOwnedSlice(a), .identity = channel.digestBytes() };
    }
    /// Compare against original actual row emission in a pure graph fixture.
    /// This is a parity check; it grants no cryptographic graph authority.
    pub fn validateLive(self: *const Owned, live: *const Original.Lowered) !void {
        if (!std.meta.eql(self.identity, live.identity) or self.wires.len != live.wires.len) return error.UntrustedRecursiveFixedGraph;
        for (self.wires, live.wires) |actual, expected| if (!std.meta.eql(actual, expected)) return error.UntrustedRecursiveFixedGraph;
        inline for (0..Storage.Airs.len) |i| {
            if (self.fixed[i].len != live.rows.fixed[i].len) return error.UntrustedRecursiveFixedGraph;
            for (self.fixed[i], live.rows.fixed[i]) |actual, expected| if (!std.meta.eql(actual, expected)) return error.UntrustedRecursiveFixedGraph;
        }
    }
    pub fn deinit(self: *Owned) void {
        const lease = self.lease;
        inline for (0..Storage.Airs.len) |i| self.allocator.free(self.fixed[i]);
        self.allocator.free(self.wires);
        self.* = undefined;
        if (lease) |owner| owner.destroy();
    }
};
