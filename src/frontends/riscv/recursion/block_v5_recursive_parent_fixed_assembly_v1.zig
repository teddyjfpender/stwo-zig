//! Original fixed lowering of all three parent verifier DAGs. This is assembly
//! work, not successful verification: no private evaluation or dummy capture.
//! The original compiled graphs must outlive this immutable borrowed plan.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Arena = @import("air/stable_graph_arena_v1.zig");
const PiecesModule = @import("block_v5_recursive_parent_fixed_pieces_v1.zig");
const Graph = @import("air/composition_circuit.zig").CircuitGraph;
const Lower = @import("air/verifier_arithmetic_lowering.zig");
const Fusion = @import("air/arithmetic_fusion_rows.zig");
const Ports = @import("air/block_v5_recursive_parent_fixed_pcs_ports_v1.zig");
const Storage = @import("air/blake3_parent_row_storage.zig");
const Boundary = @import("air/blake3_boundary.zig");
const M = @import("stwo_core").fields.m31.M31;
const Q = @import("stwo_core").fields.qm31.QM31;

/// Owns the exact original six-mode-lane Reference, original Plan and fused
/// opening/multiply-add/inverse/linear fixed columns. No main columns exist.
pub const Arithmetic = struct {
    allocator: std.mem.Allocator,
    lease: ?*Budget,
    arena: Arena.Owned,
    reference: Lower.Reference,
    plan: Lower.Plan,
    fused: Fusion.Fixed,
    boundaries: []Storage.FixedRow(Boundary),
    pub fn init(a: std.mem.Allocator, graphs: [3]Graph) !Arithmetic {
        const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
        errdefer if (lease) |owner| owner.destroy();
        var arena = try Arena.Owned.init(a);
        errdefer arena.deinit();
        const temp = arena.allocator();
        const lanes = try temp.alloc(Lower.Lane, 6);
        for (graphs, 0..) |graph, i| {
            try graph.validate();
            lanes[2 * i] = .{ .circuit_id = @intCast(1500 + 2 * i), .active_in = .segment, .circuit_identity = graph.identity_digest, .graph = graph };
            lanes[2 * i + 1] = lanes[2 * i];
            lanes[2 * i + 1].circuit_id += 1;
            lanes[2 * i + 1].active_in = .binary;
        }
        const reference = try Lower.Reference.seal(lanes);
        var plan = try Lower.Plan.init(a, reference);
        errdefer plan.deinit();
        var fused = try Fusion.materializeFixed(a, &plan, reference, .segment_leaf);
        errdefer fused.deinit();
        var boundaries: std.ArrayList(Storage.FixedRow(Boundary)) = .empty;
        for (plan.public_terms) |term| {
            if (term.active_in != .segment) continue;
            const weight = M.fromCanonical(term.multiplicity);
            try boundaries.append(temp, Storage.compactFixed(Boundary, try Boundary.logicalCoordinates(term.circuit_id, term.node_id, if (term.role == .emit) weight else weight.neg(), term.value.toM31Array())));
        }
        return .{ .allocator = a, .lease = lease, .arena = arena, .reference = reference, .plan = plan, .fused = fused, .boundaries = try boundaries.toOwnedSlice(temp) };
    }
    pub fn validate(self: *const Arithmetic) !void {
        try self.reference.validateAuthority();
        try self.plan.validateAgainst(self.reference);
    }
    pub fn deinit(self: *Arithmetic) void {
        const lease = self.lease;
        self.fused.deinit();
        self.plan.deinit();
        self.arena.deinit();
        self.* = undefined;
        if (lease) |owner| owner.destroy();
    }
};
/// Exact original active-selector supply shared by parent and native setup.
pub fn selectorsForGraphs(a: std.mem.Allocator, dg: *const @import("air/pcs_deep_circuit.zig").Circuit, fg: *const @import("air/fri_verifier_circuit.zig").Circuit) ![2]Storage.FixedRow(Boundary) {
    var selectors: [2]Storage.FixedRow(Boundary) = undefined;
    inline for (.{ dg.bindings, fg.bindings }, 0..) |bindings, i| {
        const scratch = try a.alloc(u32, (if (i == 0) dg.graph() else fg.graph()).nodes.len);
        defer a.free(scratch);
        const uses = try Lower.computeUseCountsInto(if (i == 0) dg.graph() else fg.graph(), scratch);
        var count: usize = 0;
        for (bindings) |binding| {
            if (binding.source != .active_selector) continue;
            if (count != 0) return error.InvalidNativeParentRows;
            selectors[i] = Storage.compactFixed(Boundary, try Boundary.logicalCoordinates(@intCast(1502 + 2 * i), binding.node_id, M.fromCanonical(uses[binding.node_id]), Q.one().toM31Array()));
            count += 1;
        }
        if (count != 1) return error.InvalidNativeParentRows;
    }
    return selectors;
}
/// New isolated orchestration uses the genuine admitted fixed-only Pieces.
/// Borrowed pieces/policy must stay immutable until this owner is destroyed.
/// It intentionally cannot emit a complete expected key until remaining exact
/// source and native-fusion ports have been assembled and independently checked.
pub fn ForAdmission(comptime Admission: type) type {
    comptime if (!@hasDecl(Admission, "fixed_setup_only") or !Admission.fixed_setup_only) @compileError("fixed compiler requires independently reconstructed setup-only admission");
    return struct {
        const Pieces = PiecesModule.ForAdmission(Admission);
        pub const Owned = struct {
            const Self = @This();
            allocator: std.mem.Allocator,
            lease: ?*Budget,
            shape_id: [32]u8,
            arithmetic: Arithmetic,
            pcs: *Ports.Owned,
            selectors: [2]Storage.FixedRow(Boundary),
            graph_ids: [3][32]u8,
            transcript_id: [32]u8,
            pub const complete_fixed_setup = false;
            pub const reusable_across_instances = false;
            pub const complete_block_authority = false;
            pub fn init(a: std.mem.Allocator, pieces: *const Pieces.Owned, admission: *const Admission) !*Self {
                try pieces.validateAgainst(admission);
                const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
                errdefer if (lease) |owner| owner.destroy();
                const self = try a.create(Self);
                errdefer a.destroy(self);
                const graphs = [3]Graph{ pieces.composition.circuit.graph(), pieces.arithmetic.deep_graph.graph(), pieces.arithmetic.fri_graph.graph() };
                var arithmetic = try Arithmetic.init(a, graphs);
                errdefer arithmetic.deinit();
                const pcs = try Ports.Owned.init(a, pieces.shape, &pieces.arithmetic.deep_graph, &pieces.arithmetic.fri_graph, &pieces.queries);
                errdefer pcs.deinit();
                const selectors = try selectorsForGraphs(a, &pieces.arithmetic.deep_graph, &pieces.arithmetic.fri_graph);
                self.* = .{ .allocator = a, .lease = lease, .shape_id = pieces.shape.seal, .arithmetic = arithmetic, .pcs = pcs, .selectors = selectors, .graph_ids = .{ graphs[0].identity_digest, graphs[1].identity_digest, graphs[2].identity_digest }, .transcript_id = pieces.transcript.fixed.id };
                return self;
            }
            pub fn validateAgainst(self: *const Self, pieces: *const Pieces.Owned, admission: *const Admission) !void {
                try pieces.validateAgainst(admission);
                try self.arithmetic.validate();
                try self.pcs.validateAgainst(pieces.shape, &pieces.arithmetic.deep_graph, &pieces.arithmetic.fri_graph, &pieces.queries);
                if (!std.meta.eql(self.shape_id, pieces.shape.seal) or !std.meta.eql(self.transcript_id, pieces.transcript.fixed.id)) return error.UntrustedRecursiveParentFixedAssembly;
                const graphs = [3]Graph{ pieces.composition.circuit.graph(), pieces.arithmetic.deep_graph.graph(), pieces.arithmetic.fri_graph.graph() };
                for (graphs, self.graph_ids) |graph, id| if (!std.meta.eql(graph.identity_digest, id)) return error.UntrustedRecursiveParentFixedAssembly;
            }
            pub fn requireComplete(_: *const Self) error{MissingRecursiveParentFixedPorts}!void {
                return error.MissingRecursiveParentFixedPorts;
            }
            pub fn deinit(self: *Self) void {
                const a = self.allocator;
                const lease = self.lease;
                self.pcs.deinit();
                self.arithmetic.deinit();
                a.destroy(self);
                if (lease) |owner| owner.destroy();
            }
        };
    };
}
const Default = ForAdmission(@import("block_v5_closed_input_request_shape_admission_v1.zig").Admission);
pub const Owned = Default.Owned;
