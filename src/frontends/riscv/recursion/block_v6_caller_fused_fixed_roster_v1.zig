//! Complete original B5CF fixed roster from independent admitted metadata.
//! Private claims and roots are public wire inputs; no capture/proof is used.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Admission = @import("../prover/block_v5_caller_fused_recursive_admission_v1.zig");
const Native = @import("block_v6_caller_fused_fixed_v1.zig");
const Transcript = @import("block_v6_caller_fused_fixed_transcript_v1.zig");
const Shape = @import("block_v6_caller_fused_fixed_profile_v1.zig").Profile;
const Bus = @import("block_v5_caller_fused_recursive_public_bus_v1.zig");
const Statement = @import("air/block_v5_caller_fused_statement_v1.zig");
const Sources = @import("air/block_v5_recursive_parent_fixed_sources_v1.zig").ForPieces(void).Owned;
const Pcs = @import("block_v5_native_recursive_fixed_pcs_v1.zig").ForCommitments(5).Owned;
const Assembly = @import("block_v5_recursive_parent_fixed_assembly_v1.zig");
const Roster = @import("block_v5_recursive_parent_fixed_roster_v1.zig");
const Storage = @import("air/blake3_parent_row_storage.zig");
const Namespace = @import("air/block_v5_recursive_fixed_namespace_v1.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
pub const Limits = struct { max_bytes: usize = 2 << 30, native: Native.Limits = .{}, transcript: @import("air/blake3_fixed_operation_recorder_v1.zig").Limits = .{} };
pub const Owned = struct {
    allocator: std.mem.Allocator,
    budget: *Budget,
    fixed: Storage.FixedTuple(false),
    wires: []Bus.Wire,
    context: Base.Context,
    namespace: Namespace.Plan,
    pub const fixed_setup_only = true;
    pub const complete_family_setup = true;
    pub const whole_family_live_parity_qualified = false;
    pub const complete_block_authority = false;
    pub fn derive(backing: std.mem.Allocator, admitted: *const Admission.Prepared, claims: Native.Claims, capacity: u32, profile: Base.Profile, limits: Limits) !Owned {
        if (limits.max_bytes == 0 or capacity == 0 or !std.meta.eql(admitted.config, profile.config())) return error.CallerFusedFixedRosterResourceLimit;
        try admitted.validate(admitted.template_id);
        const budget = try Budget.createRetainingParent(backing, limits.max_bytes);
        errdefer budget.destroy();
        const a = budget.allocator();
        const native = try Native.Owned.derive(a, admitted, claims, limits.native);
        defer native.deinit();
        var transcript = try Transcript.derive(a, admitted, claims, native, capacity, limits.transcript, limits.native);
        defer transcript.deinit();
        var shape = try Shape.derive(native, admitted, claims, limits.native);
        const pcs = try Pcs.compile(a, &shape, &native.deep_graph, &native.fri_graph, &transcript);
        defer pcs.deinit();
        const sources = try Sources.compileCallerFused(a, &shape, &native.composition, &native.deep_graph, &native.fri_graph, &transcript);
        defer sources.deinit();
        const selectors = try Assembly.selectorsForGraphs(a, &native.deep_graph, &native.fri_graph);
        const fixed = try Roster.compileOriginalRoster(a, sources, null, pcs.openings, pcs.ports, &transcript, &pcs.paths, &native.arithmetic, selectors, &native.deep_graph);
        errdefer inline for (0..Storage.Airs.len) |i| a.free(fixed[i]);
        var namespace = try Namespace.prepareForArithmetic(a, fixed, 1, .{ .plan = &native.arithmetic.plan, .reference = native.arithmetic.reference, .kind = .segment_leaf });
        errdefer namespace.deinit();
        try namespace.requireIndependentMainPort();
        var statement = try Statement.initClaims(a, admitted, claims);
        defer statement.deinit();
        const public_count = try @import("air/block_v5_caller_fused_composition_v1.zig").publicCount(admitted.schedule.program.len, admitted.schedule.tables.len, admitted.schedule.memory.len);
        const wires = try Bus.API.collectFixedSchedule(a, &transcript, &native.composition, statement.words.len, public_count, 3, @intCast(admitted.config.fri_config.n_queries), admitted.limits.max_public_wires);
        errdefer a.free(wires);
        const context = Base.Context{ .child_key_id = admitted.template_id, .child_config = admitted.config, .graph_ids = .{ native.composition.circuit.identity_digest, native.deep_graph.graph().identity_digest, native.fri_graph.graph().identity_digest }, .transcript_plan_id = transcript.id };
        _ = try Base.contextIdentity(context);
        return .{ .allocator = a, .budget = budget, .fixed = fixed, .wires = wires, .context = context, .namespace = namespace };
    }
    pub fn validateLive(self: *const Owned, live: *Bus.Prepared) !void {
        try live.recursive.rows.partitionHashRows();
        try self.namespace.validateLive(&live.recursive.rows);
        if (!std.meta.eql(self.context, live.recursive.context) or self.wires.len != live.wires.len) return error.UntrustedCallerFusedFixedRoster;
        for (self.wires, live.wires) |want, got| if (!std.meta.eql(want, got)) return error.UntrustedCallerFusedFixedRoster;
        inline for (0..Storage.Airs.len) |i| {
            if (self.fixed[i].len != live.recursive.rows.fixed[i].len) return error.UntrustedCallerFusedFixedRoster;
            for (self.fixed[i], live.recursive.rows.fixed[i]) |want, got| if (!std.meta.eql(want, got)) return error.UntrustedCallerFusedFixedRoster;
        }
    }
    pub fn deinit(self: *Owned) void {
        const budget = self.budget;
        self.namespace.deinit();
        self.allocator.free(self.wires);
        inline for (0..Storage.Airs.len) |i| self.allocator.free(self.fixed[i]);
        self.* = undefined;
        budget.destroy();
    }
};
