//! Original native B6JP fixed roster, derived without proof or private witness.
//! Full mixed-key authority additionally requires canonical mixed joining and
//! live/fixed parity qualification. This factory emits no verifier-success token.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Native = @import("block_v6_partitioned_recursive_fixed_v1.zig");
const Admission = @import("../prover/block_v6_partitioned_recursive_admission_v1.zig");
const Bus = @import("block_v6_partitioned_public_bus_v1.zig");
const Transcript = @import("block_v6_partitioned_fixed_transcript_v1.zig");
const Profile = @import("block_v6_partitioned_fixed_profile_v1.zig");
const Pcs = @import("block_v5_native_recursive_fixed_pcs_v1.zig");
const Sources = @import("air/block_v5_recursive_parent_fixed_sources_v1.zig");
const Original = @import("block_v5_recursive_parent_fixed_roster_v1.zig");
const Assembly = @import("block_v5_recursive_parent_fixed_assembly_v1.zig");
const Namespace = @import("air/block_v5_recursive_fixed_namespace_v1.zig");
const Storage = @import("air/blake3_parent_row_storage.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
pub const Limits = struct { max_bytes: usize = 2 << 30, native: Native.Limits = .{}, transcript: Transcript.Limits = .{} };
pub const Owned = struct {
    allocator: std.mem.Allocator,
    budget: *Budget,
    fixed: Storage.FixedTuple(false),
    wires: []Bus.Wire,
    context: Base.Context,
    namespace: Namespace.Plan,
    retry_capacity: u32,
    profile: Base.Profile,
    pub const fixed_setup_only = true;
    pub const complete_family_setup = true;
    pub const whole_family_live_parity_qualified = false;
    pub const complete_block_authority = false;
    pub fn derive(backing: std.mem.Allocator, admitted: *const Admission.Prepared, claims: Bus.Claims, capacity: u32, profile: Base.Profile, limits: Limits) !Owned {
        if (capacity == 0 or limits.max_bytes == 0 or !std.meta.eql(admitted.config, profile.config())) return error.PartitionedFixedRosterPolicy;
        try admitted.validate(admitted.template_id);
        return if (admitted.tree_count == 3) deriveFor(4, backing, admitted, claims, capacity, profile, limits) else if (admitted.tree_count == 4) deriveFor(5, backing, admitted, claims, capacity, profile, limits) else error.InvalidPartitionedFixedGeometry;
    }
    fn deriveFor(comptime N: usize, backing: std.mem.Allocator, admitted: *const Admission.Prepared, claims: Bus.Claims, capacity: u32, profile: Base.Profile, limits: Limits) !Owned {
        @setEvalBranchQuota(30_000);
        const budget = try Budget.createRetainingParent(backing, limits.max_bytes);
        errdefer budget.destroy();
        const a = budget.allocator();
        const native = try Native.Owned.derive(a, admitted, claims, limits.native);
        defer native.deinit();
        var transcript = try Transcript.derive(a, admitted, claims, native, capacity, limits.transcript, limits.native);
        defer transcript.deinit();
        var shape = try Profile.ForCommitments(N).derive(native, admitted, claims, limits.native);
        const pcs = try Pcs.ForCommitments(N).Owned.compile(a, &shape, &native.deep_graph, &native.fri_graph, &transcript);
        defer pcs.deinit();
        const composition = .{ .circuit = native.composition, .sources = native.sources };
        const sources = try Sources.Owned.compileNativePartitioned(a, &shape, &composition, &native.deep_graph, &native.fri_graph, &transcript);
        defer sources.deinit();
        const selectors = try Assembly.selectorsForGraphs(a, &native.deep_graph, &native.fri_graph);
        const fixed = try Original.compileOriginalRoster(a, sources, null, pcs.openings, pcs.ports, &transcript, &pcs.paths, &native.arithmetic, selectors, &native.deep_graph);
        errdefer inline for (0..Storage.Airs.len) |i| a.free(fixed[i]);
        const extent = try @import("air/block_v6_partitioned_statement_v1.zig").extent(admitted);
        const wires = try Bus.API.collectFixedSchedule(a, &transcript, &composition, extent.words, extent.public_inputs, admitted.tree_count - 1, @intCast(admitted.config.fri_config.n_queries), admitted.limits.max_public_wires);
        errdefer a.free(wires);
        var namespace = try Namespace.prepareForArithmetic(a, fixed, 1, .{ .plan = &native.arithmetic.plan, .reference = native.arithmetic.reference, .kind = .segment_leaf });
        errdefer namespace.deinit();
        try namespace.requireIndependentMainPort();
        const context = Base.Context{ .child_key_id = admitted.template_id, .child_config = admitted.config, .graph_ids = .{ native.composition.identity_digest, native.deep_graph.graph().identity_digest, native.fri_graph.graph().identity_digest }, .transcript_plan_id = transcript.id };
        _ = try Base.contextIdentity(context);
        _ = try Bus.scheduleDigest(wires);
        try admitted.validate(admitted.template_id);
        return .{ .allocator = a, .budget = budget, .fixed = fixed, .wires = wires, .context = context, .namespace = namespace, .retry_capacity = capacity, .profile = profile };
    }
    pub fn validateLive(self: *const Owned, live: *Bus.Prepared) !void {
        try live.recursive.rows.partitionHashRows();
        if (!std.meta.eql(self.context, live.recursive.context) or self.wires.len != live.wires.len) return error.UntrustedPartitionedFixedRoster;
        for (self.wires, live.wires) |got, want| if (!std.meta.eql(got, want)) return error.UntrustedPartitionedFixedRoster;
        inline for (0..Storage.Airs.len) |i| {
            if (self.fixed[i].len != live.recursive.rows.fixed[i].len) return error.UntrustedPartitionedFixedRoster;
            for (self.fixed[i], live.recursive.rows.fixed[i]) |got, want| if (!std.meta.eql(got, want)) return error.UntrustedPartitionedFixedRoster;
        }
        try self.namespace.validateLive(&live.recursive.rows);
    }
    pub fn deinit(self: *Owned) void {
        const a = self.allocator;
        const budget = self.budget;
        self.namespace.deinit();
        a.free(self.wires);
        inline for (0..Storage.Airs.len) |i| a.free(self.fixed[i]);
        self.* = undefined;
        budget.destroy();
    }
};
test "partitioned cold complete fixed roster codegen" {
    std.mem.doNotOptimizeAway(&Owned.derive);
    std.mem.doNotOptimizeAway(&Owned.validateLive);
}
