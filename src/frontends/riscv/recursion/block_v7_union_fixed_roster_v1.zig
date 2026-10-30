//! Capture-free complete verifier rows for one joined original. This factory
//! accepts independently pinned metadata and proposed physical claims, never
//! live rows, a proof capture, or a producer-nominated verifier key.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Profile = @import("block_v7_union_fixed_profile_v1.zig").ForMode(true);
const Multi = @import("../prover/block_v7_multi_union_proof_v1.zig").ForMode(true);
const Public = @import("block_v7_union_public_v1.zig");
const Storage = @import("air/blake3_parent_row_storage.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
const Namespace = @import("air/block_v5_recursive_fixed_namespace_v1.zig");
const Assembly = @import("block_v5_recursive_parent_fixed_assembly_v1.zig");
pub const Limits = struct { max_bytes: usize = 8 << 30, max_public_wires: usize = 1 << 20, transcript: @import("air/blake3_fixed_operation_recorder_v1.zig").Limits = .{} };
pub const Owned = struct {
    allocator: std.mem.Allocator,
    budget: *Budget,
    fixed: Storage.FixedTuple(false),
    wires: []Public.Wire,
    context: Base.Context,
    namespace: Namespace.Plan,
    pub fn derive(backing: std.mem.Allocator, original: *const Profile.Owned, claims: *const Multi.Claims, capacity: u32, limits: Limits) !Owned {
        if (limits.max_bytes == 0 or limits.max_public_wires == 0 or capacity == 0) return error.UnionFixedResourceLimit;
        const budget = try Budget.createRetainingParent(backing, limits.max_bytes);
        errdefer budget.destroy();
        const a = budget.allocator();
        var profile = try @import("block_v7_union_pcs_profile_v1.zig").View.init(original, claims);
        var composition = try @import("air/block_v7_union_composition_v1.zig").compile(a, original, claims);
        defer composition.deinit();
        var deep = try @import("air/pcs_deep_circuit.zig").build(a, profile.deepProfile());
        defer deep.deinit();
        var fri = try @import("air/fri_verifier_circuit.zig").build(a, profile.friProfile());
        defer fri.deinit();
        var arithmetic = try Assembly.Arithmetic.init(a, .{ composition.circuit.graph(), deep.graph(), fri.graph() });
        defer arithmetic.deinit();
        return finish(a, budget, &profile, original, claims, capacity, limits, &composition, &deep, &fri, &arithmetic, null);
    }
    pub fn deriveFromCapsule(backing: std.mem.Allocator, capsule: *const @import("block_v7_union_compiler_capsule_v1.zig").Capsule, capacity: u32, limits: Limits) !Owned {
        if (limits.max_bytes == 0 or limits.max_public_wires == 0 or capacity == 0) return error.UnionFixedResourceLimit;
        const budget = try Budget.createRetainingParent(backing, limits.max_bytes);
        errdefer budget.destroy();
        var profile = try @import("block_v7_union_pcs_profile_v1.zig").FrozenView.init(capsule);
        const c = capsule.compiler();
        return finish(budget.allocator(), budget, &profile, capsule.profile(), &c.claims, capacity, limits, &c.composition, &c.deep, &c.fri, &c.arithmetic, capsule);
    }
    fn finish(a: std.mem.Allocator, budget: *Budget, profile: anytype, original: *const Profile.Owned, claims: *const Multi.Claims, capacity: u32, limits: Limits, composition: *const @import("air/block_v7_union_composition_v1.zig").Compiled, deep: *const @import("air/pcs_deep_circuit.zig").Circuit, fri: *const @import("air/fri_verifier_circuit.zig").Circuit, arithmetic: *const Assembly.Arithmetic, capsule: ?*const @import("block_v7_union_compiler_capsule_v1.zig").Capsule) !Owned {
        var transcript = if (capsule) |c| try @import("air/block_v7_union_transcript_v1.zig").fixedFromFrame(a, original, &c.compiler().values.statement, capacity, limits.transcript) else try @import("air/block_v7_union_transcript_v1.zig").fixed(a, original, claims, capacity, limits.transcript);
        defer transcript.deinit();
        var queries = try @import("air/blake3_query_links.zig").build(a, transcript.fixed.query_outputs, deep, fri, profile.config.fri_config.n_queries, profile.widths.len);
        defer queries.deinit();
        var paths = try @import("air/blake3_stark_paths.zig").compileBoundedProfile(profile.columns.len, a, profile, &queries);
        defer paths.deinit();
        const ports = try @import("air/block_v5_recursive_parent_fixed_pcs_ports_v1.zig").compileBoundedProfile(profile.columns.len, a, profile, deep, fri, &queries);
        defer ports.deinit();
        const openings = try @import("air/block_v5_recursive_parent_fixed_openings_v1.zig").compileBoundedProfile(profile.columns.len, a, profile, deep, fri, &paths, &ports.projection);
        defer openings.deinit();
        const sources = try @import("air/block_v5_recursive_parent_fixed_sources_v1.zig").ForPieces(void).Owned.compileUnion(a, profile, composition, deep, fri, &transcript);
        defer sources.deinit();
        const selectors = try Assembly.selectorsForGraphs(a, deep, fri);
        const fixed = try @import("block_v5_recursive_parent_fixed_roster_v1.zig").compileOriginalRoster(a, sources, null, openings, ports, &transcript, &paths, arithmetic, selectors, deep);
        errdefer inline for (0..Storage.Airs.len) |i| a.free(fixed[i]);
        var namespace = try Namespace.prepareForArithmetic(a, fixed, 1, .{ .plan = &arithmetic.plan, .reference = arithmetic.reference, .kind = .segment_leaf });
        errdefer namespace.deinit();
        try namespace.requireIndependentMainPort();
        var values = if (capsule) |c| try c.values(a) else try Public.reconstruct(a, original, claims);
        defer values.deinit();
        const reads = try a.alloc(u32, profile.initial_roots);
        defer a.free(reads);
        for (reads, profile.columns[0..reads.len]) |*count, columns| count.* = if (columns.len == 0) 0 else @intCast(profile.config.fri_config.n_queries);
        const wires = try Public.API.collectFixedSchedulePerTree(a, &transcript, composition, values.statement.words.len, values.public.len, reads, limits.max_public_wires);
        errdefer a.free(wires);
        const context = Base.Context{ .child_key_id = profile.seal, .child_config = profile.config, .graph_ids = .{ composition.circuit.identity_digest, deep.graph().identity_digest, fri.graph().identity_digest }, .transcript_plan_id = transcript.id };
        _ = try Base.contextIdentity(context);
        return .{ .allocator = a, .budget = budget, .fixed = fixed, .wires = wires, .context = context, .namespace = namespace };
    }
    pub fn validateLive(self: *const Owned, live: *@import("block_v7_union_preparation_v1.zig").Prepared) !void {
        try live.recursive.rows.partitionHashRows();
        try self.namespace.validateLive(&live.recursive.rows);
        if (!std.meta.eql(self.context, live.recursive.context) or self.wires.len != live.wires.len) return error.UntrustedUnionFixedRoster;
        for (self.wires, live.wires) |got, want| if (!std.meta.eql(got, want)) return error.UntrustedUnionFixedRoster;
        inline for (0..Storage.Airs.len) |i| {
            if (self.fixed[i].len != live.recursive.rows.fixed[i].len) return error.UntrustedUnionFixedRoster;
            for (self.fixed[i], live.recursive.rows.fixed[i]) |got, want| if (!std.meta.eql(got, want)) return error.UntrustedUnionFixedRoster;
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
