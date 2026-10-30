//! Complete independent fixed rows for a four/five-commitment v7 native child.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Profile = @import("block_v7_native_fixed_profile_v1.zig");
const Public = @import("block_v7_native_public_v1.zig");
const Protocol = @import("block_v7_native_parent_protocol_v1.zig");
const Storage = @import("air/blake3_parent_row_storage.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
const Namespace = @import("air/block_v5_recursive_fixed_namespace_v1.zig");
const Capsule = @import("block_v7_native_compiler_capsule_v1.zig").Capsule;
const Assembly = @import("block_v5_recursive_parent_fixed_assembly_v1.zig");
pub const Limits = struct { shared_epoch: bool = false, max_bytes: usize = 4 << 30, max_public_wires: usize = 1 << 20, transcript: @import("air/blake3_fixed_operation_recorder_v1.zig").Limits = .{} };
pub const Owned = struct {
    shared_epoch: ?@import("air/blake3_transcript_witness.zig").StatePorts = null,
    allocator: std.mem.Allocator,
    budget: *Budget,
    fixed: Storage.FixedTuple(false),
    wires: []Public.Wire,
    context: Base.Context,
    namespace: Namespace.Plan,
    pub fn derive(a: std.mem.Allocator, profile: *const Profile.Owned, claims: Public.Claims, capacity: u32, limits: Limits) !Owned {
        return switch (profile.trace_count) {
            3 => deriveFor(4, a, profile, claims, capacity, limits),
            4 => deriveFor(5, a, profile, claims, capacity, limits),
            else => error.InvalidNativeFixedCommitments,
        };
    }
    pub fn deriveFromCapsule(backing: std.mem.Allocator, capsule: *const Capsule, claims: Public.Claims, capacity: u32, limits: Limits) !Owned {
        return switch (capsule.profile().trace_count) {
            3 => deriveCapsuleFor(4, backing, capsule, claims, capacity, limits),
            4 => deriveCapsuleFor(5, backing, capsule, claims, capacity, limits),
            else => error.InvalidNativeFixedCommitments,
        };
    }
    fn deriveCapsuleFor(comptime N: usize, backing: std.mem.Allocator, capsule: *const Capsule, claims: Public.Claims, capacity: u32, limits: Limits) !Owned {
        if (limits.max_bytes == 0 or capacity == 0) return error.NativeFixedResourceLimit;
        const budget = try Budget.createRetainingParent(backing, limits.max_bytes);
        errdefer budget.destroy();
        const compiler = capsule.compiler();
        return finish(N, budget, compiler.profile, claims, capacity, limits, &compiler.composition, &compiler.deep_graph, &compiler.fri_graph, &compiler.arithmetic);
    }
    fn deriveFor(comptime N: usize, backing: std.mem.Allocator, original: *const Profile.Owned, claims: Public.Claims, capacity: u32, limits: Limits) !Owned {
        if (limits.max_bytes == 0 or capacity == 0) return error.NativeFixedResourceLimit;
        const budget = try Budget.createRetainingParent(backing, limits.max_bytes);
        errdefer budget.destroy();
        const a = budget.allocator();
        var profile = try Profile.ForCommitments(N).init(original);
        var composition = try @import("air/block_v7_native_composition_v1.zig").compile(a, original);
        defer composition.deinit();
        var deep = try @import("air/pcs_deep_circuit.zig").build(a, profile.deepProfile());
        defer deep.deinit();
        var fri = try @import("air/fri_verifier_circuit.zig").build(a, profile.friProfile());
        defer fri.deinit();
        var arithmetic = try Assembly.Arithmetic.init(a, .{ composition.circuit.graph(), deep.graph(), fri.graph() });
        defer arithmetic.deinit();
        return finish(N, budget, original, claims, capacity, limits, &composition, &deep, &fri, &arithmetic);
    }
    fn finish(comptime N: usize, budget: *Budget, original: *const Profile.Owned, claims: Public.Claims, capacity: u32, limits: Limits, composition: *const @import("air/block_v7_native_composition_v1.zig").Compiled, deep: *const @import("air/pcs_deep_circuit.zig").Circuit, fri: *const @import("air/fri_verifier_circuit.zig").Circuit, arithmetic: *const Assembly.Arithmetic) !Owned {
        const a = budget.allocator();
        var profile = try Profile.ForCommitments(N).init(original);
        var transcript = try @import("block_v7_native_fixed_transcript_v1.zig").deriveWithShared(a, original, claims.projection, claims.access, capacity, limits.transcript, limits.shared_epoch);
        defer transcript.deinit();
        const pcs = try @import("block_v5_native_recursive_fixed_pcs_v1.zig").ForCommitments(N).Owned.compile(a, &profile, deep, fri, &transcript);
        defer pcs.deinit();
        const sources = try @import("air/block_v5_recursive_parent_fixed_sources_v1.zig").ForPieces(void).Owned.compileNativeV7(a, &profile, composition, deep, fri, &transcript);
        defer sources.deinit();
        const selectors = try Assembly.selectorsForGraphs(a, deep, fri);
        const fixed = try @import("block_v5_recursive_parent_fixed_roster_v1.zig").compileOriginalRoster(a, sources, null, pcs.openings, pcs.ports, &transcript, &pcs.paths, arithmetic, selectors, deep);
        errdefer inline for (0..Storage.Airs.len) |i| a.free(fixed[i]);
        var namespace = try Namespace.prepareForArithmetic(a, fixed, 1, .{ .plan = &arithmetic.plan, .reference = arithmetic.reference, .kind = .segment_leaf });
        errdefer namespace.deinit();
        try namespace.requireIndependentMainPort();
        var values = try Public.reconstruct(a, original, claims);
        defer values.deinit();
        const wires = try Public.API.collectFixedSchedule(a, &transcript, composition, values.statement.words.len, values.public.len, N - 2, @intCast(profile.config.fri_config.n_queries), limits.max_public_wires);
        errdefer a.free(wires);
        const context = Base.Context{ .child_key_id = profile.seal, .child_config = profile.config, .graph_ids = .{ composition.circuit.identity_digest, deep.graph().identity_digest, fri.graph().identity_digest }, .transcript_plan_id = transcript.id };
        _ = try Base.contextIdentity(context);
        return .{ .shared_epoch = transcript.fixed.resumed_state, .allocator = a, .budget = budget, .fixed = fixed, .wires = wires, .context = context, .namespace = namespace };
    }
    pub fn validateLive(self: *const Owned, live: *@import("block_v7_native_preparation_v1.zig").Prepared) !void {
        try live.recursive.rows.partitionHashRows();
        try self.namespace.validateLive(&live.recursive.rows);
        if (!std.meta.eql(self.context, live.recursive.context) or self.wires.len != live.wires.len) return error.UntrustedNativeFixedRoster;
        for (self.wires, live.wires) |got, want| if (!std.meta.eql(got, want)) return error.UntrustedNativeFixedRoster;
        inline for (0..Storage.Airs.len) |i| {
            if (self.fixed[i].len != live.recursive.rows.fixed[i].len) return error.UntrustedNativeFixedRoster;
            for (self.fixed[i], live.recursive.rows.fixed[i]) |got, want| if (!std.meta.eql(got, want)) return error.UntrustedNativeFixedRoster;
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
pub fn expected(profile: *const Profile.Owned) Protocol.Bus.Expected {
    return .{ .profile = profile.seal, .epoch = profile.epoch.digest, .roots = profile.pin.roots ++ .{profile.pin.access_root}, .root_count = @intCast(profile.trace_count - 1) };
}
