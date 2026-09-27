//! Exactly two real recursive roots: public-closed requesters and source-backed
//! RAM/range. No descendant RAM verifier is embedded here. No complete token.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Scoped = @import("block_v5_heterogeneous_scoped_owner_v1.zig");
const Coverage = @import("../prover/block_v5_recursive_coverage_plan_v1.zig");
pub const Requester = @import("block_v5_requester_public_source_v1.zig");
pub const Memory = @import("block_v5_source_ram_forest_join_source_v1.zig");
pub const VERSION: u32 = 22;
pub const Wire = @import("block_v5_heterogeneous_scoped_public_bus_v1.zig").Wire;
pub const Policy = struct {
    expected_requester: *const Scoped.Owner,
    requester: *const Requester.Source,
    memory: *const Memory.Source,
};
pub const Limits = struct { max_children: usize = 2 };
pub const Owner = struct {
    policy: Policy,
    limits: Limits,
    lease: Scoped.Borrow,
    budget: ?*Budget,
    pub const complete_block_authority = false;
    pub fn init(a: std.mem.Allocator, policy: Policy, limits: Limits) !Owner {
        if (limits.max_children < 2) return error.RequesterMemoryResourceLimit;
        var lease = try policy.expected_requester.borrow();
        errdefer lease.deinit();
        const budget = if (Budget.fromAllocator(a)) |b| b.retain() else null;
        errdefer if (budget) |b| b.destroy();
        const result = Owner{ .policy = policy, .limits = limits, .lease = lease, .budget = budget };
        try result.validate();
        return result;
    }
    pub fn deinit(self: *Owner) void {
        const budget = self.budget;
        self.lease.deinit();
        self.* = undefined;
        if (budget) |b| b.destroy();
    }
    pub fn validate(self: *const Owner) !void {
        if (self.limits.max_children < 2) return error.RequesterMemoryResourceLimit;
        const p = self.policy;
        try p.requester.validate();
        try p.memory.validate();
        if (p.requester.requester() != p.expected_requester or p.expected_requester.scoped.recipe != .requesters) return error.UntrustedRequesterMemoryRecipe;
        const forest = p.memory.fresh.public.policy.memory;
        const ctx = p.memory.fresh.public.policy.source.fresh.public.policy.forest.context;
        const meta = p.expected_requester.coverage.meta;
        if (!std.meta.eql(p.expected_requester.pins.source, forest.sealed.digest) or
            !std.meta.eql(meta.seal_digest, forest.sealed.digest) or
            !std.meta.eql(ctx.base, forest.sealed) or
            forest.sealed.register_custody_mode != 1 or
            !std.meta.eql(meta.security.base, forest.memory.seal.config) or
            meta.ram_events != forest.memory.expected_total_events) return error.UnpairedRequesterMemorySource;
        // Independently preserve base and recursive security, rather than
        // accepting different base/recursive query, PoW or FRI policies.
        if (!std.meta.eql(p.requester.fresh.policy.key.config, p.memory.fresh.policy.key.config) or
            !std.meta.eql(p.requester.fresh.policy.key.config, meta.security.recursive)) return error.RequesterMemorySecurityMismatch;
        try meta.security.require(p.memory.fresh.policy.key.config);
        const sources = meta.sources;
        const image = sources[@intFromEnum(Coverage.SourceKind.initial_image)];
        const final = sources[@intFromEnum(Coverage.SourceKind.final_image)];
        const windows = sources[@intFromEnum(Coverage.SourceKind.register_windows)];
        const ram = sources[@intFromEnum(Coverage.SourceKind.ram_plan)];
        if (!std.meta.eql(image.identity, forest.sealed.initial_source_plan_digest) or
            !std.meta.eql(final.identity, forest.sealed.rw_endpoint_plan_digest) or
            !std.meta.eql(windows.identity, forest.sealed.register_endpoint_plan_digest) or
            !std.meta.eql(ram.identity, forest.memory.seal.memory_plan_digest) or ram.count != meta.ram_events or
            windows.count != p.expected_requester.scoped.semantic.execution_count or
            meta.register_window_version != p.expected_requester.pins.recipe.windowVersion()) return error.UnpairedRequesterMemoryCensus;
        if (sources[@intFromEnum(Coverage.SourceKind.first_touches)].count != ctx.admitted.source.records(.first_touches) or
            final.count != ctx.admitted.source.records(.endpoints) or
            image.count != try std.math.add(u64, ctx.admitted.source.records(.input_words), ctx.admitted.source.records(.rw_words)) or
            sources[@intFromEnum(Coverage.SourceKind.public_input)].count != ctx.admitted.source.byteLength(.public_input) or
            !std.meta.eql(sources[@intFromEnum(Coverage.SourceKind.public_input)].identity, ctx.admitted.source.digest(.public_input))) return error.UnpairedRequesterMemoryCensus;
        _ = try p.requester.transition();
    }
};
pub const Values = struct {
    public: *const Owner,
    pub fn validate(self: @This()) !void {
        try self.public.validate();
    }
    pub fn requireConfig(self: @This(), config: core.pcs.PcsConfig) !void {
        if (!std.meta.eql(config, self.public.policy.expected_requester.coverage.meta.security.recursive)) return error.RequesterMemorySecurityMismatch;
    }
    pub fn at(self: @This(), wire: Wire) ![4]M {
        const p = self.public.policy;
        const value = switch (wire.kind) {
            .child_cell => switch (wire.child) {
                0 => try p.requester.cell(wire.coordinate),
                1 => try p.memory.cell(wire.coordinate),
                else => return error.InvalidRequesterMemoryCoordinate,
            },
            .child_term => {
                if (wire.part != null) return error.InvalidRequesterMemoryCoordinate;
                const terms = switch (wire.child) {
                    0 => p.requester.terms,
                    1 => p.memory.terms,
                    else => return error.InvalidRequesterMemoryCoordinate,
                };
                return if (wire.coordinate < terms.len) terms[wire.coordinate].coordinates else error.InvalidRequesterMemoryCoordinate;
            },
            else => return error.InvalidRequesterMemoryCoordinate,
        };
        return if (wire.part) |part| .{ value[part], M.zero(), M.zero(), M.zero() } else value;
    }
    pub fn mix(self: @This(), c: anytype) !void {
        try self.validate();
        const p = self.public.policy;
        const owner = p.expected_requester;
        const memory = p.memory.fresh.public.policy;
        const ctx = memory.source.fresh.public.policy.forest.context;
        c.mixU32s(&.{ 0x52514d42, VERSION, 2, owner.scoped.semantic.execution_count, owner.coverage.meta.register_window_version });
        const requester_authority = try p.requester.fresh.authority();
        const memory_authority = try p.memory.fresh.authority();
        inline for (.{ owner.pinned_identity, owner.pins.coverage, owner.pins.source, p.requester.fresh.policy.expected_id, try requester_authority.publicInputIdentity(), p.memory.fresh.policy.expected_id, try memory_authority.publicInputIdentity(), memory.expected_memory_plan, ctx.admitted.source.identity, ctx.sealed.digest, ctx.epoch.after_draw_digest }) |root| c.mixRoot(root);
        c.mixU64(memory.memory.memory.expected_total_events);
    }
};
pub fn scheduleDigest(wires: []const Wire) ![32]u8 {
    if (wires.len != 0) return error.ClosedRequesterMemoryHasNoPublicTerms;
    var c = core.channel.blake3.Channel{};
    c.mixU32s(&.{ 0x52514d57, VERSION, 0 });
    return c.digestBytes();
}
pub fn supply(wires: []const Wire, values: Values, _: @import("air/universal_challenges.zig").UniversalRelations) !Q {
    _ = try scheduleDigest(wires);
    try values.validate();
    return .zero();
}
pub const init = Owner.init;
