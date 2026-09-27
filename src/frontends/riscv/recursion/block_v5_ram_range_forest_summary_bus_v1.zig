//! Exact same forest grammar with summary-only fresh reception. No native
//! descendant witness/admission is resurrected by closed parent Source.
const std = @import("std");
const core = @import("stwo_core");
const Original = @import("block_v5_ram_range_forest_bus_v1.zig");
pub const Policy = Original.Policy;
pub const Spec = Original.Spec;
pub const Summary = Original.Summary;
pub const Wire = Original.Wire;
pub const Limits = Original.Limits;
pub const scheduleDigest = Original.scheduleDigest;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub const Owner = struct {
    policy: Policy,
    limits: Limits,
    summary: Summary,
    lease: ?*Budget,
    pub const complete_block_authority = false;
    pub fn init(a: std.mem.Allocator, policy: Policy, limits: Limits) !Owner {
        try policy.validate();
        return .{ .policy = policy, .limits = limits, .summary = try Summary.init(policy), .lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null };
    }
    pub fn validate(self: *const @This()) !void {
        try self.policy.validate();
        try self.summary.validate();
        if (!std.meta.eql(self.summary.policy, self.policy)) return error.UntrustedRamRangeForestNode;
    }
    pub fn deinit(self: *@This()) void {
        const lease = self.lease;
        self.* = undefined;
        if (lease) |owner| owner.destroy();
    }
};
pub const Values = struct {
    public: *const Owner,
    pub fn validate(self: @This()) !void {
        try self.public.validate();
    }
    pub fn requireConfig(self: @This(), config: core.pcs.PcsConfig) !void {
        if (!std.meta.eql(config, self.public.policy.forest.memory.seal.config)) return error.UntrustedRamRangeForestSecurity;
    }
    pub fn at(_: @This(), _: Wire) ![4]core.fields.m31.M31 {
        return error.ClosedRamRangeForestHasNoPublicTerms;
    }
    pub fn mix(self: @This(), channel: anytype) !void {
        try self.validate();
        self.public.summary.mix(channel);
    }
};
pub fn supply(wires: []const Wire, values: Values, relations: @import("air/universal_challenges.zig").UniversalRelations) !core.fields.qm31.QM31 {
    _ = relations;
    _ = try scheduleDigest(wires);
    try values.validate();
    return .zero();
}
pub const init = Owner.init;
