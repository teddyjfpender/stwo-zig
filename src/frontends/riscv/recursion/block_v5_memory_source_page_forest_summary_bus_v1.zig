//! Receiving-only closed PAGE statement. No original leaf descriptors are
//! needed after local suppliers are proved under the independently rebuilt
//! fixed key. Actual Parent verification remains mandatory. Producers still
//! use the full original Bus.Owner and exact child/merge/supplier equations.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Original = @import("block_v5_memory_source_page_forest_bus_v1.zig");
pub const Policy = Original.Policy;
pub const Limits = Original.Limits;
pub const Summary = Original.Summary;
pub const Spec = Original.Spec;
pub const Wire = Original.Wire;
pub const scheduleDigest = Original.scheduleDigest;
pub const Owner = struct {
    allocator: std.mem.Allocator,
    allocation_owner: ?*Budget,
    policy: Policy,
    limits: Limits,
    summary: Summary,
    pub fn init(a: std.mem.Allocator, policy: Policy, limits: Limits) !Owner {
        try policy.validate();
        const summary = try Summary.init(policy);
        const owner = if (Budget.fromAllocator(a)) |budget| budget.retain() else null;
        return .{ .allocator = a, .allocation_owner = owner, .policy = policy, .limits = limits, .summary = summary };
    }
    pub fn validate(self: *const Owner) !void {
        try self.policy.validate();
        if (!std.meta.eql(self.policy, self.summary.policy)) return error.UnpairedPageForestSummaryPolicy;
        try self.summary.validate();
    }
    pub fn deinit(self: *Owner) void {
        const owner = self.allocation_owner;
        self.* = undefined;
        if (owner) |budget| budget.destroy();
    }
};
pub const Values = struct {
    public: *const Owner,
    pub fn validate(self: Values) !void {
        try self.public.validate();
    }
    pub fn requireConfig(self: Values, config: core.pcs.PcsConfig) !void {
        if (!std.meta.eql(config, self.public.policy.forest.context.fold_plan.config)) return error.UntrustedPageForestNode;
    }
    pub fn mix(self: Values, channel: anytype) !void {
        try self.validate();
        self.public.summary.mix(channel);
    }
    pub fn at(_: Values, _: Wire) ![4]core.fields.m31.M31 {
        return error.ClosedPageForestNodeHasNoPublicTerms;
    }
};
pub fn supply(wires: []const Wire, values: Values, _: @import("air/universal_challenges.zig").UniversalRelations) !core.fields.qm31.QM31 {
    if (wires.len != 0) return error.ClosedPageForestNodeHasNoPublicTerms;
    try values.validate();
    return core.fields.qm31.QM31.zero();
}
pub const init = Owner.init;
