//! Heap-stable exact source ownership: both actual fresh captures, expected
//! public file owner, lazy source and normative recipe survive parent rows.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Owner = @import("block_v5_heterogeneous_scoped_owner_v1.zig");
const Compact = @import("block_v5_heterogeneous_scoped_owned_receiver_v1.zig");
const Public = @import("block_v5_global_public_owned_receiver_v1.zig");
const Source = @import("block_v5_heterogeneous_scoped_public_source_v1.zig");
const Plan = @import("block_v5_heterogeneous_scoped_public_plan_v1.zig");
const Values = @import("block_v5_heterogeneous_scoped_public_values_v1.zig").Values;
pub const Limits = struct { max_compact_bytes: usize = 512 << 20, max_public_bytes: usize = 512 << 20, public: Public.Limits = .{}, plan: Plan.Limits = .{} };
pub const Policy = struct {
    owner: *const Owner.Owner,
    public_policy: @import("block_v5_global_public_export_policy_v1.zig").Policy,
    expected_public: @import("block_v5_global_expected_public_job_v1.zig").Expected,
    public_dir: std.fs.Dir,
    public_file: @import("../prover/block_v5_global_expected_public_file_v1.zig").Pin,
    public_key: @import("block_v5_reusable_global_public_export_protocol_v1.zig").Key,
    public_id: [32]u8,
    public_schedule: []const @import("block_v5_global_public_export_bus_v1.zig").Wire,
    limits: Limits = .{},
};
pub const Context = struct {
    allocator: std.mem.Allocator,
    lease: Owner.Borrow,
    policy: Policy,
    compact: Compact.Fresh,
    public: Public.Fresh,
    source: Source.Source,
    plan: Plan.Plan,
    outputs: []Q,
    pub const complete_block_authority = false;
    pub fn values(self: *const Context) Values {
        return .{ .owner = self.policy.owner, .compact = &self.compact.source, .public = &self.source, .plan = &self.plan, .outputs = self.outputs };
    }
    pub fn deinit(self: *Context) void {
        const allocator = self.allocator;
        const owner = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.fromAllocator(allocator);
        if (owner) |value| _ = value.retain();
        self.allocator.free(self.outputs);
        self.plan.deinit();
        self.source.deinit();
        self.public.deinit();
        self.compact.deinit();
        self.lease.deinit();
        allocator.destroy(self);
        if (owner) |value| value.destroy();
    }
};
pub fn outputCount(windows: usize, max_windows: usize) !usize {
    if (windows == 0 or max_windows == 0 or windows > max_windows) return error.ScopedPublicBridgeResourceLimit;
    return std.math.add(usize, try std.math.mul(usize, windows, 3), try std.math.mul(usize, windows - 1, 4));
}
pub fn open(a: std.mem.Allocator, policy: Policy, compact_bytes: []const u8, public_bytes: []const u8) !*Context {
    if (compact_bytes.len == 0 or compact_bytes.len > policy.limits.max_compact_bytes or public_bytes.len == 0 or public_bytes.len > policy.limits.max_public_bytes) return error.ScopedPublicBridgeResourceLimit;
    const self = try a.create(Context);
    errdefer a.destroy(self);
    self.allocator = a;
    self.policy = policy;
    self.lease = try policy.owner.borrow();
    errdefer self.lease.deinit();
    self.compact = switch (policy.owner.cohorts.root) {
        .leaf => |ordinal| try Compact.verifyLeaf(a, compact_bytes, policy.owner, ordinal),
        .node => |index| try Compact.verify(a, compact_bytes, policy.owner, index),
    };
    errdefer self.compact.deinit();
    self.public = try Public.verify(a, policy.public_dir, policy.public_file, policy.expected_public, policy.public_policy, public_bytes, policy.public_key, policy.public_id, policy.public_schedule, policy.limits.public);
    errdefer self.public.deinit();
    self.source = try Source.Source.init(a, &self.public, policy.public_policy, policy.public_key, policy.public_id, policy.public_schedule, policy.limits.public.fields);
    errdefer self.source.deinit();
    self.plan = try Plan.init(a, policy.owner, &self.source, policy.limits.plan);
    errdefer self.plan.deinit();
    const count = self.plan.windows.len;
    const extent = try outputCount(count, policy.limits.plan.max_windows);
    self.outputs = try a.alloc(Q, extent);
    errdefer a.free(self.outputs);
    for (self.source.public.terms, 0..) |terms, index| @memcpy(self.outputs[3 * index ..][0..3], &terms);
    for (self.source.public.fields[0 .. count - 1], 0..) |field, index| {
        const carries = try @import("air/block_v5_recursive_u64_span_v1.zig").carries(field.last_cycle);
        for (carries, 0..) |carry, limb| self.outputs[3 * count + 4 * index + limb] = Q.fromBase(core.fields.m31.M31.fromCanonical(carry));
    }
    try self.values().validate();
    return self;
}
