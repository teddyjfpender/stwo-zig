//! Source-only authority for canonical groups and their remaining folds. No
//! proposed verifier key or proof bytes enter construction. Group key custody
//! remains with its caller; this topology owns only independently derived folds.
const std = @import("std");
const Stream = @import("source.zig");
const Planner = @import("plan.zig");
const Inventory = @import("../sponge_cpu/inventory.zig").Inventory;
const Prepared = @import("../sponge_cpu/root_admission.zig").Prepared;
const Key = @import("../native_omul/authority.zig").Key;
const Fold = @import("../native_omul/fold.zig");
const Profile = @import("../op_profile.zig").Profile;
const Retire = @import("../native_omul/verifier_key.zig").retireProverData;
/// Construct only from the concrete typed native source emitters. This never
/// accepts a deserialized key, claimed key hash, generic arbitrary graph or VK.
pub const Group = struct {
    key: Key,
    span: Planner.Span,
    profile: Profile,
    manifest: [36]u8,
    bindings: [4]Stream.Binding,
    pub fn init(a: std.mem.Allocator, source: *Stream.Stream) !Group {
        if (!source.trace_only) return error.NativeGroupSourceTraceRequired;
        var trace = try source.finish();
        defer trace.deinit();
        return .{ .key = try Key.init(a, &trace, source.profile), .span = .{ .first = source.first, .count = source.count }, .profile = source.profile, .manifest = source.manifest, .bindings = source.bindings };
    }
    pub fn deinit(self: *Group) void {
        self.key.deinit();
        self.* = undefined;
    }
    pub fn retireProverData(self: *Group) void {
        Retire(&self.key);
    }
    fn require(self: *const Group, inventory: *const Inventory, prepared: *const Prepared, span: Planner.Span, profile: Profile) !void {
        if (!std.meta.eql(self.span, span) or self.profile != profile or self.key.base.profile != profile or self.key.base.n_outputs != 9 or !std.mem.eql(u8, &self.manifest, &prepared.manifest)) return error.NativeGroupSourceAuthority;
        for (self.bindings[0..span.count], inventory.workers[span.first..try span.end()], span.first..) |binding, worker, ordinal| {
            if (binding.ordinal != ordinal or worker.authority.ordinal != ordinal or worker.authority.profile != profile or !std.mem.eql(u8, &binding.fixed_identity, &worker.authority.fixed_identity)) return error.NativeGroupSourceAuthority;
        }
    }
};
pub const Topology = struct {
    allocator: std.mem.Allocator,
    plan: Planner.Plan,
    profile: Profile,
    execution: [32]u8,
    manifest: [36]u8,
    keys: [Planner.MAX_NODES]?*const Key = @splat(null),
    owned: std.ArrayList(*Key) = .empty,
    /// All group bindings are checked before constructing ANY fold key.
    /// Producer scheduling derives one fold key just before its proof, then
    /// retires its wide data; receiver init derives verification-only keys.
    pub fn begin(a: std.mem.Allocator, inventory: *const Inventory, prepared: *const Prepared, maximum_group: u32, groups: []const *const Group) !Topology {
        if (inventory.workers.len == 0 or inventory.workers.len != prepared.outputs.len or !std.mem.eql(u8, &inventory.execution, &prepared.execution)) return error.NativeGroupExecutionAuthority;
        const profile = inventory.workers[0].authority.profile;
        var self = Topology{ .allocator = a, .plan = try Planner.Plan.init(@intCast(inventory.workers.len), maximum_group), .profile = profile, .execution = prepared.execution, .manifest = prepared.manifest };
        errdefer self.deinit();
        var group_index: usize = 0;
        for (self.plan.ordered(), 0..) |node, index| switch (node.operation) {
            .group => {
                if (group_index >= groups.len) return error.NativeGroupSourceCoverage;
                const source = groups[group_index];
                try source.require(inventory, prepared, node.span, profile);
                self.keys[index] = &source.key;
                group_index += 1;
            },
            .fold => {},
        };
        if (group_index != groups.len) return error.NativeGroupSourceCoverage;
        return self;
    }
    pub fn init(a: std.mem.Allocator, inventory: *const Inventory, prepared: *const Prepared, maximum_group: u32, groups: []const *const Group) !Topology {
        var self = try begin(a, inventory, prepared, maximum_group, groups);
        errdefer self.deinit();
        for (self.plan.ordered(), 0..) |node, index| if (node.operation == .fold) {
            _ = try self.deriveFold(index, false);
        };
        try self.requireComplete();
        return self;
    }
    pub fn deriveFold(self: *Topology, index: usize, resident: bool) !*Key {
        if (index >= self.plan.node_count or self.plan.nodes[index].operation != .fold or self.keys[index] != null) return error.NativeGroupFoldPhase;
        const edge = self.plan.nodes[index].operation.fold;
        const source = Fold.TraceSource{ .keys = .{ self.keys[edge.left] orelse return error.NativeGroupSourceCoverage, self.keys[edge.right] orelse return error.NativeGroupSourceCoverage } };
        var trace = try source.build(self.allocator);
        defer trace.deinit();
        try self.owned.ensureUnusedCapacity(self.allocator, 1);
        const key = try self.allocator.create(Key);
        errdefer self.allocator.destroy(key);
        key.* = try Key.init(self.allocator, &trace, self.profile);
        self.owned.appendAssumeCapacity(key);
        self.keys[index] = key;
        if (!resident) Retire(key);
        return key;
    }
    pub fn requireComplete(self: *const Topology) !void {
        try self.plan.validate();
        for (self.keys[0..self.plan.node_count]) |key| if (key == null) return error.NativeGroupSourceCoverage;
    }
    pub fn deinit(self: *Topology) void {
        for (self.owned.items) |key| {
            key.deinit();
            self.allocator.destroy(key);
        }
        self.owned.deinit(self.allocator);
        self.* = undefined;
    }
    pub fn rootKey(self: *const Topology) *const Key {
        return self.keys[self.plan.root].?;
    }
    pub fn verify(self: *const Topology, inventory: *const Inventory, prepared: *const Prepared, bytes: []const u8) !void {
        try self.requireComplete();
        if (self.plan.leaf_count != inventory.workers.len or prepared.outputs.len != inventory.workers.len or !std.mem.eql(u8, &self.execution, &inventory.execution) or !std.mem.eql(u8, &self.execution, &prepared.execution) or !std.mem.eql(u8, &self.manifest, &prepared.manifest)) return error.NativeGroupExecutionAuthority;
        if (self.profile != inventory.workers[0].authority.profile or self.rootKey().base.profile != self.profile or self.rootKey().base.n_outputs != 9) return error.NativeGroupSourceAuthority;
        const output = try prepared.expectedRoot();
        try @import("../native_omul/proof.zig").verify(self.allocator, self.rootKey(), &output, bytes);
    }
};
