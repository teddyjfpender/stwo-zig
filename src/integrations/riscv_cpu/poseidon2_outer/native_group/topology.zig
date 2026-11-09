//! Source-only authority for canonical groups and their remaining folds. No
//! proposed verifier key or proof bytes enter construction. Group key custody
//! remains with its caller; this topology owns only independently derived folds.
const std = @import("std");
const Stream = @import("source.zig");
const Planner = @import("plan.zig");
const Inventory = @import("../sponge_cpu/inventory.zig").Inventory;
const Prepared = @import("../sponge_cpu/root_admission.zig").Prepared;
const Key = @import("../native_omul/authority.zig").Key;
const Keys = @import("keys.zig");
const Fold = @import("../native_omul/fold.zig");
const Profile = @import("../op_profile.zig").Profile;
/// Construct only from the concrete typed native source emitters. This never
/// accepts a deserialized key, claimed key hash, generic arbitrary graph or VK.
pub const Group = struct {
    key: Keys.Owner,
    span: Planner.Span,
    profile: Profile,
    manifest: [36]u8,
    bindings: [4]Stream.Binding,
    pub fn init(a: std.mem.Allocator, source: *Stream.Stream) !Group {
        return initWithOuterProfile(a, source, source.profile);
    }
    pub fn initWithOuterProfile(a: std.mem.Allocator, source: *Stream.Stream, outer_profile: Profile) !Group {
        try requireTerminalProfile(source.profile, outer_profile);
        if (!source.trace_only) return error.NativeGroupSourceTraceRequired;
        var trace = try source.finish();
        defer trace.deinit();
        return .{ .key = .{ .r6 = try Key.init(a, &trace, outer_profile) }, .span = .{ .first = source.first, .count = source.count }, .profile = source.profile, .manifest = source.manifest, .bindings = source.bindings };
    }
    pub fn initSelectedWithOuterProfile(a: std.mem.Allocator, source: *Keys.Stream, outer_profile: Profile) !Group {
        const header = source.base();
        try requireTerminalProfile(header.profile, outer_profile);
        const first = header.first;
        const count = header.count;
        const profile = header.profile;
        const manifest = header.manifest;
        const bindings = header.bindings;
        return .{ .key = try Keys.Owner.fromSelectedStreamWithProfile(a, source, outer_profile), .span = .{ .first = first, .count = count }, .profile = profile, .manifest = manifest, .bindings = bindings };
    }
    pub fn deinit(self: *Group) void {
        self.key.deinit();
        self.* = undefined;
    }
    pub fn retireProverData(self: *Group) void {
        self.key.retireProverData();
    }
    fn require(self: *const Group, inventory: *const Inventory, prepared: *const Prepared, span: Planner.Span, profile: Profile, outer_profile: Profile, format: Keys.Format) !void {
        if (!std.meta.eql(self.span, span) or self.profile != profile or std.meta.activeTag(self.key) != format or self.key.ref().profile() != outer_profile or self.key.ref().nOutputs() != 9 or !std.mem.eql(u8, &self.manifest, &prepared.manifest)) return error.NativeGroupSourceAuthority;
        for (self.bindings[0..span.count], inventory.workers[span.first..try span.end()], span.first..) |binding, worker, ordinal| {
            if (binding.ordinal != ordinal or worker.authority.ordinal != ordinal or worker.authority.profile != profile or !std.mem.eql(u8, &binding.fixed_identity, &worker.authority.fixed_identity)) return error.NativeGroupSourceAuthority;
        }
    }
};
pub const Topology = struct {
    allocator: std.mem.Allocator,
    plan: Planner.Plan,
    profile: Profile,
    terminal_outer_profile: Profile,
    format: Keys.Format = .r6,
    execution: [32]u8,
    manifest: [36]u8,
    keys: [Planner.MAX_NODES]?Keys.Ref = @splat(null),
    owned: std.ArrayList(*Keys.Owner) = .empty,
    /// All group bindings are checked before constructing ANY fold key.
    /// Producer scheduling derives one fold key just before its proof, then
    /// retires its wide data; receiver init derives verification-only keys.
    pub fn begin(a: std.mem.Allocator, inventory: *const Inventory, prepared: *const Prepared, maximum_group: u32, groups: []const *const Group) !Topology {
        if (inventory.workers.len == 0) return error.NativeGroupExecutionAuthority;
        return beginWithOuterProfile(a, inventory, prepared, maximum_group, groups, inventory.workers[0].authority.profile);
    }
    pub fn beginWithOuterProfile(a: std.mem.Allocator, inventory: *const Inventory, prepared: *const Prepared, maximum_group: u32, groups: []const *const Group, terminal_outer_profile: Profile) !Topology {
        return beginWithPolicy(a, inventory, prepared, maximum_group, groups, terminal_outer_profile, .r6);
    }
    pub fn beginWithPolicy(a: std.mem.Allocator, inventory: *const Inventory, prepared: *const Prepared, maximum_group: u32, groups: []const *const Group, terminal_outer_profile: Profile, format: Keys.Format) !Topology {
        if (inventory.workers.len == 0 or inventory.workers.len != prepared.outputs.len or !std.mem.eql(u8, &inventory.execution, &prepared.execution)) return error.NativeGroupExecutionAuthority;
        const profile = inventory.workers[0].authority.profile;
        try requireTerminalProfile(profile, terminal_outer_profile);
        var self = Topology{ .format = format, .terminal_outer_profile = terminal_outer_profile, .allocator = a, .plan = try Planner.Plan.init(@intCast(inventory.workers.len), maximum_group), .profile = profile, .execution = prepared.execution, .manifest = prepared.manifest };
        errdefer self.deinit();
        var group_index: usize = 0;
        for (self.plan.ordered(), 0..) |node, index| switch (node.operation) {
            .group => {
                if (group_index >= groups.len) return error.NativeGroupSourceCoverage;
                const source = groups[group_index];
                try source.require(inventory, prepared, node.span, profile, self.outerProfile(index), format);
                self.keys[index] = source.key.ref();
                group_index += 1;
            },
            .fold => {},
        };
        if (group_index != groups.len) return error.NativeGroupSourceCoverage;
        return self;
    }
    pub fn init(a: std.mem.Allocator, inventory: *const Inventory, prepared: *const Prepared, maximum_group: u32, groups: []const *const Group) !Topology {
        if (inventory.workers.len == 0) return error.NativeGroupExecutionAuthority;
        return initWithOuterProfile(a, inventory, prepared, maximum_group, groups, inventory.workers[0].authority.profile);
    }
    pub fn initWithOuterProfile(a: std.mem.Allocator, inventory: *const Inventory, prepared: *const Prepared, maximum_group: u32, groups: []const *const Group, terminal_outer_profile: Profile) !Topology {
        return initWithPolicy(a, inventory, prepared, maximum_group, groups, terminal_outer_profile, .r6);
    }
    pub fn initWithPolicy(a: std.mem.Allocator, inventory: *const Inventory, prepared: *const Prepared, maximum_group: u32, groups: []const *const Group, terminal_outer_profile: Profile, format: Keys.Format) !Topology {
        var self = try beginWithPolicy(a, inventory, prepared, maximum_group, groups, terminal_outer_profile, format);
        errdefer self.deinit();
        for (self.plan.ordered(), 0..) |node, index| if (node.operation == .fold) {
            _ = try self.deriveFold(index, false);
        };
        try self.requireComplete();
        return self;
    }
    pub fn outerProfile(self: *const Topology, index: usize) Profile {
        return if (index == self.plan.root) self.terminal_outer_profile else self.profile;
    }
    pub fn deriveFold(self: *Topology, index: usize, resident: bool) !*Keys.Owner {
        if (index >= self.plan.node_count or self.plan.nodes[index].operation != .fold or self.keys[index] != null) return error.NativeGroupFoldPhase;
        const edge = self.plan.nodes[index].operation.fold;
        const children = [2]Keys.Ref{ self.keys[edge.left] orelse return error.NativeGroupSourceCoverage, self.keys[edge.right] orelse return error.NativeGroupSourceCoverage };
        try self.owned.ensureUnusedCapacity(self.allocator, 1);
        const key = try self.allocator.create(Keys.Owner);
        errdefer self.allocator.destroy(key);
        key.* = switch (self.format) {
            .r6 => blk: {
                if (children[0] != .r6 or children[1] != .r6) return error.NativeGroupArithmetizationPolicy;
                var trace = try (Fold.TraceSource{ .keys = .{ children[0].r6, children[1].r6 } }).build(self.allocator);
                defer trace.deinit();
                break :blk .{ .r6 = try Key.init(self.allocator, &trace, self.outerProfile(index)) };
            },
            .r7 => try Keys.Owner.canonicalFold(self.allocator, children, self.outerProfile(index)),
        };
        self.owned.appendAssumeCapacity(key);
        self.keys[index] = key.ref();
        if (!resident) key.retireProverData();
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
    pub fn rootKey(self: *const Topology) Keys.Ref {
        return self.keys[self.plan.root].?;
    }
    pub fn verify(self: *const Topology, inventory: *const Inventory, prepared: *const Prepared, bytes: []const u8) !void {
        try self.requireComplete();
        if (self.plan.leaf_count != inventory.workers.len or prepared.outputs.len != inventory.workers.len or !std.mem.eql(u8, &self.execution, &inventory.execution) or !std.mem.eql(u8, &self.execution, &prepared.execution) or !std.mem.eql(u8, &self.manifest, &prepared.manifest)) return error.NativeGroupExecutionAuthority;
        if (self.profile != inventory.workers[0].authority.profile or std.meta.activeTag(self.rootKey()) != self.format or self.rootKey().profile() != self.terminal_outer_profile or self.rootKey().nOutputs() != 9) return error.NativeGroupSourceAuthority;
        const output = try prepared.expectedRoot();
        try self.rootKey().verify(self.allocator, &output, bytes);
    }
};

/// Terminal policy is receiver-owned and separate from all native members.
/// No other cross-profile conversion is admitted by this experimental route.
pub fn requireTerminalProfile(native: Profile, terminal: Profile) !void {
    if (native == .reference_b2_q24_p0 or (terminal != native and !(native == .op_target_b4_q72_p0_fold4_v1 and terminal == .op_control_b2_q144_p0_fold4_v1))) return error.NativeGroupTerminalProfile;
}
