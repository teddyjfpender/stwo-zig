//! Same original recursion-wire public supply with statically typed WM/v2,
//! forest-node and unique carrier cells. Own compact request cells are actual
//! node public inputs, never invented proof children or metadata receipts.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Layout = @import("block_v5_input_request_forest_public_v1.zig");
const Plan = @import("block_v5_input_request_forest_plan_v1.zig");
const W = @import("block_v5_tail_linked_public_windows_v2.zig");
const WB = @import("block_v5_tail_linked_public_windows_bus_v2.zig");
const WS = @import("block_v5_tail_linked_public_windows_source_v2.zig");
const WP = @import("block_v5_reusable_tail_linked_public_windows_protocol_v2.zig");
const CP = @import("block_v5_input_tail_protocol_v1.zig");
const CS = @import("block_v5_input_tail_source_v1.zig");
const B = @import("block_v5_heterogeneous_scoped_public_bus_v1.zig");
pub const Wire = B.Wire;
pub const scheduleDigest = B.scheduleDigest;
pub const Policy = Layout.Policy;
pub const Limits = Layout.Limits;
pub const Child = union(enum) {
    leaf: struct { public: W.Owner, prefix: [32]u32, prefix_count: u32, ref: u32 },
    node: struct { public: Layout.Owned, prefix: [32]u32, prefix_count: u32, ref: u32 },
    pub fn deinit(self: *Child) void {
        switch (self.*) {
            .leaf => |*v| v.public.deinit(),
            .node => {},
        }
        self.* = undefined;
    }
    pub fn prefixCount(self: *const Child) u32 {
        return switch (self.*) {
            .leaf => |v| v.prefix_count,
            .node => |v| v.prefix_count,
        };
    }
    pub fn cell(self: *const Child, coordinate: u32) ![4]M {
        return switch (self.*) {
            .leaf => |*v| if (coordinate >= v.prefix_count) v.public.cell(coordinate - v.prefix_count) else word(v.prefix[coordinate]),
            .node => |*v| if (coordinate >= v.prefix_count) v.public.cell(coordinate - v.prefix_count) else word(v.prefix[coordinate]),
        };
    }
};
fn word(raw: u32) [4]M {
    var out: [4]M = undefined;
    for (&out, 0..) |*byte, part| byte.* = M.fromCanonical((raw >> @as(u5, @intCast(8 * part))) & 255);
    return out;
}
const Prefix = struct {
    words: [32]u32 = undefined,
    len: u32 = 0,
    failure: ?anyerror = null,
    pub fn mixU32s(self: *Prefix, values: []const u32) void {
        if (self.failure != null) return;
        const end = std.math.add(usize, self.len, values.len) catch {
            self.failure = error.InvalidInputRequestPrefix;
            return;
        };
        if (end > self.words.len) {
            self.failure = error.InvalidInputRequestPrefix;
            return;
        }
        @memcpy(self.words[self.len..end], values);
        self.len = @intCast(end);
    }
    pub fn mixRoot(self: *Prefix, root: [32]u8) void {
        var values: [8]u32 = undefined;
        for (&values, 0..) |*v, i| v.* = std.mem.readInt(u32, root[4 * i ..][0..4], .little);
        self.mixU32s(&values);
    }
    pub fn mixFelts(self: *Prefix, felts: []const Q) void {
        for (felts) |felt| {
            var values: [4]u32 = undefined;
            for (&values, felt.toM31Array()) |*v, limb| v.* = limb.v;
            self.mixU32s(&values);
        }
    }
};
pub fn nodePrefix(policy: Policy) !Prefix {
    if (policy.index >= policy.specs.len) return error.UntrustedInputRequestNode;
    const spec = policy.specs[policy.index];
    var out = Prefix{};
    out.mixU32s(&.{ 0x42354d50, 4, @intFromEnum(spec.geometry.profile) });
    spec.geometry.config.mixInto(&out);
    out.mixRoot(spec.expected_id);
    if (out.failure) |failure| return failure;
    return out;
}
pub const Owner = struct {
    allocator: std.mem.Allocator,
    allocation_owner: ?*Budget,
    input: *@import("block_v5_input_tail_public_v1.zig").Owned,
    policy: Policy,
    limits: Limits,
    summary: Layout.Owned,
    children: [4]?Child,
    child_count: u32,
    carrier: ?CS.Normalized,
    pub const complete_source_authority = false;
    pub const complete_block_authority = false;
    pub fn init(a: std.mem.Allocator, policy: Policy, limits: Limits) !Owner {
        const summary = try Layout.Owned.init(policy, limits);
        const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
        errdefer if (lease) |owner| owner.destroy();
        const input = policy.forest.input.retain();
        errdefer input.deinit();
        var children: [4]?Child = @splat(null);
        var made: usize = 0;
        errdefer for (children[0..made]) |*child| if (child.*) |*v| v.deinit();
        const node = policy.forest.geometry.nodes[policy.index];
        for (node.children[0..node.child_count], 0..) |ref, index| {
            children[index] = switch (ref) {
                .leaf => |ordinal| block: {
                    const p = policy.forest.policies[ordinal];
                    var public = try W.init(a, p.public, p.public_limits);
                    errdefer public.deinit();
                    const admitted = try WP.Admission.init(p.key, p.expected_id, p.schedule, .{ .public = &public });
                    const prefix = try WS.publicPrefix(&admitted);
                    break :block .{ .leaf = .{ .public = public, .prefix = prefix.words, .prefix_count = prefix.len, .ref = ordinal } };
                },
                .node => |ordinal| block: {
                    if (ordinal >= policy.index) return error.InvalidInputRequestForest;
                    var p = policy;
                    p.index = ordinal;
                    const public = try Layout.Owned.init(p, limits);
                    const prefix = try nodePrefix(p);
                    break :block .{ .node = .{ .public = public, .prefix = prefix.words, .prefix_count = prefix.len, .ref = ordinal } };
                },
            };
            made += 1;
        }
        const carrier = if (node.kind == .carrier) block: {
            const admitted = try CP.Admission.init(policy.carrier.key, policy.carrier.expected_id, input, policy.forest.expected_input);
            break :block try CS.Normalized.fromAdmission(&admitted);
        } else null;
        return .{ .allocator = a, .allocation_owner = lease, .input = input, .policy = policy, .limits = limits, .summary = summary, .children = children, .child_count = node.child_count, .carrier = carrier };
    }
    pub fn deinit(self: *Owner) void {
        const lease = self.allocation_owner;
        for (self.children[0..self.child_count]) |*child| if (child.*) |*v| v.deinit();
        self.input.deinit();
        self.* = undefined;
        if (lease) |owner| owner.destroy();
    }
    pub fn validate(self: *const Owner) !void {
        try self.summary.validate();
        if (!std.meta.eql(self.summary.policy, self.policy) or !std.meta.eql(self.summary.limits, self.limits) or self.input != self.policy.forest.input) return error.MutatedInputRequestNode;
        var expected = try Owner.init(self.allocator, self.policy, self.limits);
        defer expected.deinit();
        if (self.child_count != expected.child_count or (self.carrier != null) != (expected.carrier != null)) return error.MutatedInputRequestNode;
        if (self.carrier) |actual| {
            const admitted = expected.carrier.?;
            if (actual.count != admitted.count or actual.public_first != admitted.public_first or actual.failure != null or !std.mem.eql(u32, actual.words[0..actual.count], admitted.words[0..admitted.count])) return error.MutatedInputRequestNode;
        }
        for (self.children[0..self.child_count], expected.children[0..expected.child_count]) |*actual, *admitted| {
            if (actual.* == null or admitted.* == null or std.meta.activeTag(actual.*.?) != std.meta.activeTag(admitted.*.?)) return error.MutatedInputRequestNode;
            switch (actual.*.?) {
                .leaf => |*v| {
                    const p = admitted.*.?.leaf;
                    if (v.ref != p.ref or v.prefix_count != p.prefix_count or !std.mem.eql(u32, v.prefix[0..v.prefix_count], p.prefix[0..p.prefix_count]) or !std.meta.eql(v.public.policy, p.public.policy) or !std.meta.eql(v.public.limits, p.public.limits)) return error.MutatedInputRequestNode;
                    try v.public.validate();
                },
                .node => |*v| {
                    const p = admitted.*.?.node;
                    if (v.ref != p.ref or v.prefix_count != p.prefix_count or !std.mem.eql(u32, v.prefix[0..v.prefix_count], p.prefix[0..p.prefix_count]) or !std.meta.eql(v.public.policy, p.public.policy) or !std.meta.eql(v.public.limits, p.public.limits)) return error.MutatedInputRequestNode;
                    try v.public.validate();
                },
            }
        }
    }
};
pub const init = Owner.init;
pub const Values = struct {
    public: *const Owner,
    pub fn validate(self: Values) !void {
        try self.public.validate();
    }
    pub fn requireConfig(self: Values, config: core.pcs.PcsConfig) !void {
        if (!std.meta.eql(config, self.public.policy.specs[self.public.policy.index].geometry.config)) return error.WidePublicWindowsSecurityMismatch;
    }
    pub fn at(self: Values, wire: Wire) anyerror![4]M {
        if (wire.kind == .output_slot) {
            const value = try self.public.summary.cell(wire.coordinate);
            return if (wire.part) |part| .{ value[part], M.zero(), M.zero(), M.zero() } else value;
        }
        const offset: u32 = if (self.public.carrier != null) 1 else 0;
        if (wire.child < offset) {
            if (wire.kind != .child_cell) return error.InvalidInputRequestNodeCell;
            const value = try self.public.carrier.?.cell(wire.coordinate);
            return if (wire.part) |part| .{ value[part], M.zero(), M.zero(), M.zero() } else value;
        }
        const index = wire.child - offset;
        if (index >= self.public.child_count) return error.InvalidInputRequestNodeCell;
        const child = &self.public.children[index].?;
        if (wire.kind == .child_cell) {
            const value = try child.cell(wire.coordinate);
            return if (wire.part) |part| .{ value[part], M.zero(), M.zero(), M.zero() } else value;
        }
        if (wire.kind != .child_term or wire.part != null) return error.InvalidInputRequestNodeCell;
        return switch (child.*) {
            .leaf => |*v| block: {
                const p = self.public.policy.forest.policies[v.ref];
                if (wire.coordinate >= p.schedule.len) return error.InvalidInputRequestNodeCell;
                const values = WB.Values{ .public = &v.public };
                break :block try values.at(p.schedule[wire.coordinate]);
            },
            .node => |v| block: {
                var p = self.public.policy;
                p.index = v.ref;
                const spec = p.specs[v.ref];
                if (wire.coordinate >= spec.schedule.len) return error.InvalidInputRequestNodeCell;
                var owner = try Owner.init(self.public.allocator, p, self.public.limits);
                defer owner.deinit();
                break :block try (Values{ .public = &owner }).at(spec.schedule[wire.coordinate]);
            },
        };
    }
    pub fn mix(self: Values, channel: anytype) !void {
        try self.validate();
        try Layout.mix(self.public.policy, channel);
    }
};
pub fn supply(wires: []const Wire, values: Values, relations: @import("air/universal_challenges.zig").UniversalRelations) !Q {
    _ = try scheduleDigest(wires);
    try values.validate();
    const relation = try relations.getExact(.recursion_wire);
    var total = Q.zero();
    for (wires) |wire| {
        const denominator = try relation.combineBase(&(.{ M.fromCanonical(wire.circuit), M.fromCanonical(wire.wire) } ++ try values.at(wire)));
        if (denominator.isZero()) return error.RecursivePublicDenominatorZero;
        const term = Q.fromBase(M.fromCanonical(wire.uses)).mul(try denominator.inv());
        total = if (wire.negative) total.sub(term) else total.add(term);
    }
    return total;
}
