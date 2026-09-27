//! Per-node compact public statements. Host summaries are proposals whose
//! actual byte merges and original child verifiers are proved in the node.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const A = @import("block_v5_ram_range_forest_authority_v1.zig");
const G = @import("block_v5_ram_range_forest_plan_v1.zig");
const Norm = @import("block_v5_memory_source_page_forest_normalizer_v1.zig");
const P = @import("block_v5_ram_range_forest_protocol_v1.zig");
const Original = @import("block_v5_heterogeneous_scoped_public_bus_v1.zig");
pub const Wire = Original.Wire;
pub const Spec = struct { geometry: @import("blake3_execution_parent_protocol.zig").Key, expected_id: [32]u8 };
pub const Limits = struct { normalization: Norm.Limits = .{} };
pub const Policy = struct {
    forest: *const A.Owned,
    expected_plan: [32]u8,
    specs: []const Spec,
    index: u32,
    pub fn validateSources(self: @This()) !void {
        const node = try self.forest.node(self.index, self.expected_plan);
        if (self.specs.len != self.forest.geometry.nodes.len) return error.UntrustedRamRangeForestNode;
        for (node.children[0..node.child_count]) |ref| if (ref == .node) {
            var lower = self;
            lower.index = ref.node;
            try lower.validateKey();
        };
    }
    pub fn validateKey(self: @This()) !void {
        if (self.index >= self.specs.len) return error.UntrustedRamRangeForestNode;
        const spec = self.specs[self.index];
        const config = self.forest.memory.seal.config;
        if (!std.meta.eql(spec.geometry.config, config) or !std.meta.eql(spec.geometry.context.child_config, config)) return error.UntrustedRamRangeForestNode;
        const key = try P.Key.fromGeometry(spec.geometry, &.{});
        if (!std.meta.eql(try key.identity(), spec.expected_id)) return error.UntrustedRamRangeForestNode;
    }
    pub fn validate(self: @This()) !void {
        try self.validateSources();
        try self.validateKey();
    }
};
pub const CLAIM_FIRST: u32 = 36;
pub const Summary = struct {
    policy: Policy,
    value: A.Claims,
    header: [12]u32,
    pub fn init(policy: Policy) !Summary {
        try policy.validateSources();
        const n = try policy.forest.node(policy.index, policy.expected_plan);
        const value = policy.forest.summaries[policy.index];
        for (value) |q| for (q.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.UntrustedRamRangeForestClaim;
        return .{ .policy = policy, .value = value, .header = .{ 0x52524653, G.VERSION, policy.index, @intFromEnum(n.kind), n.lanes.first, n.lanes.count, n.shards.first, n.shards.count, @truncate(n.events), @truncate(n.events >> 32), @truncate(n.requests), @truncate(n.requests >> 32) } };
    }
    pub fn validate(self: *const Summary) !void {
        const expected = try Summary.init(self.policy);
        if (!std.meta.eql(self.value, expected.value) or !std.meta.eql(self.header, expected.header)) return error.MutatedRamRangeForestSummary;
    }
    pub fn mix(self: *const Summary, channel: anytype) void {
        channel.mixU32s(&self.header);
        channel.mixRoot(self.policy.forest.sealed.digest);
        channel.mixRoot(self.policy.forest.memory.seal.memory_plan_digest);
        channel.mixRoot(self.policy.expected_plan);
        channel.mixFelts(&self.value);
    }
    pub fn cell(self: *const Summary, index: u32) ![4]M {
        if (index >= CLAIM_FIRST + 4 * A.CLAIM_COUNT) return error.InvalidRamRangeForestCell;
        const word: u32 = if (index < 12) self.header[index] else if (index < CLAIM_FIRST) blk: {
            const roots = [_][32]u8{ self.policy.forest.sealed.digest, self.policy.forest.memory.seal.memory_plan_digest, self.policy.expected_plan };
            const pos = index - 12;
            break :blk std.mem.readInt(u32, roots[pos / 8][4 * (pos % 8) ..][0..4], .little);
        } else self.value[(index - CLAIM_FIRST) / 4].toM31Array()[(index - CLAIM_FIRST) % 4].v;
        var out: [4]M = undefined;
        for (&out, 0..) |*byte, part| byte.* = M.fromCanonical((word >> @as(u5, @intCast(8 * part))) & 255);
        return out;
    }
};
pub const Child = union(enum) { ram: struct { policy: A.Ram.Policy, normal: A.Ram.Normalized }, range: struct { policy: A.Range.Policy, normal: A.Range.Normalized }, node: struct { policy: Policy, summary: Summary, normal: Norm.Normalized } };
pub const Owner = struct {
    a: std.mem.Allocator,
    lease: ?*Budget,
    policy: Policy,
    limits: Limits,
    summary: Summary,
    children: [4]?Child,
    child_count: u32,
    pub const complete_block_authority = false;
    pub fn init(a: std.mem.Allocator, policy: Policy, limits: Limits) !Owner {
        try policy.validate();
        return Owner.prepareSources(a, policy, limits);
    }
    pub fn prepareSources(a: std.mem.Allocator, policy: Policy, limits: Limits) !Owner {
        try policy.validateSources();
        const summary = try Summary.init(policy);
        const node = try policy.forest.node(policy.index, policy.expected_plan);
        const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
        errdefer if (lease) |owner| owner.destroy();
        var children: [4]?Child = @splat(null);
        var made: usize = 0;
        errdefer for (children[0..made]) |*child| deinitChild(&child.*.?);
        for (node.children[0..node.child_count], 0..) |ref, i| {
            children[i] = switch (ref) {
                .ram => |ordinal| blk: {
                    const p = policy.forest.ram[ordinal];
                    const admission = try p.authority();
                    break :blk .{ .ram = .{ .policy = p, .normal = try A.Ram.Normalized.init(a, &admission, p.limits) } };
                },
                .range => |ordinal| blk: {
                    const p = policy.forest.range[ordinal];
                    const admission = try p.authority();
                    break :blk .{ .range = .{ .policy = p, .normal = try A.Range.Normalized.init(a, &admission, p.limits) } };
                },
                .node => |ordinal| blk: {
                    var p = policy;
                    p.index = ordinal;
                    const value = try Summary.init(p);
                    const direct = Direct{ .policy = p, .summary = &value };
                    const normal = try Norm.Normalized.initWithWords(a, &direct, &value.value, 0, &value.header, limits.normalization);
                    break :blk .{ .node = .{ .policy = p, .summary = value, .normal = normal } };
                },
            };
            made += 1;
        }
        return .{ .a = a, .lease = lease, .policy = policy, .limits = limits, .summary = summary, .children = children, .child_count = node.child_count };
    }
    pub fn deinit(self: *Owner) void {
        const lease = self.lease;
        for (self.children[0..self.child_count]) |*child| deinitChild(&child.*.?);
        self.* = undefined;
        if (lease) |owner| owner.destroy();
    }
    pub fn validate(self: *const Owner) !void {
        try self.policy.validate();
        try self.validateSources();
    }
    pub fn validateSources(self: *const Owner) !void {
        try self.policy.validateSources();
        try self.summary.validate();
        if (!std.meta.eql(self.summary.policy, self.policy)) return error.UntrustedRamRangeForestNode;
        const node = try self.policy.forest.node(self.policy.index, self.policy.expected_plan);
        if (node.child_count != self.child_count) return error.UntrustedRamRangeForestNode;
        for (self.children[0..self.child_count], node.children[0..node.child_count]) |*optional, ref| {
            const child = &optional.*.?;
            switch (child.*) {
                .ram => |*v| {
                    if (ref != .ram or !std.meta.eql(v.policy, self.policy.forest.ram[ref.ram])) return error.UntrustedRamRangeForestNode;
                    const admission = try v.policy.authority();
                    try v.normal.require(self.a, &admission, v.policy.limits);
                },
                .range => |*v| {
                    if (ref != .range or !std.meta.eql(v.policy, self.policy.forest.range[ref.range])) return error.UntrustedRamRangeForestNode;
                    const admission = try v.policy.authority();
                    try v.normal.require(self.a, &admission, v.policy.limits);
                },
                .node => |*v| {
                    if (ref != .node or v.policy.index != ref.node or v.policy.forest != self.policy.forest or !std.meta.eql(v.policy.expected_plan, self.policy.expected_plan) or v.policy.specs.ptr != self.policy.specs.ptr or v.policy.specs.len != self.policy.specs.len) return error.UntrustedRamRangeForestNode;
                    try v.summary.validate();
                    const direct = Direct{ .policy = v.policy, .summary = &v.summary };
                    try v.normal.requireWithWords(self.a, &direct, &v.summary.value, 0, &v.summary.header, self.limits.normalization);
                },
            }
        }
    }
};
fn deinitChild(child: *Child) void {
    switch (child.*) {
        .ram => |*v| v.normal.deinit(),
        .range => |*v| v.normal.deinit(),
        .node => |*v| v.normal.deinit(),
    }
    child.* = undefined;
}
pub const Direct = struct {
    policy: Policy,
    summary: *const Summary,
    pub fn mix(self: *const @This(), channel: anytype) !void {
        try self.policy.validate();
        const spec = self.policy.specs[self.policy.index];
        channel.mixU32s(&.{ 0x42354d50, G.VERSION, @intFromEnum(spec.geometry.profile) });
        spec.geometry.config.mixInto(channel);
        channel.mixRoot(spec.expected_id);
        self.summary.mix(channel);
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
    pub fn mix(self: @This(), channel: anytype) !void {
        try self.validate();
        self.public.summary.mix(channel);
    }
    pub fn at(self: @This(), wire: Wire) ![4]M {
        if (wire.kind == .output_slot) {
            const value = try self.public.summary.cell(wire.coordinate);
            return if (wire.part) |part| .{ value[part], M.zero(), M.zero(), M.zero() } else value;
        }
        if (wire.child >= self.public.child_count) return error.InvalidRamRangeForestCell;
        const child = &self.public.children[wire.child].?;
        if (wire.kind == .child_cell) {
            const value = switch (child.*) {
                .ram => |*v| try v.normal.cell(wire.coordinate),
                .range => |*v| try v.normal.cell(wire.coordinate),
                .node => |*v| try v.normal.cell(wire.coordinate),
            };
            return if (wire.part) |part| .{ value[part], M.zero(), M.zero(), M.zero() } else value;
        }
        if (wire.kind != .child_term or wire.part != null) return error.InvalidRamRangeForestCell;
        return switch (child.*) {
            .ram => |*v| blk: {
                if (wire.coordinate >= v.policy.schedule.len) return error.InvalidRamRangeForestCell;
                const w = v.policy.schedule[wire.coordinate];
                const admission = try v.policy.authority();
                break :blk try admission.values.at(w.source, w.coordinate);
            },
            .range => |*v| blk: {
                if (wire.coordinate >= v.policy.schedule.len) return error.InvalidRamRangeForestCell;
                const w = v.policy.schedule[wire.coordinate];
                const admission = try v.policy.authority();
                break :blk try admission.values.at(w.source, w.coordinate);
            },
            .node => error.ClosedRamRangeForestHasNoPublicTerms,
        };
    }
};
pub const SourceValues = struct {
    public: *const Owner,
    pub fn validate(self: @This()) !void {
        try self.public.validateSources();
    }
    pub fn at(self: @This(), wire: Wire) ![4]M {
        return (Values{ .public = self.public }).at(wire);
    }
};
pub fn scheduleDigest(wires: []const Wire) ![32]u8 {
    if (wires.len != 0) return error.ClosedRamRangeForestHasNoPublicTerms;
    var c = core.channel.blake3.Channel{};
    c.mixU32s(&.{ 0x52524657, G.VERSION, 0 });
    return c.digestBytes();
}
pub fn supply(wires: []const Wire, values: Values, relations: @import("air/universal_challenges.zig").UniversalRelations) !Q {
    _ = relations;
    _ = try scheduleDigest(wires);
    try values.validate();
    return Q.zero();
}
pub const init = Owner.init;
