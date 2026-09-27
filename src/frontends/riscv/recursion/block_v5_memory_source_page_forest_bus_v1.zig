//! Bounded PAGE source summary public supply. All proposals are independently
//! reconstructed; exact child verification and byte merges remain mandatory.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Plan = @import("block_v5_memory_source_page_forest_plan_v1.zig");
const A = @import("block_v5_memory_source_page_forest_algebra_v1.zig");
const Leaves = @import("block_v5_memory_source_page_forest_leaf_v1.zig");
const Norm = @import("block_v5_memory_source_page_forest_normalizer_v1.zig");
const OriginalBus = @import("block_v5_memory_source_page_recursive_public_bus_v1.zig");
const OriginalProtocol = @import("block_v5_reusable_memory_source_page_parent_protocol_v1.zig");
const Protocol = @import("block_v5_memory_source_page_forest_protocol_v1.zig");
const B = @import("block_v5_heterogeneous_scoped_public_bus_v1.zig");
pub const Wire = B.Wire;
pub fn scheduleDigest(wires: []const Wire) ![32]u8 {
    if (wires.len != 0) return B.scheduleDigest(wires);
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x50474657, 16, 0 });
    return channel.digestBytes();
}
pub const Spec = struct { geometry: @import("blake3_execution_parent_protocol.zig").Key, schedule: []const Wire, expected_id: [32]u8 };
pub const Limits = struct { normalization: Norm.Limits = .{} };
pub const Policy = struct {
    forest: *const Plan.Owned,
    expected_plan: [32]u8,
    specs: []const Spec,
    index: u32,
    pub fn validateSources(self: Policy) !void {
        const node = try self.forest.node(self.index, self.expected_plan);
        if (self.specs.len != self.forest.geometry.nodes.len) return error.UntrustedPageForestNode;
        for (node.children[0..node.child_count]) |ref| if (ref == .node) {
            var lower = self;
            lower.index = ref.node;
            try lower.validateKey();
        };
    }
    fn validateKey(self: Policy) !void {
        if (self.index >= self.specs.len) return error.UntrustedPageForestNode;
        const spec = self.specs[self.index];
        const config = self.forest.context.fold_plan.config;
        if (!std.meta.eql(spec.geometry.config, config) or !std.meta.eql(spec.geometry.context.child_config, config)) return error.UntrustedPageForestNode;
        const key = try Protocol.Key.fromGeometry(spec.geometry, spec.schedule);
        if (spec.schedule.len != 0 or !std.meta.eql(try key.identity(), spec.expected_id)) return error.UntrustedPageForestNode;
    }
    pub fn validate(self: Policy) !void {
        try self.validateSources();
        try self.validateKey();
    }
};
pub const CLAIM_FIRST: u32 = 49;
pub const Summary = struct {
    policy: Policy,
    value: Plan.Summary,
    header: [9]u32,
    pub fn init(policy: Policy) !Summary {
        try policy.validateSources();
        const value = policy.forest.summaries[policy.index];
        try A.canonical(value.claims);
        return .{ .policy = policy, .value = value, .header = .{ 0x50474653, 1, policy.index, value.range.first, value.range.count, value.raw_pages, value.fold_pages, value.raw_rows, value.fold_rows } };
    }
    pub fn validate(self: *const Summary) !void {
        const expected = try Summary.init(self.policy);
        if (!std.meta.eql(self.value, expected.value) or !std.meta.eql(self.header, expected.header)) return error.MutatedPageForestSummary;
    }
    pub fn mix(self: *const Summary, channel: anytype) void {
        channel.mixU32s(&self.header);
        channel.mixRoot(self.policy.forest.source);
        channel.mixRoot(self.policy.forest.seal);
        channel.mixRoot(self.policy.forest.epoch);
        channel.mixRoot(self.policy.forest.base);
        channel.mixRoot(self.policy.expected_plan);
        channel.mixFelts(&self.value.claims);
    }
    pub fn cell(self: *const Summary, index: u32) ![4]M {
        if (index >= CLAIM_FIRST + 4 * A.CLAIM_COUNT) return error.InvalidPageForestCell;
        var word: u32 = undefined;
        if (index < 9) {
            word = self.header[index];
        } else if (index < CLAIM_FIRST) {
            const roots = [_][32]u8{ self.policy.forest.source, self.policy.forest.seal, self.policy.forest.epoch, self.policy.forest.base, self.policy.expected_plan };
            const relative = index - 9;
            word = std.mem.readInt(u32, roots[relative / 8][4 * (relative % 8) ..][0..4], .little);
        } else {
            const relative = index - CLAIM_FIRST;
            word = self.value.claims[relative / 4].toM31Array()[relative % 4].v;
        }
        var out: [4]M = undefined;
        for (&out, 0..) |*byte, part| byte.* = M.fromCanonical((word >> @as(u5, @intCast(8 * part))) & 255);
        return out;
    }
};
const RawValue = OriginalBus.ForKind(.raw).Values;
const FoldValue = OriginalBus.ForKind(.fold).Values;
pub const Child = union(enum) { raw: struct { policy: Leaves.ForKind(.raw).Policy, values: RawValue, normal: Norm.Normalized }, fold: struct { policy: Leaves.ForKind(.fold).Policy, values: FoldValue, normal: Norm.Normalized }, node: struct { policy: Policy, summary: Summary, normal: Norm.Normalized } };
pub const Owner = struct {
    allocator: std.mem.Allocator,
    allocation_owner: ?*Budget,
    policy: Policy,
    limits: Limits,
    summary: Summary,
    children: [4]?Child,
    child_count: u32,
    pub const complete_source_authority = false;
    pub const complete_block_authority = false;
    pub fn init(a: std.mem.Allocator, policy: Policy, limits: Limits) !Owner {
        try policy.validate();
        return prepareSources(a, policy, limits);
    }
    /// Source-only template preparation has no current-node key authority.
    /// A real Protocol.Admission still requires the independently derived key.
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
                .leaf => |ordinal| if (ordinal < policy.forest.raw.len) block: {
                    const original = policy.forest.raw[ordinal];
                    try original.validate();
                    var values = try RawValue.init(a, original.admitted, original.claims);
                    errdefer values.deinit();
                    const admission = try OriginalProtocol.ForKind(.raw).Admission.init(original.key, original.expected_id, original.schedule, values);
                    if (values.statement.component_claim_first < A.CLAIM_COUNT) return error.UntrustedPageForestClaimLayout;
                    const normal = try Norm.Normalized.initWithWords(a, &admission, values.statement.felts, try A.semanticClaimOffset(values.statement.component_claim_first), values.statement.words, original.normalization);
                    break :block .{ .raw = .{ .policy = original, .values = values, .normal = normal } };
                } else block: {
                    const original = policy.forest.fold[ordinal - policy.forest.raw.len];
                    try original.validate();
                    var values = try FoldValue.init(a, original.admitted, original.claims);
                    errdefer values.deinit();
                    const admission = try OriginalProtocol.ForKind(.fold).Admission.init(original.key, original.expected_id, original.schedule, values);
                    if (values.statement.component_claim_first < A.CLAIM_COUNT) return error.UntrustedPageForestClaimLayout;
                    const normal = try Norm.Normalized.initWithWords(a, &admission, values.statement.felts, try A.semanticClaimOffset(values.statement.component_claim_first), values.statement.words, original.normalization);
                    break :block .{ .fold = .{ .policy = original, .values = values, .normal = normal } };
                },
                .node => |ordinal| block: {
                    var lower = policy;
                    lower.index = ordinal;
                    const lower_summary = try Summary.init(lower);
                    // The exact new parent transcript contains its compact self statement,
                    // never any full descendant statement. Boundaries/uses still reconstruct
                    // from independent original child policy when the verifier requests them.
                    const direct = Direct{ .policy = lower, .summary = &lower_summary };
                    const normal = try Norm.Normalized.initWithWords(a, &direct, &lower_summary.value.claims, 0, &lower_summary.header, limits.normalization);
                    break :block .{ .node = .{ .policy = lower, .summary = lower_summary, .normal = normal } };
                },
            };
            made += 1;
        }
        return .{ .allocator = a, .allocation_owner = lease, .policy = policy, .limits = limits, .summary = summary, .children = children, .child_count = node.child_count };
    }
    pub fn deinit(self: *Owner) void {
        const lease = self.allocation_owner;
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
        if (!std.meta.eql(self.summary.policy, self.policy)) return error.UntrustedPageForestNode;
        const node = try self.policy.forest.node(self.policy.index, self.policy.expected_plan);
        if (self.child_count != node.child_count) return error.UntrustedPageForestNode;
        for (self.children[0..self.child_count], node.children[0..node.child_count]) |*optional, ref| {
            const child = &optional.*.?;
            switch (child.*) {
                .raw => |*value| {
                    if (ref != .leaf or ref.leaf >= self.policy.forest.raw.len or !std.meta.eql(value.policy, self.policy.forest.raw[ref.leaf])) return error.UntrustedPageForestNode;
                    const admission = try OriginalProtocol.ForKind(.raw).Admission.init(value.policy.key, value.policy.expected_id, value.policy.schedule, value.values);
                    try value.normal.requireWithWords(self.allocator, &admission, value.values.statement.felts, try A.semanticClaimOffset(value.values.statement.component_claim_first), value.values.statement.words, value.policy.normalization);
                },
                .fold => |*value| {
                    if (ref != .leaf or ref.leaf < self.policy.forest.raw.len or !std.meta.eql(value.policy, self.policy.forest.fold[ref.leaf - self.policy.forest.raw.len])) return error.UntrustedPageForestNode;
                    const admission = try OriginalProtocol.ForKind(.fold).Admission.init(value.policy.key, value.policy.expected_id, value.policy.schedule, value.values);
                    try value.normal.requireWithWords(self.allocator, &admission, value.values.statement.felts, try A.semanticClaimOffset(value.values.statement.component_claim_first), value.values.statement.words, value.policy.normalization);
                },
                .node => |*value| {
                    if (ref != .node or value.policy.index != ref.node or value.policy.forest != self.policy.forest or !std.meta.eql(value.policy.expected_plan, self.policy.expected_plan) or value.policy.specs.ptr != self.policy.specs.ptr or value.policy.specs.len != self.policy.specs.len) return error.UntrustedPageForestNode;
                    try value.summary.validate();
                    const direct = Direct{ .policy = value.policy, .summary = &value.summary };
                    try value.normal.requireWithWords(self.allocator, &direct, &value.summary.value.claims, 0, &value.summary.header, self.limits.normalization);
                },
            }
        }
    }
};
fn deinitChild(child: *Child) void {
    switch (child.*) {
        .raw => |*v| {
            v.normal.deinit();
            v.values.deinit();
        },
        .fold => |*v| {
            v.normal.deinit();
            v.values.deinit();
        },
        .node => |*v| v.normal.deinit(),
    }
    child.* = undefined;
}
/// One canonical new transcript kernel, shared by actual Protocol.Admission
/// and the exact lazy node normalizer. No duplicate channel equations.
pub const Direct = struct {
    policy: Policy,
    summary: *const Summary,
    pub fn mix(self: *const Direct, channel: anytype) !void {
        try self.policy.validate();
        const spec = self.policy.specs[self.policy.index];
        channel.mixU32s(&.{ 0x42354d50, 16, @intFromEnum(spec.geometry.profile) });
        spec.geometry.config.mixInto(channel);
        channel.mixRoot(spec.expected_id);
        self.summary.mix(channel);
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
    pub fn at(self: Values, wire: Wire) ![4]M {
        if (wire.kind == .output_slot) {
            const value = try self.public.summary.cell(wire.coordinate);
            return if (wire.part) |part| .{ value[part], M.zero(), M.zero(), M.zero() } else value;
        }
        if (wire.child >= self.public.child_count) return error.InvalidPageForestCell;
        const child = &self.public.children[wire.child].?;
        if (wire.kind == .child_cell) {
            const value = switch (child.*) {
                .raw => |*v| try v.normal.cell(wire.coordinate),
                .fold => |*v| try v.normal.cell(wire.coordinate),
                .node => |*v| try v.normal.cell(wire.coordinate),
            };
            return if (wire.part) |part| .{ value[part], M.zero(), M.zero(), M.zero() } else value;
        }
        if (wire.kind != .child_term or wire.part != null) return error.InvalidPageForestCell;
        return switch (child.*) {
            .raw => |*v| block: {
                if (wire.coordinate >= v.policy.schedule.len) return error.InvalidPageForestCell;
                const w = v.policy.schedule[wire.coordinate];
                break :block try v.values.at(w.source, w.coordinate);
            },
            .fold => |*v| block: {
                if (wire.coordinate >= v.policy.schedule.len) return error.InvalidPageForestCell;
                const w = v.policy.schedule[wire.coordinate];
                break :block try v.values.at(w.source, w.coordinate);
            },
            .node => return error.ClosedPageForestNodeHasNoPublicTerms,
        };
    }
};
/// All local tuple suppliers are actual fixed-boundary AIR in the node.
/// No descendant packed supplier schedule crosses a node boundary.
pub fn supply(wires: []const Wire, values: Values, relations: @import("air/universal_challenges.zig").UniversalRelations) !Q {
    _ = relations;
    if (wires.len != 0) return error.ClosedPageForestNodeHasNoPublicTerms;
    try values.validate();
    return Q.zero();
}
/// Source-only row preparation cannot confer current-node key authority.
pub const SourceValues = struct {
    public: *const Owner,
    pub fn validate(self: @This()) !void {
        try self.public.validateSources();
    }
    pub fn at(self: @This(), wire: Wire) ![4]M {
        return (Values{ .public = self.public }).at(wire);
    }
};

pub const init = Owner.init;
