//! Independently reconstructed ancestor public cells for ONE actual carrier and
//! at most three actual bounded-window roots. This local proof is OPEN for a
//! larger forest/source census; it never accepts metadata as carrier authority.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const C = @import("block_v5_input_tail_receiver_v1.zig");
const CP = @import("block_v5_input_tail_protocol_v1.zig");
const CS = @import("block_v5_input_tail_source_v1.zig");
const W = @import("block_v5_tail_linked_public_windows_receiver_v2.zig");
const WP = @import("block_v5_reusable_tail_linked_public_windows_protocol_v2.zig");
const WS = @import("block_v5_tail_linked_public_windows_source_v2.zig");
const Public = @import("block_v5_tail_linked_public_windows_v2.zig");
const WireBus = @import("block_v5_heterogeneous_scoped_public_bus_v1.zig");
pub const Wire = WireBus.Wire;
pub const scheduleDigest = WireBus.scheduleDigest;
pub const MAX_CONSUMERS = 3;
pub const Limits = struct { max_consumers: usize = MAX_CONSUMERS };
pub const Policy = struct {
    carrier: C.Policy,
    consumers: []const W.Policy,
    /// Selected contiguous local interval, independently pinned by the caller.
    /// A larger job requires a genuine forest coverage proof, not this object.
    first_window: u32,
    window_count: u32,
    pub fn validate(self: Policy) !void {
        try self.carrier.public.require(self.carrier.expected_input);
        if (self.consumers.len == 0 or self.consumers.len > MAX_CONSUMERS or self.window_count == 0) return error.UntrustedInputTailAncestor;
        var cursor = self.first_window;
        for (self.consumers) |p| {
            try p.public.validate();
            if (p.public.first_window != cursor or p.public.input != self.carrier.public or !std.meta.eql(p.public.input_expected, self.carrier.expected_input) or !std.meta.eql(p.public.expected.expected().coverage_digest, self.carrier.public.job.expected().coverage_digest) or !std.meta.eql(p.key.config, self.carrier.key.config)) return error.UntrustedInputTailAncestor;
            cursor = try std.math.add(u32, cursor, @intCast(p.public.instances.len));
        }
        if (cursor != try std.math.add(u32, self.first_window, self.window_count)) return error.UntrustedInputTailAncestor;
    }
};
pub const Descriptor = struct {
    owner: Public.Owner,
    prefix: [32]u32,
    prefix_count: u32,
    pub fn admission(self: *const Descriptor, policy: W.Policy) !WP.Admission {
        return WP.Admission.init(policy.key, policy.expected_id, policy.schedule, .{ .public = &self.owner });
    }
    pub fn cell(self: *const Descriptor, coordinate: u32) ![4]M {
        if (coordinate >= self.prefix_count) return self.owner.cell(coordinate - self.prefix_count);
        return wordCell(self.prefix[coordinate]);
    }
};
fn wordCell(word: u32) [4]M {
    var out: [4]M = undefined;
    for (&out, 0..) |*byte, part| byte.* = M.fromCanonical((word >> @as(u5, @intCast(8 * part))) & 255);
    return out;
}
pub const Owner = struct {
    allocator: std.mem.Allocator,
    budget_owner: ?*Budget,
    policy: Policy,
    limits: Limits,
    carrier: *@import("block_v5_input_tail_public_v1.zig").Owned,
    normalized_carrier: CS.Normalized,
    consumers: []Descriptor,
    pub const complete_source_authority = false;
    pub const complete_block_authority = false;
    pub fn requireComplete(_: *const Owner) !void {
        return error.InputTailForestSourceClosureUnavailable;
    }
    pub fn init(a: std.mem.Allocator, policy: Policy, limits: Limits) !Owner {
        try policy.validate();
        if (limits.max_consumers == 0 or limits.max_consumers > MAX_CONSUMERS or policy.consumers.len > limits.max_consumers) return error.InputTailResourceLimit;
        const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
        errdefer if (lease) |owner| owner.destroy();
        const carrier = policy.carrier.public.retain();
        errdefer carrier.deinit();
        const cp = try CP.Admission.init(policy.carrier.key, policy.carrier.expected_id, carrier, policy.carrier.expected_input);
        const normalized = try CS.Normalized.fromAdmission(&cp);
        const consumers = try a.alloc(Descriptor, policy.consumers.len);
        errdefer a.free(consumers);
        var made: usize = 0;
        errdefer for (consumers[0..made]) |*descriptor| descriptor.owner.deinit();
        for (consumers, policy.consumers) |*descriptor, p| {
            descriptor.owner = try Public.init(a, p.public, p.public_limits);
            made += 1;
            const admission = try descriptor.admission(p);
            const prefix = try WS.publicPrefix(&admission);
            descriptor.prefix = prefix.words;
            descriptor.prefix_count = prefix.len;
        }
        return .{ .allocator = a, .budget_owner = lease, .policy = policy, .limits = limits, .carrier = carrier, .normalized_carrier = normalized, .consumers = consumers };
    }
    pub fn deinit(self: *Owner) void {
        const lease = self.budget_owner;
        for (self.consumers) |*descriptor| descriptor.owner.deinit();
        self.allocator.free(self.consumers);
        self.carrier.deinit();
        self.* = undefined;
        if (lease) |owner| owner.destroy();
    }
    pub fn validate(self: *const Owner) !void {
        try self.policy.validate();
        if (self.limits.max_consumers == 0 or self.limits.max_consumers > MAX_CONSUMERS or self.consumers.len > self.limits.max_consumers) return error.MutatedInputTailAncestor;
        if (self.carrier != self.policy.carrier.public or self.consumers.len != self.policy.consumers.len) return error.MutatedInputTailAncestor;
        const cp = try CP.Admission.init(self.policy.carrier.key, self.policy.carrier.expected_id, self.carrier, self.policy.carrier.expected_input);
        const normalized = try CS.Normalized.fromAdmission(&cp);
        if (normalized.count != self.normalized_carrier.count or normalized.public_first != self.normalized_carrier.public_first or self.normalized_carrier.failure != null or !std.mem.eql(u32, normalized.words[0..normalized.count], self.normalized_carrier.words[0..normalized.count])) return error.MutatedInputTailAncestor;
        for (self.consumers, self.policy.consumers) |*descriptor, p| {
            if (!std.meta.eql(descriptor.owner.policy, p.public) or !std.meta.eql(descriptor.owner.limits, p.public_limits)) return error.MutatedInputTailAncestor;
            const admission = try descriptor.admission(p);
            const prefix = try WS.publicPrefix(&admission);
            if (prefix.len != descriptor.prefix_count or !std.mem.eql(u32, prefix.words[0..prefix.len], descriptor.prefix[0..prefix.len])) return error.MutatedInputTailAncestor;
        }
    }
};
pub const Values = struct {
    public: *const Owner,
    pub fn validate(self: Values) !void {
        try self.public.validate();
    }
    pub fn requireConfig(self: Values, config: core.pcs.PcsConfig) !void {
        if (!std.meta.eql(config, self.public.policy.carrier.key.config)) return error.WidePublicWindowsSecurityMismatch;
        for (self.public.policy.consumers) |p| if (!std.meta.eql(config, p.key.config)) return error.WidePublicWindowsSecurityMismatch;
    }
    pub fn at(self: Values, wire: Wire) ![4]M {
        var value: [4]M = undefined;
        switch (wire.kind) {
            .child_cell => {
                value = if (wire.child == 0) try self.public.normalized_carrier.cell(wire.coordinate) else block: {
                    if (wire.child > self.public.consumers.len) return error.UntrustedInputTailAncestorCell;
                    break :block try self.public.consumers[wire.child - 1].cell(wire.coordinate);
                };
            },
            .child_term => {
                if (wire.child == 0 or wire.child > self.public.consumers.len or wire.part != null) return error.UntrustedInputTailAncestorCell;
                const p = self.public.policy.consumers[wire.child - 1];
                if (wire.coordinate >= p.schedule.len) return error.UntrustedInputTailAncestorCell;
                const values = @import("block_v5_tail_linked_public_windows_bus_v2.zig").Values{ .public = &self.public.consumers[wire.child - 1].owner };
                return values.at(p.schedule[wire.coordinate]);
            },
            else => return error.UntrustedInputTailAncestorCell,
        }
        return if (wire.part) |part| .{ value[part], M.zero(), M.zero(), M.zero() } else value;
    }
    pub fn mix(self: Values, channel: anytype) !void {
        try self.validate();
        channel.mixU32s(&.{ 0x42355441, 1, self.public.policy.first_window, self.public.policy.window_count, @intCast(self.public.consumers.len) });
        const cp = try CP.Admission.init(self.public.policy.carrier.key, self.public.policy.carrier.expected_id, self.public.carrier, self.public.policy.carrier.expected_input);
        try cp.mix(channel);
        for (self.public.consumers, self.public.policy.consumers) |*descriptor, p| {
            const admitted = try descriptor.admission(p);
            try admitted.mix(channel);
        }
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

pub const init = Owner.init;
