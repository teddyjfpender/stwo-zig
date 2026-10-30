//! One public bus for original native, global-provider and source/caller checks.
//! Authentication of this bus does not replace complete global closure policy.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
pub const Native = @import("block_v6_partitioned_public_bus_v1.zig");
pub const Provider = @import("block_v6_provider_batch_public_v1.zig");
pub const Auxiliary = @import("block_v6_auxiliary_direct_public_v1.zig");
pub const VERSION: u32 = 1;
pub const MAX_CHILDREN: usize = 64;
pub const Kind = enum(u32) { native = 1, provider = 2, auxiliary = 3 };
pub const Expected = union(Kind) {
    native: struct { index: u32, template: [32]u8 },
    provider: Provider.Expected,
    auxiliary: Auxiliary.Expected,
    fn order(self: Expected) [2]u32 {
        return switch (self) {
            .native => |v| .{ 1, v.index },
            .provider => |v| .{ 1 + @intFromEnum(v.family), v.index },
            .auxiliary => |v| .{ 5 + @intFromEnum(v.family), v.index },
        };
    }
};
pub const Child = union(Kind) {
    native: struct { index: u32, value: Native.Values },
    provider: Provider.Child,
    auxiliary: Auxiliary.Child,
    pub fn expected(self: Child) Expected {
        return switch (self) {
            .native => |v| .{ .native = .{ .index = v.index, .template = v.value.template } },
            .provider => |v| .{ .provider = v.expected() },
            .auxiliary => |v| .{ .auxiliary = v.expected() },
        };
    }
    pub fn clone(self: Child, a: std.mem.Allocator) !Child {
        return switch (self) {
            .native => |v| .{ .native = .{ .index = v.index, .value = try v.value.clone(a) } },
            .provider => self,
            .auxiliary => |v| switch (v.value) {
                .caller_arithmetic => self,
                inline else => |value, family| .{ .auxiliary = .{ .index = v.index, .value = @unionInit(Auxiliary.Value, @tagName(family), try value.clone(a)) } },
            },
        };
    }
    pub fn deinit(self: *Child) void {
        switch (self.*) {
            .native => |*v| v.value.deinit(),
            .provider => {},
            .auxiliary => |*v| v.value.deinit(),
        }
        self.* = undefined;
    }
};
pub const Source = union(Kind) { native: Native.Source, provider: Provider.Source, auxiliary: Auxiliary.Source };
pub const Wire = struct { circuit: u32, wire: u32, uses: u32, child: u8, source: Source, coordinate: u32 };
pub const Values = struct {
    children: []const Child,
    pub fn validate(self: Values) !void {
        if (self.children.len == 0 or self.children.len > MAX_CHILDREN) return error.InvalidMixedDirectCount;
        var previous: ?[2]u32 = null;
        var provider_seal: ?[32]u8 = null;
        for (self.children) |child| {
            const order = child.expected().order();
            if (order[1] >= core.fields.m31.Modulus) return error.InvalidMixedDirectRoster;
            if (previous) |old| if (old[0] > order[0] or (old[0] == order[0] and old[1] >= order[1])) return error.InvalidMixedDirectRoster;
            previous = order;
            switch (child) {
                .native => |v| try v.value.validate(),
                .provider => |v| {
                    try v.validate();
                    const seal = v.expected().sealed;
                    if (provider_seal) |old| if (!std.meta.eql(old, seal)) return error.InvalidMixedDirectSeal;
                    provider_seal = seal;
                },
                .auxiliary => |v| try (Auxiliary.Values{ .children = &.{v} }).validate(),
            }
        }
    }
    pub fn requireRoster(self: Values, expected: []const Expected) !void {
        try self.validate();
        _ = try rosterDigest(expected);
        if (expected.len != self.children.len) return error.UntrustedMixedDirectRoster;
        for (self.children, expected) |child, pin| if (!std.meta.eql(child.expected(), pin)) return error.UntrustedMixedDirectRoster;
    }
    pub fn at(self: Values, wire: Wire) ![4]M {
        if (wire.child >= self.children.len) return error.InvalidMixedDirectWire;
        const child = self.children[wire.child];
        if (std.meta.activeTag(child) != std.meta.activeTag(wire.source)) return error.InvalidMixedDirectWire;
        return switch (wire.source) {
            .native => |source| child.native.value.at(source, wire.coordinate),
            .provider => |source| (Provider.Values{ .children = &.{child.provider} }).at(.{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .child = 0, .source = source, .coordinate = wire.coordinate }),
            .auxiliary => |source| (Auxiliary.Values{ .children = &.{child.auxiliary} }).at(.{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .child = 0, .source = source, .coordinate = wire.coordinate }),
        };
    }
    pub fn mix(self: Values, channel: anytype) void {
        channel.mixU32s(&.{ 0x42364d56, VERSION, @intCast(self.children.len) });
        for (self.children) |child| {
            channel.mixU32s(&.{@intFromEnum(std.meta.activeTag(child))});
            switch (child) {
                .native => |v| {
                    channel.mixU32s(&.{v.index});
                    v.value.mix(channel);
                },
                .provider => |v| v.mix(channel),
                .auxiliary => |v| {
                    channel.mixU32s(&.{v.index});
                    v.value.mix(channel);
                },
            }
        }
    }
};
pub fn rosterDigest(roster: []const Expected) ![32]u8 {
    if (roster.len == 0 or roster.len > MAX_CHILDREN) return error.InvalidMixedDirectCount;
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42364d52, VERSION, @intCast(roster.len) });
    var previous: ?[2]u32 = null;
    for (roster) |pin| {
        const order = pin.order();
        if (order[1] >= core.fields.m31.Modulus) return error.InvalidMixedDirectRoster;
        if (previous) |old| if (old[0] > order[0] or (old[0] == order[0] and old[1] >= order[1])) return error.InvalidMixedDirectRoster;
        previous = order;
        channel.mixU32s(&order);
        switch (pin) {
            .native => |v| {
                if (std.mem.allEqual(u8, &v.template, 0)) return error.InvalidMixedDirectRoster;
                channel.mixRoot(v.template);
            },
            .provider => |v| channel.mixRoot(try Provider.rosterDigest(&.{v})),
            .auxiliary => |v| channel.mixRoot(try Auxiliary.rosterDigest(&.{v})),
        }
    }
    return channel.digestBytes();
}
pub fn scheduleDigest(wires: []const Wire) ![32]u8 {
    if (wires.len == 0 or wires.len > 1 << 22) return error.InvalidMixedDirectSchedule;
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42364d57, VERSION, @intCast(wires.len) });
    for (wires, 0..) |wire, i| {
        if (wire.child >= MAX_CHILDREN) return error.InvalidMixedDirectSchedule;
        if (i != 0 and (wires[i - 1].circuit > wire.circuit or (wires[i - 1].circuit == wire.circuit and wires[i - 1].wire >= wire.wire))) return error.InvalidMixedDirectSchedule;
        const digest = switch (wire.source) {
            .native => |s| try Native.scheduleDigest(&.{.{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .source = s, .coordinate = wire.coordinate }}),
            .provider => |s| try Provider.scheduleDigest(&.{.{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .child = 0, .source = s, .coordinate = wire.coordinate }}),
            .auxiliary => |s| try Auxiliary.scheduleDigest(&.{.{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .child = 0, .source = s, .coordinate = wire.coordinate }}),
        };
        channel.mixU32s(&.{ @intFromEnum(std.meta.activeTag(wire.source)), wire.child });
        channel.mixRoot(digest);
    }
    return channel.digestBytes();
}
pub fn supply(wires: []const Wire, values: Values, relations: @import("air/universal_challenges.zig").UniversalRelations) !Q {
    _ = try scheduleDigest(wires);
    try values.validate();
    const relation = try relations.getExact(.recursion_wire);
    var sum = Q.zero();
    for (wires) |wire| {
        const denominator = try relation.combineBase(&(.{ M.fromCanonical(wire.circuit), M.fromCanonical(wire.wire) } ++ try values.at(wire)));
        if (denominator.isZero()) return error.MixedDirectDenominatorZero;
        sum = sum.add(Q.fromBase(M.fromCanonical(wire.uses)).mul(try denominator.inv()));
    }
    return sum;
}
