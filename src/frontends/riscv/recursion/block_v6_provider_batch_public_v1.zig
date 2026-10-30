//! Direct heterogeneous BASE-provider public supply. Every provider claim is
//! still open until the independently derived complete global equations close it.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
pub const Family = @import("../prover/block_v5_recursive_provider_family_v1.zig").Family;
pub const VERSION: u32 = 1;
pub const MAX_CHILDREN: usize = 16;
pub fn Definition(comptime family: Family) type {
    return @import("../prover/block_v5_recursive_provider_definition_v1.zig").ForFamily(family);
}
pub const Child = union(Family) {
    range16: Definition(.range16).Bus.Values,
    ram_lanes: Definition(.ram_lanes).Bus.Values,
    program_table: Definition(.program_table).Bus.Values,
    native_lookup: Definition(.native_lookup).Bus.Values,
    pub fn validate(self: Child) !void {
        switch (self) {
            inline else => |value| try value.validate(),
        }
    }
    pub fn index(self: Child) u32 {
        return switch (self) {
            .range16 => |v| v.shard.index,
            .ram_lanes => |v| v.pin.index,
            .program_table => |v| v.index,
            .native_lookup => |v| v.plan.index,
        };
    }
    pub fn expected(self: Child) Expected {
        return switch (self) {
            inline else => |value, family| .{
                .family = family,
                .index = self.index(),
                .template = value.template,
                .sealed = value.sealed,
                .roots = if (family == .ram_lanes) value.pin.roots else value.roots,
            },
        };
    }
    pub fn mix(self: Child, channel: anytype) void {
        channel.mixU32s(&.{@intFromEnum(std.meta.activeTag(self))});
        switch (self) {
            inline else => |value| value.mix(channel),
        }
    }
};
pub const Expected = struct { family: Family, index: u32, template: [32]u8, sealed: [32]u8, roots: [2][32]u8 };
pub const Source = union(Family) {
    range16: Definition(.range16).Bus.Source,
    ram_lanes: Definition(.ram_lanes).Bus.Source,
    program_table: Definition(.program_table).Bus.Source,
    native_lookup: Definition(.native_lookup).Bus.Source,
};
pub const Wire = struct { circuit: u32, wire: u32, uses: u32, child: u8, source: Source, coordinate: u32 };
pub const Values = struct {
    children: []const Child,
    pub fn validate(self: Values) !void {
        if (self.children.len == 0 or self.children.len > MAX_CHILDREN) return error.InvalidProviderBatchCount;
        var previous: ?Expected = null;
        for (self.children) |child| {
            try child.validate();
            const value = child.expected();
            if (previous) |old| {
                if (!std.meta.eql(old.sealed, value.sealed)) return error.MixedProviderBatchSeal;
                if (@intFromEnum(old.family) > @intFromEnum(value.family) or
                    (old.family == value.family and old.index >= value.index)) return error.InvalidProviderBatchOrder;
            }
            previous = value;
        }
    }
    pub fn requireRoster(self: Values, expected: []const Expected) !void {
        try self.validate();
        if (self.children.len != expected.len) return error.UntrustedProviderBatchRoster;
        for (self.children, expected) |child, pin| if (!std.meta.eql(child.expected(), pin)) return error.UntrustedProviderBatchRoster;
    }
    pub fn at(self: Values, wire: Wire) ![4]M {
        if (wire.child >= self.children.len) return error.InvalidProviderBatchWire;
        const child = self.children[wire.child];
        if (std.meta.activeTag(child) != std.meta.activeTag(wire.source)) return error.InvalidProviderBatchWire;
        return switch (wire.source) {
            inline else => |source, family| @field(child, @tagName(family)).at(source, wire.coordinate),
        };
    }
    pub fn mix(self: Values, channel: anytype) void {
        channel.mixU32s(&.{ 0x42365056, VERSION, @intCast(self.children.len) });
        for (self.children) |child| child.mix(channel);
    }
};
pub fn rosterDigest(expected: []const Expected) ![32]u8 {
    if (expected.len == 0 or expected.len > MAX_CHILDREN) return error.InvalidProviderBatchCount;
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42365052, VERSION, @intCast(expected.len) });
    for (expected, 0..) |entry, i| {
        if (entry.index >= core.fields.m31.Modulus) return error.UntrustedProviderBatchRoster;
        if (i != 0) {
            const old = expected[i - 1];
            if (!std.meta.eql(old.sealed, entry.sealed) or @intFromEnum(old.family) > @intFromEnum(entry.family) or
                (old.family == entry.family and old.index >= entry.index)) return error.UntrustedProviderBatchRoster;
        }
        for ([_][32]u8{ entry.template, entry.sealed, entry.roots[0], entry.roots[1] }) |digest| {
            if (std.mem.allEqual(u8, &digest, 0)) return error.UntrustedProviderBatchRoster;
            channel.mixRoot(digest);
        }
        channel.mixU32s(&.{ @intFromEnum(entry.family), entry.index });
    }
    return channel.digestBytes();
}
pub fn scheduleDigest(wires: []const Wire) ![32]u8 {
    if (wires.len == 0 or wires.len > MAX_CHILDREN * 256) return error.InvalidProviderBatchSchedule;
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42365057, VERSION, @intCast(wires.len) });
    for (wires, 0..) |wire, i| {
        if (wire.child >= MAX_CHILDREN or wire.uses == 0 or wire.uses >= core.fields.m31.Modulus or
            wire.circuit >= core.fields.m31.Modulus or wire.wire >= core.fields.m31.Modulus) return error.InvalidProviderBatchSchedule;
        if (i != 0 and (wires[i - 1].circuit > wire.circuit or
            (wires[i - 1].circuit == wire.circuit and wires[i - 1].wire >= wire.wire))) return error.InvalidProviderBatchSchedule;
        const source = switch (wire.source) {
            inline else => |value, family| checked: {
                // Delegate coordinate bounds to the original family schedule.
                const D = Definition(family);
                _ = try D.Bus.scheduleDigest(&.{.{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .source = value, .coordinate = wire.coordinate }});
                break :checked @intFromEnum(value);
            },
        };
        channel.mixU32s(&.{ wire.circuit, wire.wire, wire.uses, wire.child, @intFromEnum(std.meta.activeTag(wire.source)), source, wire.coordinate });
    }
    return channel.digestBytes();
}
pub fn supply(wires: []const Wire, values: Values, relations: @import("air/universal_challenges.zig").UniversalRelations) !Q {
    _ = try scheduleDigest(wires);
    try values.validate();
    const relation = try relations.getExact(.recursion_wire);
    var result = Q.zero();
    for (wires) |wire| {
        const denominator = try relation.combineBase(&(.{ M.fromCanonical(wire.circuit), M.fromCanonical(wire.wire) } ++ try values.at(wire)));
        if (denominator.isZero()) return error.ProviderBatchPublicDenominatorZero;
        result = result.add(Q.fromBase(M.fromCanonical(wire.uses)).mul(try denominator.inv()));
    }
    return result;
}
