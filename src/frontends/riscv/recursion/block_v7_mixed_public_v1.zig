//! Exact typed public operands for a bounded mixed original-verifier root.
//! Values are proposals until the parent equation and global closure verify.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../prover/block_v7_execution_epoch_v1.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
pub const VERSION: u32 = 1;
pub const MAX_CHILDREN: usize = 64;
pub const Kind = enum(u32) { native = 0, caller_active = 1, caller = 2, program = 3, lookup = 4, ram = 5, interval = 6, range16 = 7, terminal = 8, memory = 9, window_memory = 10 };
/// Mixed public domains distinguish original protocols even when their open
/// exports share one epoch family. They are never interchangeable keys.
pub fn epochFamily(kind: Kind) E.Family {
    return if (kind == .caller_active) .caller_fused else @enumFromInt(@intFromEnum(kind));
}
pub fn Family(comptime kind: Kind) type {
    return switch (kind) {
        .native => @import("block_v7_native_public_v1.zig"),
        .caller => @import("block_v7_caller_joint_public_v1.zig"),
        .caller_active => @import("block_v7_caller_family_v1.zig").Active.Public,
        .program => @import("block_v7_program_public_v1.zig"),
        .lookup => @import("block_v7_lookup_compact_public_v1.zig"),
        .memory => @import("block_v7_memory_joint_public_v1.zig"),
        .window_memory => @import("block_v7_window_memory_family_v1.zig").Public,
        inline .ram, .interval, .range16, .terminal => |family| @import("block_v7_memory_component_recursive_v1.zig").For(@field(@import("air/block_v7_memory_composition_v1.zig").Family, @tagName(family))).Public,
    };
}
pub const Value = union(Kind) {
    native: Family(.native).Values,
    caller_active: Family(.caller_active).Values,
    caller: Family(.caller).Values,
    program: Family(.program).Values,
    lookup: Family(.lookup).Values,
    ram: Family(.ram).Values,
    interval: Family(.interval).Values,
    range16: Family(.range16).Values,
    terminal: Family(.terminal).Values,
    memory: Family(.memory).Values,
    window_memory: Family(.window_memory).Values,
};
pub const Source = union(Kind) {
    native: @FieldType(Family(.native).Wire, "source"),
    caller_active: @FieldType(Family(.caller_active).Wire, "source"),
    caller: @FieldType(Family(.caller).Wire, "source"),
    program: @FieldType(Family(.program).Wire, "source"),
    lookup: @FieldType(Family(.lookup).Wire, "source"),
    ram: @FieldType(Family(.ram).Wire, "source"),
    interval: @FieldType(Family(.interval).Wire, "source"),
    range16: @FieldType(Family(.range16).Wire, "source"),
    terminal: @FieldType(Family(.terminal).Wire, "source"),
    memory: @FieldType(Family(.memory).Wire, "source"),
    window_memory: @FieldType(Family(.window_memory).Wire, "source"),
};
pub const Expected = struct { kind: Kind, index: u32, template: [32]u8, epoch: [32]u8, entry: E.Entry };
pub const Child = struct {
    index: u32,
    value: Value,
    pub fn deinit(self: *Child) void {
        switch (self.value) {
            inline else => |*v| v.deinit(),
        }
        self.* = undefined;
    }
    pub fn clone(self: Child, a: std.mem.Allocator) !Child {
        return switch (self.value) {
            inline else => |v, kind| .{ .index = self.index, .value = @unionInit(Value, @tagName(kind), try v.clone(a)) },
        };
    }
};
pub const Wire = struct { circuit: u32, wire: u32, uses: u32, child: u8, source: Source, coordinate: u32 };
pub const Values = struct {
    children: []const Child,
    pub fn validate(self: Values) !void {
        if (self.children.len == 0 or self.children.len > MAX_CHILDREN) return error.InvalidV7MixedCount;
        var prior: ?[2]u32 = null;
        var epoch: ?[32]u8 = null;
        for (self.children) |child| {
            try order(&prior, std.meta.activeTag(child.value), child.index);
            switch (child.value) {
                inline else => |v| {
                    try v.validate();
                    const current = try v.statement.digest(v.statement.sealed_offset);
                    if (epoch) |old| {
                        if (!std.meta.eql(old, current)) return error.MixedV7Epochs;
                    } else epoch = current;
                },
            }
        }
    }
    pub fn requireRoster(self: Values, expected: []const Expected) !void {
        try self.validate();
        _ = try rosterDigest(expected);
        if (expected.len != self.children.len) return error.UntrustedV7MixedRoster;
        for (self.children, expected) |child, pin| {
            if (std.meta.activeTag(child.value) != pin.kind or child.index != pin.index) return error.UntrustedV7MixedRoster;
            switch (child.value) {
                inline else => |v| {
                    if (!std.meta.eql(v.template, pin.template) or !std.meta.eql(try v.statement.digest(v.statement.sealed_offset), pin.epoch) or v.roots_count != pin.entry.root_count) return error.UntrustedV7MixedRoster;
                    for (pin.entry.roots[0..pin.entry.root_count], 0..) |root, i| if (!std.meta.eql(root, try v.statement.digest(v.statement.roots_offset[i]))) return error.UntrustedV7MixedRoster;
                },
            }
        }
    }
    pub fn at(self: Values, wire: Wire) ![4]M {
        if (wire.child >= self.children.len) return error.InvalidV7MixedWire;
        const child = self.children[wire.child];
        if (std.meta.activeTag(child.value) != std.meta.activeTag(wire.source)) return error.InvalidV7MixedWire;
        return switch (wire.source) {
            inline else => |source, kind| @field(child.value, @tagName(kind)).at(source, wire.coordinate),
        };
    }
    pub fn mix(self: Values, ch: anytype) void {
        ch.mixU32s(&.{ 0x42374d56, VERSION, @intCast(self.children.len) });
        for (self.children) |child| {
            ch.mixU32s(&.{ @intFromEnum(std.meta.activeTag(child.value)), child.index });
            switch (child.value) {
                inline else => |v| v.mix(ch),
            }
        }
    }
};
fn order(prior: *?[2]u32, kind: Kind, index: u32) !void {
    if (index >= core.fields.m31.Modulus) return error.InvalidV7MixedRoster;
    const current = [2]u32{ @intFromEnum(kind), index };
    if (prior.*) |old| if (old[0] > current[0] or (old[0] == current[0] and old[1] >= current[1])) return error.InvalidV7MixedRoster;
    prior.* = current;
}
pub fn rosterDigest(roster: []const Expected) ![32]u8 {
    if (roster.len == 0 or roster.len > MAX_CHILDREN) return error.InvalidV7MixedCount;
    var ch = core.proof_suites.Blake3.Channel{};
    ch.mixU32s(&.{ 0x42374d52, VERSION, @intCast(roster.len) });
    var prior: ?[2]u32 = null;
    var epoch: ?[32]u8 = null;
    for (roster) |pin| {
        try order(&prior, pin.kind, pin.index);
        try pin.entry.validate();
        if (pin.entry.family != epochFamily(pin.kind) or pin.entry.index != pin.index or std.mem.allEqual(u8, &pin.template, 0)) return error.InvalidV7MixedRoster;
        if (epoch) |old| {
            if (!std.meta.eql(old, pin.epoch)) return error.MixedV7Epochs;
        } else epoch = pin.epoch;
        ch.mixU32s(&.{ @intFromEnum(pin.kind), pin.index });
        ch.mixRoot(pin.template);
        ch.mixRoot(pin.epoch);
        pin.entry.mix(&ch);
    }
    return ch.digestBytes();
}
pub fn scheduleDigest(wires: []const Wire) ![32]u8 {
    if (wires.len == 0 or wires.len > 1 << 22) return error.InvalidV7MixedSchedule;
    var ch = core.proof_suites.Blake3.Channel{};
    ch.mixU32s(&.{ 0x42374d57, VERSION, @intCast(wires.len) });
    for (wires, 0..) |wire, i| {
        if (wire.child >= MAX_CHILDREN) return error.InvalidV7MixedSchedule;
        if (i != 0 and (wires[i - 1].circuit > wire.circuit or (wires[i - 1].circuit == wire.circuit and wires[i - 1].wire >= wire.wire))) return error.InvalidV7MixedSchedule;
        const digest = switch (wire.source) {
            inline else => |source, kind| try Family(kind).scheduleDigest(&.{.{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .source = source, .coordinate = wire.coordinate }}),
        };
        ch.mixU32s(&.{ @intFromEnum(std.meta.activeTag(wire.source)), wire.child });
        ch.mixRoot(digest);
    }
    return ch.digestBytes();
}
pub fn supply(wires: []const Wire, values: Values, relations: @import("air/universal_challenges.zig").UniversalRelations) !Q {
    _ = try scheduleDigest(wires);
    try values.validate();
    const relation = try relations.getExact(.recursion_wire);
    var sum = Q.zero();
    for (wires) |wire| {
        const denominator = try relation.combineBase(&(.{ M.fromCanonical(wire.circuit), M.fromCanonical(wire.wire) } ++ try values.at(wire)));
        if (denominator.isZero()) return error.V7MixedDenominatorZero;
        sum = sum.add(Q.fromBase(M.fromCanonical(wire.uses)).mul(try denominator.inv()));
    }
    return sum;
}
