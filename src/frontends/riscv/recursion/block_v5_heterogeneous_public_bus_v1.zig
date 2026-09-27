//! Open heterogeneous public input supply. Exact source/aggregate closures
//! remain mandatory independent obligations; this is never a ClosedBlock bus.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Frames = @import("block_v5_heterogeneous_child_frames_v1.zig");
const Policy = @import("block_v5_heterogeneous_policy_v1.zig").Policy;
const universal = @import("air/universal_challenges.zig");
pub const VERSION: u32 = 1;
pub const PUBLIC_CIRCUIT = Frames.PUBLIC_CIRCUIT;
pub const MAX_CHILDREN: usize = 1024;
pub const Kind = enum(u8) { frame_cell, child_supply_packed, native_span, pairing_coordinate };
pub const Wire = struct { circuit: u32, wire: u32, uses: u32, negative: bool = false, child: u32, kind: Kind, coordinate: u32, part: u2 = 0 };
pub const Values = struct {
    policy: Policy,
    pub fn validate(self: Values) !void {
        if (self.policy.children.len == 0 or self.policy.children.len > MAX_CHILDREN) return error.HeterogeneousResourceLimit;
        try self.policy.validate();
    }
    pub fn at(self: Values, wire: Wire) ![4]M {
        if (wire.child >= self.policy.children.len) return error.InvalidHeterogeneousSchedule;
        const child = &self.policy.children[wire.child];
        return switch (wire.kind) {
            .frame_cell => if (wire.coordinate < child.cells.len) child.cells[wire.coordinate] else error.InvalidHeterogeneousSchedule,
            .child_supply_packed => if (wire.coordinate < child.terms.len) child.terms[wire.coordinate].coordinates else error.InvalidHeterogeneousSchedule,
            .pairing_coordinate => if (wire.coordinate < child.cells.len) .{ child.cells[wire.coordinate][wire.part], M.zero(), M.zero(), M.zero() } else error.InvalidHeterogeneousSchedule,
            .native_span => block: {
                if (wire.coordinate >= 6 or child.span == null) return error.HeterogeneousProviderHasNativeSpan;
                const words = @import("block_v5_open_parent_public_bus_v1.zig").spanWords(child.span.?);
                break :block .{ M.fromCanonical(words[wire.coordinate]), M.zero(), M.zero(), M.zero() };
            },
        };
    }
    pub fn mix(self: Values, channel: anytype) void {
        channel.mixU32s(&.{ 0x42354856, VERSION, @intCast(self.policy.children.len) });
        channel.mixRoot(self.policy.plan.pinned_digest);
        for (self.policy.children) |*child| {
            channel.mixU32s(&.{ @intFromEnum(child.physical.kind), @intFromEnum(child.physical.subtype), child.physical.index, child.physical.logical_count });
            channel.mixU32s(&child.physical.logical);
            channel.mixRoot(child.physical.instance_id);
            channel.mixRoot(child.expected_id);
            channel.mixRoot(child.public_input_digest);
            child.mix(channel);
            channel.mixU32s(&.{@intFromBool(child.span != null)});
            if (child.span) |span| {
                channel.mixU32s(&@import("block_v5_open_parent_public_bus_v1.zig").spanWords(span));
                channel.mixRoot(span.job_id);
                channel.mixRoot(span.source_image_digest);
                channel.mixRoot(span.sealed_digest);
                channel.mixU32s(&.{span.job_segment_count});
            }
        }
    }
};
pub fn scheduleDigest(wires: []const Wire) ![32]u8 {
    if (wires.len == 0 or wires.len > Frames.LIMIT) return error.InvalidHeterogeneousSchedule;
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42354857, VERSION, @intCast(wires.len) });
    for (wires, 0..) |wire, i| {
        if (wire.child >= MAX_CHILDREN or wire.uses == 0 or wire.uses >= core.fields.m31.Modulus or wire.circuit >= core.fields.m31.Modulus or wire.wire >= core.fields.m31.Modulus or (wire.kind != .pairing_coordinate and wire.part != 0)) return error.InvalidHeterogeneousSchedule;
        if (i > 0 and (wires[i - 1].circuit > wire.circuit or (wires[i - 1].circuit == wire.circuit and wires[i - 1].wire >= wire.wire))) return error.InvalidHeterogeneousSchedule;
        channel.mixU32s(&.{ wire.circuit, wire.wire, wire.uses, @intFromBool(wire.negative), wire.child, @intFromEnum(wire.kind), wire.coordinate, wire.part });
    }
    return channel.digestBytes();
}
pub fn supply(wires: []const Wire, values: Values, relations: universal.UniversalRelations) !Q {
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
