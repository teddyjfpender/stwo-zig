//! Compact scope outputs and independent child pins only. No lower-child
//! descendant transcript is replayed in this node's public statement.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Routes = @import("block_v5_heterogeneous_scoped_routes_v1.zig");
const Source = @import("block_v5_heterogeneous_scoped_source_v1.zig");
pub const VERSION: u32 = 1;
pub const PUBLIC_CIRCUIT = Source.PUBLIC_CIRCUIT;
pub const Kind = enum(u32) { child_cell, child_term, child_span, output_slot, output_span };
pub const Wire = struct { circuit: u32, wire: u32, uses: u32, negative: bool = false, kind: Kind, child: u32 = 0, coordinate: u32, part: ?u2 = null };
pub const ChildPin = struct { key: @import("blake3_execution_parent_protocol.zig").Key, id: [32]u8, public_input: [32]u8, source_seal: [32]u8 };
pub const Values = struct {
    routes: *const Routes.Plan,
    index: u32,
    children: []const Source.Source,
    pins: []const ChildPin,
    outputs: []const Q,
    pub fn validate(self: Values) !void {
        try self.routes.validate();
        if (self.index >= self.routes.nodes.len) return error.InvalidScopedPublicCensus;
        const cohort = self.routes.cohorts.nodes[self.index];
        if (self.children.len != cohort.child_count or self.pins.len != self.children.len or self.outputs.len != self.routes.nodes[self.index].exports.len) return error.InvalidScopedPublicCensus;
        for (self.outputs) |value| for (value.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.NoncanonicalScopedSummary;
        for (self.children, self.pins, cohort.children[0..cohort.child_count]) |*child, pin, ref| {
            try child.validate();
            if (!std.meta.eql(child.ref, ref) or !std.meta.eql(child.routing, self.routes.digest) or !std.meta.eql(child.key, pin.key) or !std.meta.eql(child.expected_id, pin.id) or !std.meta.eql(child.public_input_digest, pin.public_input) or !std.meta.eql(child.seal, pin.source_seal)) return error.UntrustedScopedPublicSource;
            switch (ref) {
                .leaf => |ordinal| {
                    var independently = try Source.fromLeaf(child.arena.child_allocator, &self.routes.scoped.full.children[ordinal], ordinal, self.routes.digest);
                    defer independently.deinit();
                    if (!std.meta.eql(independently.seal, child.seal)) return error.UntrustedScopedPublicSource;
                },
                .node => |ordinal| {
                    const expected = self.routes.nodes[ordinal].exports;
                    if (child.slots.len != expected.len or !std.meta.eql(child.span, self.routes.cohorts.nodes[ordinal].span)) return error.UntrustedScopedPublicSource;
                    for (child.slots, expected) |slot, id| if (slot.requirement != id) return error.InvalidScopedPublicCensus;
                },
            }
        }
    }
    pub fn at(self: Values, wire: Wire) ![4]M {
        var cell: [4]M = undefined;
        switch (wire.kind) {
            .child_cell => {
                if (wire.child >= self.children.len or wire.coordinate >= self.children[wire.child].cells.len) return error.InvalidScopedPublicSchedule;
                cell = self.children[wire.child].cells[wire.coordinate];
            },
            .child_term => {
                if (wire.child >= self.children.len or wire.coordinate >= self.children[wire.child].terms.len or wire.part != null) return error.InvalidScopedPublicSchedule;
                return self.children[wire.child].terms[wire.coordinate].coordinates;
            },
            .child_span, .output_span => {
                const span = if (wire.kind == .child_span) block: {
                    if (wire.child >= self.children.len) return error.InvalidScopedPublicSchedule;
                    break :block self.children[wire.child].span;
                } else self.routes.cohorts.nodes[self.index].span;
                if (span == null or wire.coordinate >= 6) return error.InvalidScopedPublicSpan;
                const word_value = @import("block_v5_open_parent_public_bus_v1.zig").spanWords(span.?)[wire.coordinate];
                if (wire.part) |part| return .{ M.fromCanonical((word_value >> @as(u5, @intCast(8 * @as(u8, part)))) & 255), M.zero(), M.zero(), M.zero() };
                return .{ M.fromCanonical(word_value), M.zero(), M.zero(), M.zero() };
            },
            .output_slot => {
                const slot = wire.coordinate / 4;
                if (slot >= self.outputs.len) return error.InvalidScopedPublicSchedule;
                const word_value = self.outputs[slot].toM31Array()[wire.coordinate % 4].v;
                for (&cell, 0..) |*byte, part| byte.* = M.fromCanonical((word_value >> @as(u5, @intCast(8 * part))) & 255);
            },
        }
        return if (wire.part) |part| .{ cell[part], M.zero(), M.zero(), M.zero() } else cell;
    }
    pub fn mix(self: Values, channel: anytype) void {
        channel.mixU32s(&.{ 0x42355a42, VERSION, self.index, @intCast(self.children.len), @intCast(self.outputs.len) }); // B5ZB
        channel.mixRoot(self.routes.digest);
        channel.mixRoot(self.routes.scoped.full.plan.pinned_digest);
        channel.mixRoot(self.routes.scoped.mapping.source_seal);
        for (self.pins) |pin| {
            channel.mixRoot(pin.id);
            channel.mixRoot(pin.public_input);
            channel.mixRoot(pin.source_seal);
        }
        const span = self.routes.cohorts.nodes[self.index].span;
        channel.mixU32s(&.{@intFromBool(span != null)});
        if (span) |native| {
            if (@hasDecl(@TypeOf(channel.*), "beginSpan")) channel.beginSpan();
            channel.mixU32s(&@import("block_v5_open_parent_public_bus_v1.zig").spanWords(native));
            channel.mixRoot(native.job_id);
            channel.mixRoot(native.source_image_digest);
            channel.mixRoot(native.sealed_digest);
            channel.mixU32s(&.{native.job_segment_count});
        }
        const route = self.routes.nodes[self.index];
        channel.mixU32s(&.{@intCast(route.closed.len)});
        channel.mixU32s(route.closed);
        for (route.exports, self.outputs) |id, output| {
            const key = self.routes.scoped.requirements[id].key;
            channel.mixU32s(&.{ id, @intFromEnum(key.kind), key.scope, key.coordinate });
            if (@hasDecl(@TypeOf(channel.*), "beginSlot")) channel.beginSlot(id);
            channel.mixFelts(&.{output});
        }
    }
};
pub fn scheduleDigest(wires: []const Wire) ![32]u8 {
    if (wires.len == 0 or wires.len > Source.MAX_CELLS) return error.InvalidScopedPublicSchedule;
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42355a57, VERSION, @intCast(wires.len) }); // B5ZW
    for (wires, 0..) |wire, index| {
        if (wire.uses == 0 or wire.uses >= core.fields.m31.Modulus or wire.circuit >= core.fields.m31.Modulus or wire.wire >= core.fields.m31.Modulus or index > 0 and (wires[index - 1].circuit > wire.circuit or wires[index - 1].circuit == wire.circuit and wires[index - 1].wire >= wire.wire)) return error.InvalidScopedPublicSchedule;
        channel.mixU32s(&.{ wire.circuit, wire.wire, wire.uses, @intFromBool(wire.negative), @intFromEnum(wire.kind), wire.child, wire.coordinate, if (wire.part) |part| part else 4 });
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
        if (denominator.isZero()) return error.RecursivePublicDenominatorZero;
        const term = Q.fromBase(M.fromCanonical(wire.uses)).mul(try denominator.inv());
        sum = if (wire.negative) sum.sub(term) else sum.add(term);
    }
    return sum;
}
