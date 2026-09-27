//! Public data and original-coordinate forwarding for one exact hierarchy
//! node. Trusted node policy, never proof envelopes, supplies these values.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Topology = @import("block_v5_heterogeneous_hierarchy_plan_v1.zig");
const Frames = @import("block_v5_heterogeneous_hierarchy_frames_v1.zig");
pub const VERSION: u32 = 1;
pub const PUBLIC_CIRCUIT = Frames.PUBLIC_CIRCUIT;
pub const Kind = enum(u8) { child_cell, child_term, child_span, export_cell, export_span };
pub const Wire = struct { circuit: u32, wire: u32, uses: u32, negative: bool = false, kind: Kind, child: u32 = 0, coordinate: u32, part: ?u2 = null };
pub const ChildPin = struct { key: @import("blake3_execution_parent_protocol.zig").Key, id: [32]u8, public_input: [32]u8, source_seal: [32]u8 };
pub const Values = struct {
    plan: *const Topology.Plan,
    index: u32,
    children: []const Frames.Source,
    pins: []const ChildPin,
    pub fn validate(self: Values) !void {
        try self.plan.validate();
        if (self.index >= self.plan.full.plan.meta.nodes.len) return error.InvalidHeterogeneousHierarchyTopology;
        const node = self.plan.full.plan.meta.nodes[self.index];
        if (self.children.len != node.child_count or self.pins.len != node.child_count) return error.IncompleteHeterogeneousHierarchy;
        for (self.children, self.pins, node.children[0..node.child_count]) |*source, pin, ref| {
            try source.validate();
            const bounds = try self.plan.bounds(ref);
            if (!std.meta.eql(source.ref, ref) or !std.meta.eql(source.bounds, bounds) or !std.meta.eql(source.coverage, self.plan.expected_coverage) or !std.meta.eql(source.span, try self.plan.span(ref)) or !std.meta.eql(source.key, pin.key) or !std.meta.eql(source.expected_id, pin.id) or !std.meta.eql(source.public_input_digest, pin.public_input) or !std.meta.eql(source.seal, pin.source_seal)) return error.UntrustedHeterogeneousHierarchySource;
            switch (ref) {
                .leaf => |ordinal| {
                    var expected = try Frames.fromLeaf(source.arena.child_allocator, &self.plan.full.children[ordinal], ordinal, self.plan.expected_coverage);
                    defer expected.deinit();
                    if (!std.meta.eql(expected.seal, source.seal)) return error.UntrustedHeterogeneousHierarchySource;
                },
                .node => |ordinal| {
                    if (source.node_id == null or !std.meta.eql(source.node_id.?, try self.plan.nodeIdentity(ordinal))) return error.UntrustedHeterogeneousHierarchySource;
                },
            }
        }
    }
    pub fn at(self: Values, wire: Wire) ![4]M {
        var cell: [4]M = undefined;
        switch (wire.kind) {
            .child_cell => {
                if (wire.child >= self.children.len or wire.coordinate >= self.children[wire.child].cells.len) return error.InvalidHeterogeneousHierarchySchedule;
                cell = self.children[wire.child].cells[wire.coordinate];
            },
            .child_term => {
                if (wire.child >= self.children.len or wire.coordinate >= self.children[wire.child].terms.len or wire.part != null) return error.InvalidHeterogeneousHierarchySchedule;
                return self.children[wire.child].terms[wire.coordinate].coordinates;
            },
            .child_span => {
                if (wire.child >= self.children.len or wire.coordinate >= 6 or self.children[wire.child].span == null) return error.InvalidHeterogeneousHierarchySpan;
                const words = @import("block_v5_open_parent_public_bus_v1.zig").spanWords(self.children[wire.child].span.?);
                if (wire.part) |part| return .{ M.fromCanonical((words[wire.coordinate] >> @as(u5, @intCast(8 * @as(u8, part)))) & 255), M.zero(), M.zero(), M.zero() };
                return .{ M.fromCanonical(words[wire.coordinate]), M.zero(), M.zero(), M.zero() };
            },
            .export_cell => {
                const bounds = try self.plan.bounds(.{ .node = self.index });
                if (wire.child < bounds.first or wire.child - bounds.first >= bounds.count or wire.coordinate >= self.plan.full.children[wire.child].cells.len) return error.InvalidHeterogeneousHierarchySchedule;
                cell = self.plan.full.children[wire.child].cells[wire.coordinate];
            },
            .export_span => {
                const span = (try self.plan.span(.{ .node = self.index })) orelse return error.InvalidHeterogeneousHierarchySpan;
                if (wire.coordinate >= 6) return error.InvalidHeterogeneousHierarchySpan;
                const words = @import("block_v5_open_parent_public_bus_v1.zig").spanWords(span);
                if (wire.part) |part| return .{ M.fromCanonical((words[wire.coordinate] >> @as(u5, @intCast(8 * @as(u8, part)))) & 255), M.zero(), M.zero(), M.zero() };
                return .{ M.fromCanonical(words[wire.coordinate]), M.zero(), M.zero(), M.zero() };
            },
        }
        return if (wire.part) |part| .{ cell[part], M.zero(), M.zero(), M.zero() } else cell;
    }
    pub fn mix(self: Values, channel: anytype) void {
        const node = self.plan.full.plan.meta.nodes[self.index];
        channel.mixU32s(&.{ 0x42354842, VERSION, self.index, node.first_leaf, node.leaf_count, node.child_count }); // B5HB
        channel.mixRoot(self.plan.expected_coverage);
        channel.mixRoot(self.plan.full.plan.meta.seal_digest);
        channel.mixU32s(&node.schema_counts);
        for (self.children, self.pins) |*child, pin| {
            channel.mixRoot(pin.id);
            channel.mixRoot(pin.public_input);
            channel.mixRoot(pin.source_seal);
            child.mix(channel);
        }
        const span = self.plan.span(.{ .node = self.index }) catch unreachable;
        channel.mixU32s(&.{@intFromBool(span != null)});
        if (span) |native| {
            if (@hasDecl(@TypeOf(channel.*), "beginSpan")) channel.beginSpan();
            channel.mixU32s(&@import("block_v5_open_parent_public_bus_v1.zig").spanWords(native));
            channel.mixRoot(native.job_id);
            channel.mixRoot(native.source_image_digest);
            channel.mixRoot(native.sealed_digest);
            channel.mixU32s(&.{native.job_segment_count});
        }
        for (self.plan.full.children[node.first_leaf..][0..node.leaf_count], node.first_leaf..) |*leaf, ordinal| {
            channel.mixU32s(&.{ @intCast(ordinal), @intFromEnum(leaf.physical.kind), @intFromEnum(leaf.physical.subtype), leaf.physical.index, @intCast(leaf.cells.len) });
            if (@hasDecl(@TypeOf(channel.*), "beginExport")) channel.beginExport(@intCast(ordinal), @intCast(leaf.cells.len));
            leaf.mix(channel);
        }
    }
};
pub fn scheduleDigest(wires: []const Wire) ![32]u8 {
    if (wires.len == 0 or wires.len > Frames.MAX_CELLS) return error.InvalidHeterogeneousHierarchySchedule;
    var c = core.channel.blake3.Channel{};
    c.mixU32s(&.{ 0x42354859, VERSION, @intCast(wires.len) });
    for (wires, 0..) |wire, i| {
        if (wire.uses == 0 or wire.uses >= core.fields.m31.Modulus or wire.circuit >= core.fields.m31.Modulus or wire.wire >= core.fields.m31.Modulus or i > 0 and (wires[i - 1].circuit > wire.circuit or wires[i - 1].circuit == wire.circuit and wires[i - 1].wire >= wire.wire)) return error.InvalidHeterogeneousHierarchySchedule;
        c.mixU32s(&.{ wire.circuit, wire.wire, wire.uses, @intFromBool(wire.negative), @intFromEnum(wire.kind), wire.child, wire.coordinate, if (wire.part) |part| part else 4 });
    }
    return c.digestBytes();
}
pub fn supply(wires: []const Wire, values: Values, relations: @import("air/universal_challenges.zig").UniversalRelations) !Q {
    _ = try scheduleDigest(wires);
    try values.validate();
    const relation = try relations.getExact(.recursion_wire);
    var sum = Q.zero();
    for (wires) |wire| {
        const d = try relation.combineBase(&(.{ M.fromCanonical(wire.circuit), M.fromCanonical(wire.wire) } ++ try values.at(wire)));
        if (d.isZero()) return error.RecursivePublicDenominatorZero;
        const term = Q.fromBase(M.fromCanonical(wire.uses)).mul(try d.inv());
        sum = if (wire.negative) sum.sub(term) else sum.add(term);
    }
    return sum;
}
