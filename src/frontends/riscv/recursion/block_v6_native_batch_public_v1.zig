//! Direct-native batch public supply. Global memory/ROM/provider claims remain
//! open. Values and schedules are verifier-owned, never proof-carried authority.
const std = @import("std");
const core = @import("stwo_core");
const native = @import("block_v5_recursive_public_bus_v1.zig");
const spans = @import("block_v5_pc_clock_span_v1.zig");
const span_bus = @import("block_v5_open_parent_public_bus_v1.zig");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
pub const VERSION: u32 = 1;
pub const MAX_CHILDREN: usize = 8;
pub const Child = struct { native: native.Values, span: spans.Span };
pub const Wire = struct {
    circuit: u32,
    wire: u32,
    uses: u32,
    child: u8,
    source: union(enum) { native: native.Source, span },
    coordinate: u8,
};
pub const Values = struct {
    children: []const Child,
    pub fn validate(self: Values) !void {
        if (self.children.len == 0 or self.children.len > MAX_CHILDREN) return error.InvalidNativeBatchCount;
        var previous: ?spans.Span = null;
        for (self.children) |child| {
            try child.native.validate();
            try span_bus.validateSpanBound(child.span);
            if (child.native.native_version != 3 or child.span.segment_count != 1 or
                child.native.index != child.span.first_index or !std.meta.eql(child.native.sealed, child.span.sealed_digest))
                return error.UntrustedNativeBatchChild;
            if (previous) |left| _ = try spans.merge(&.{ left, child.span });
            previous = child.span;
        }
    }
    pub fn outputSpan(self: Values) !spans.Span {
        try self.validate();
        var result = self.children[0].span;
        for (self.children[1..]) |child| result = try spans.merge(&.{ result, child.span });
        return result;
    }
    pub fn at(self: Values, wire: Wire) ![4]M {
        if (wire.child >= self.children.len) return error.InvalidNativeBatchWire;
        const child = self.children[wire.child];
        return switch (wire.source) {
            .native => |source| child.native.at(source, wire.coordinate),
            .span => if (wire.coordinate >= 6) error.InvalidNativeBatchWire else .{
                M.fromCanonical(span_bus.spanWords(child.span)[wire.coordinate]), M.zero(), M.zero(), M.zero(),
            },
        };
    }
    pub fn mix(self: Values, channel: anytype) void {
        channel.mixU32s(&.{ 0x42364e56, VERSION, @intCast(self.children.len) });
        for (self.children) |child| {
            child.native.mix(channel);
            channel.mixU32s(&span_bus.spanWords(child.span));
            channel.mixRoot(child.span.job_id);
            channel.mixRoot(child.span.source_image_digest);
            channel.mixRoot(child.span.sealed_digest);
            channel.mixU32s(&.{child.span.job_segment_count});
        }
    }
};
pub fn scheduleDigest(wires: []const Wire) ![32]u8 {
    if (wires.len == 0 or wires.len > MAX_CHILDREN * 160) return error.InvalidNativeBatchSchedule;
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42364e57, VERSION, @intCast(wires.len) });
    for (wires, 0..) |wire, i| {
        if (wire.child >= MAX_CHILDREN or wire.uses == 0 or wire.uses >= core.fields.m31.Modulus or
            wire.circuit >= core.fields.m31.Modulus or wire.wire >= core.fields.m31.Modulus)
            return error.InvalidNativeBatchSchedule;
        if (i > 0 and (wires[i - 1].circuit > wire.circuit or
            (wires[i - 1].circuit == wire.circuit and wires[i - 1].wire >= wire.wire))) return error.InvalidNativeBatchSchedule;
        const kind: u32 = switch (wire.source) {
            .native => |source| @intFromEnum(source),
            .span => 256,
        };
        const maximum: u8 = switch (wire.source) {
            .span => 6,
            .native => |source| switch (source) {
                .compensation, .open_sum => 1,
                .ordinal_header => 3,
                else => 8,
            },
        };
        if (wire.coordinate >= maximum) return error.InvalidNativeBatchSchedule;
        channel.mixU32s(&.{ wire.circuit, wire.wire, wire.uses, wire.child, kind, wire.coordinate });
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
        sum = sum.add(Q.fromBase(M.fromCanonical(wire.uses)).mul(try denominator.inv()));
    }
    return sum;
}
