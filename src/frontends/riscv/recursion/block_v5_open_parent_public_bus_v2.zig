//! Nested known-protocol public supply and exact-count PC/clock policy. Both
//! native recursive leaves and previous open-parent STARKs are genuine children.
//! Exact outer roots cover the real leaf count without 2^k padding.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const normalized = @import("block_v5_open_child_frames_v2.zig");
const span_mod = @import("block_v5_pc_clock_span_v1.zig");
const universal = @import("air/universal_challenges.zig");
pub const PUBLIC_CIRCUIT = normalized.PUBLIC_CIRCUIT;
pub const VERSION: u32 = 2;
pub const Child = normalized.Child;
pub const Purpose = enum(u8) { local, exact_outer };
pub const Kind = enum(u8) { frame_cell, child_supply_packed, span };
pub const Wire = struct { circuit: u32, wire: u32, uses: u32, negative: bool = false, child: u8, kind: Kind, coordinate: u32 };
pub fn merge(children: []const span_mod.Span) !span_mod.Span {
    if (children.len == 0 or children.len > 32) return error.InvalidV5NestedFanIn;
    var result = children[0];
    try @import("block_v5_open_parent_public_bus_v1.zig").validateSpanBound(result);
    for (children[1..]) |right| result = try span_mod.merge(&.{ result, right });
    return result;
}
pub const Values = struct {
    purpose: Purpose,
    children: []const Child,
    pub fn validate(self: Values) !void {
        if (self.children.len == 0 or self.children.len > 32 or
            (self.purpose == .local and self.children.len != 2 and self.children.len != 4)) return error.InvalidV5NestedFanIn;
        var spans: [32]span_mod.Span = undefined;
        for (self.children, spans[0..self.children.len]) |*child, *span| {
            try child.validate();
            span.* = child.span;
        }
        const output = try merge(spans[0..self.children.len]);
        if (self.purpose == .local) {
            const width = self.children[0].span.segment_count;
            if (!std.math.isPowerOfTwo(width) or output.first_index % output.segment_count != 0) return error.InvalidV5NestedLocalShape;
            for (self.children) |child| if (child.span.segment_count != width) return error.InvalidV5NestedLocalShape;
        } else {
            if (output.first_index != 0 or output.segment_count != output.job_segment_count) return error.IncompleteV5ExactOuterSpan;
            var remaining = output.job_segment_count;
            var first: u32 = 0;
            for (self.children) |child| {
                if (remaining == 0) return error.InvalidV5ExactOuterRoster;
                const width: u32 = @as(u32, 1) << @as(u5, @intCast(31 - @clz(remaining)));
                if (child.span.first_index != first or child.span.segment_count != width) return error.InvalidV5ExactOuterRoster;
                first += width;
                remaining -= width;
            }
            if (remaining != 0) return error.IncompleteV5ExactOuterSpan;
        }
    }
    pub fn outputSpan(self: Values) !span_mod.Span {
        try self.validate();
        var spans: [32]span_mod.Span = undefined;
        for (self.children, spans[0..self.children.len]) |child, *span| span.* = child.span;
        return merge(spans[0..self.children.len]);
    }
    pub fn at(self: Values, wire: Wire) ![4]M {
        if (wire.child >= self.children.len) return error.InvalidV5NestedPublicSchedule;
        const child = &self.children[wire.child];
        const coordinate: usize = wire.coordinate;
        switch (wire.kind) {
            .frame_cell => {
                if (coordinate >= child.cells.len) return error.InvalidV5NestedPublicSchedule;
                return child.cells[coordinate];
            },
            .child_supply_packed => {
                if (coordinate >= child.terms.len) return error.InvalidV5NestedPublicSchedule;
                return child.terms[coordinate].coordinates;
            },
            .span => {
                if (coordinate >= 6) return error.InvalidV5NestedPublicSchedule;
                return .{ M.fromCanonical(@import("block_v5_open_parent_public_bus_v1.zig").spanWords(child.span)[coordinate]), M.zero(), M.zero(), M.zero() };
            },
        }
    }
    pub fn mix(self: Values, channel: anytype) void {
        channel.mixU32s(&.{ 0x42354f56, VERSION, @intFromEnum(self.purpose), @intCast(self.children.len) });
        for (self.children) |*child| {
            channel.mixRoot(child.expected_id);
            channel.mixRoot(child.public_input_digest);
            child.mix(channel);
            channel.mixU32s(&@import("block_v5_open_parent_public_bus_v1.zig").spanWords(child.span));
            channel.mixRoot(child.span.job_id);
            channel.mixRoot(child.span.source_image_digest);
            channel.mixRoot(child.span.sealed_digest);
            channel.mixU32s(&.{child.span.job_segment_count});
            channel.mixFelts(&.{child.native_open_sum});
        }
    }
};
pub fn scheduleDigest(wires: []const Wire) ![32]u8 {
    if (wires.len == 0 or wires.len > normalized.LIMIT) return error.InvalidV5NestedPublicSchedule;
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42354f57, VERSION, @intCast(wires.len) });
    // Production preparation sorts once; admission is linear and deterministic.
    for (wires, 0..) |wire, i| {
        if (wire.child >= 32 or wire.uses == 0 or wire.uses >= core.fields.m31.Modulus or
            wire.circuit >= core.fields.m31.Modulus or wire.wire >= core.fields.m31.Modulus) return error.InvalidV5NestedPublicSchedule;
        if (i > 0 and (wires[i - 1].circuit > wire.circuit or
            (wires[i - 1].circuit == wire.circuit and wires[i - 1].wire >= wire.wire))) return error.InvalidV5NestedPublicSchedule;
        channel.mixU32s(&.{ wire.circuit, wire.wire, wire.uses, @intFromBool(wire.negative), wire.child, @intFromEnum(wire.kind), wire.coordinate });
    }
    return channel.digestBytes();
}
pub fn supply(wires: []const Wire, values: Values, relations: universal.UniversalRelations) !Q {
    _ = try scheduleDigest(wires);
    try values.validate();
    const element = try relations.getExact(.recursion_wire);
    var total = Q.zero();
    for (wires) |wire| {
        const denominator = try element.combineBase(&(.{ M.fromCanonical(wire.circuit), M.fromCanonical(wire.wire) } ++ try values.at(wire)));
        if (denominator.isZero()) return error.RecursivePublicDenominatorZero;
        const term = Q.fromBase(M.fromCanonical(wire.uses)).mul(try denominator.inv());
        total = if (wire.negative) total.sub(term) else total.add(term);
    }
    return total;
}
