//! Bounded v3 leaf-to-parent public supply. A parent verifies every child STARK
//! equation and public-wire closure; changing tuples and PC/clock edges are
//! committed main inputs, never fixed-instance constants. This is an open
//! equation fold, not complete block authority or a general forest protocol.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const native_bus = @import("block_v5_recursive_public_bus_v1.zig");
const native_protocol = @import("block_v5_reusable_native_parent_protocol_v1.zig");
const spans = @import("block_v5_pc_clock_span_v1.zig");
const universal = @import("air/universal_challenges.zig");
pub const PUBLIC_CIRCUIT: u32 = 4_200_002;
pub const VERSION: u32 = 1;
pub const Kind = enum(u8) { frame_header, frame_root, frame_felt_word, child_supply, span };
pub const Wire = struct {
    circuit: u32,
    wire: u32,
    uses: u32,
    child: u8,
    kind: Kind,
    coordinate: u16,
};
pub const Child = struct {
    admission: native_protocol.Admission,
    /// Must be independently reconstructed from native public admission. Neither
    /// fresh CPU receipt nor this descriptor substitutes for recursive proof.
    span: spans.Span,
    pub fn validate(self: Child) !void {
        try self.admission.validate();
        try validateSpanBound(self.span);
        if (self.admission.values.native_version != 3 or self.span.segment_count != 1 or
            self.admission.values.index != self.span.first_index or
            !std.meta.eql(self.admission.values.sealed, self.span.sealed_digest))
            return error.UntrustedV5OpenParentChild;
    }
};
pub const Values = struct {
    children: []const Child,
    pub fn validate(self: Values) !void {
        if (self.children.len != 2 and self.children.len != 4) return error.InvalidV5PcClockFanIn;
        var list: [4]spans.Span = undefined;
        for (self.children, list[0..self.children.len]) |child, *span| {
            try child.validate();
            span.* = child.span;
        }
        _ = try spans.merge(list[0..self.children.len]);
    }
    pub fn outputSpan(self: Values) !spans.Span {
        try self.validate();
        var list: [4]spans.Span = undefined;
        for (self.children, list[0..self.children.len]) |child, *span| span.* = child.span;
        return spans.merge(list[0..self.children.len]);
    }
    pub fn at(self: Values, wire: Wire) ![4]M {
        if (wire.child >= self.children.len) return error.InvalidV5OpenParentSchedule;
        const child = self.children[wire.child];
        const value = child.admission.values;
        const coordinate: usize = wire.coordinate;
        switch (wire.kind) {
            .frame_header => {
                if (coordinate >= 3) return error.InvalidV5OpenParentSchedule;
                return bytes(([_]u32{ 0x42355049, 1, value.index })[coordinate]);
            },
            .frame_root => {
                if (coordinate >= 48) return error.InvalidV5OpenParentSchedule;
                const digest = ([_][32]u8{ value.sealed, value.template, value.instance, value.roots[0], value.roots[1], value.statement_digest })[coordinate / 8];
                return bytes(std.mem.readInt(u32, digest[(coordinate % 8) * 4 ..][0..4], .little));
            },
            .frame_felt_word => {
                if (coordinate >= 8) return error.InvalidV5OpenParentSchedule;
                const limbs = (if (coordinate < 4) value.compensation else value.open_sum).toM31Array();
                return bytes(limbs[coordinate % 4].v);
            },
            .child_supply => {
                if (coordinate >= child.admission.wires.len * 4) return error.InvalidV5OpenParentSchedule;
                const source = child.admission.wires[coordinate / 4];
                const tuple = try value.at(source.source, source.coordinate);
                return .{ tuple[coordinate % 4], M.zero(), M.zero(), M.zero() };
            },
            .span => {
                if (coordinate >= 6) return error.InvalidV5OpenParentSchedule;
                return .{ M.fromCanonical(spanWords(child.span)[coordinate]), M.zero(), M.zero(), M.zero() };
            },
        }
    }
    pub fn mix(self: Values, channel: anytype) void {
        channel.mixU32s(&.{ 0x42354f56, VERSION, @intCast(self.children.len) });
        for (self.children) |child| {
            channel.mixRoot(child.admission.expected_id);
            child.admission.values.mix(channel);
            channel.mixU32s(&spanWords(child.span));
            channel.mixRoot(child.span.job_id);
            channel.mixRoot(child.span.source_image_digest);
            channel.mixRoot(child.span.sealed_digest);
            channel.mixU32s(&.{child.span.job_segment_count});
        }
    }
};
fn bytes(word: u32) [4]M {
    var result: [4]M = undefined;
    for (&result, 0..) |*v, i| v.* = M.fromCanonical((word >> @as(u5, @intCast(i * 8))) & 255);
    return result;
}
pub fn validateSpanBound(span: spans.Span) !void {
    try span.validate();
    if (span.first_index >= 1 << 30 or span.segment_count >= 1 << 30 or span.job_segment_count >= 1 << 30 or
        span.first_cycle >= 1 << 30 or span.last_cycle >= 1 << 30) return error.V5PcClockFoldRangeExceeded;
}
pub fn spanWords(span: spans.Span) [6]u32 {
    return .{ span.first_index, span.segment_count, @intCast(span.first_cycle), @intCast(span.last_cycle), span.initial_pc, span.final_pc };
}
pub fn scheduleDigest(wires: []const Wire) ![32]u8 {
    if (wires.len == 0 or wires.len > 4096) return error.InvalidV5OpenParentSchedule;
    if (!@import("public_wire_uniqueness_v1.zig").For(Wire, 4096).unique(wires)) return error.InvalidV5OpenParentSchedule;
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42354f57, VERSION, @intCast(wires.len) });
    for (wires) |wire| {
        if (wire.child >= 4 or wire.uses == 0 or wire.uses >= core.fields.m31.Modulus or
            wire.circuit >= core.fields.m31.Modulus or wire.wire >= core.fields.m31.Modulus) return error.InvalidV5OpenParentSchedule;
        channel.mixU32s(&.{ wire.circuit, wire.wire, wire.uses, wire.child, @intFromEnum(wire.kind), wire.coordinate });
    }
    return channel.digestBytes();
}
pub fn supply(wires: []const Wire, values: Values, relations: universal.UniversalRelations) !Q {
    _ = try scheduleDigest(wires);
    try values.validate();
    const element = try relations.getExact(.recursion_wire);
    var total = Q.zero();
    for (wires) |wire| {
        const tuple = .{ M.fromCanonical(wire.circuit), M.fromCanonical(wire.wire) } ++ try values.at(wire);
        const denominator = try element.combineBase(&tuple);
        if (denominator.isZero()) return error.RecursivePublicDenominatorZero;
        total = total.add(Q.fromBase(M.fromCanonical(wire.uses)).mul(try denominator.inv()));
    }
    return total;
}
/// Wrapper preserves the exact child transcript; fold-only graph inputs are
/// supplied by the independently admitted enclosing parent policy.
pub const ChildAdmission = struct {
    pub const open_parent_v5 = true;
    original: native_protocol.Admission,
    key: native_protocol.Key,
    expected_id: [32]u8,
    wires: []const native_bus.Wire,
    values: native_bus.Values,
    pc_clock_children: []const spans.Span,
    pub fn init(original: native_protocol.Admission, pc_clock_children: []const spans.Span) ChildAdmission {
        return .{ .original = original, .key = original.key, .expected_id = original.expected_id, .wires = original.wires, .values = original.values, .pc_clock_children = pc_clock_children };
    }
    pub fn validate(self: *const ChildAdmission) !void {
        try self.original.validate();
        if (!std.meta.eql(self.key, self.original.key) or !std.meta.eql(self.expected_id, self.original.expected_id) or
            !std.meta.eql(self.values, self.original.values) or self.wires.len != self.original.wires.len)
            return error.UntrustedV5OpenParentChild;
        for (self.wires, self.original.wires) |actual, expected| if (!std.meta.eql(actual, expected)) return error.UntrustedV5OpenParentChild;
        if (self.pc_clock_children.len != 0) {
            for (self.pc_clock_children) |span| try validateSpanBound(span);
            _ = try spans.merge(self.pc_clock_children);
        }
    }
    pub fn config(self: *const ChildAdmission) !core.pcs.PcsConfig {
        return self.original.config();
    }
    pub fn admitRoot(self: *const ChildAdmission, root: [32]u8) !void {
        try self.original.admitRoot(root);
    }
    pub fn publicInputIdentity(self: *const ChildAdmission) ![32]u8 {
        return self.original.publicInputIdentity();
    }
    pub fn mix(self: *const ChildAdmission, channel: anytype) !void {
        try self.original.mix(channel);
    }
    pub fn mixClaims(self: *const ChildAdmission, channel: anytype, claims: []const Q) !void {
        try self.original.mixClaims(channel, claims);
    }
    pub fn validateClaimsForRelations(self: *const ChildAdmission, claims: @import("blake3_native_parent_artifact.zig").Claims, relations: universal.UniversalRelations) !void {
        try self.original.validateClaimsForRelations(claims, relations);
    }
};
