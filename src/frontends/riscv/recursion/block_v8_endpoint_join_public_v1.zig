//! One public roster for all exact original verifier machines and closure graph.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Source = @import("block_v8_endpoint_join_source_v1.zig");
const Scoped = @import("block_v5_heterogeneous_scoped_public_bus_v1.zig");
pub const Wire = struct { circuit: u32, wire: u32, uses: u32, child: u32, source: @FieldType(Source.RawWire, "source"), coordinate: u32, negative: bool = false };
pub const Values = struct {
    children: []const Source.Value,
    extra: []const Q,
    pub fn validate(v: Values) !void {
        if (v.children.len < 3 or v.children.len > 64) return error.InvalidEndpointJoinRoster;
        for (v.children) |child| try child.validate();
        for (v.extra) |q| if (!@import("air/universal_provider_relations.zig").secureIsCanonical(&q)) return error.NonCanonicalEndpointJoin;
    }
    pub fn at(v: Values, w: Wire) ![4]M {
        if (w.child == v.children.len) {
            if (w.coordinate >= v.extra.len) return error.InvalidEndpointJoinCoordinate;
            return v.extra[w.coordinate].toM31Array();
        }
        if (w.child >= v.children.len) return error.InvalidEndpointJoinCoordinate;
        return v.children[w.child].at(w.source, w.coordinate);
    }
    pub fn mix(v: Values, ch: anytype) void {
        ch.mixU32s(&.{ 0x42384a56, 1, @intCast(v.children.len), @intCast(v.extra.len) });
        for (v.children) |child| child.mix(ch);
        ch.mixFelts(v.extra);
    }
};
pub const View = struct {
    values: Values,
    pub fn at(v: View, w: Scoped.Wire) ![4]M {
        return v.values.at(fromGraph(w));
    }
};
pub fn fromGraph(w: Scoped.Wire) Wire {
    return .{ .circuit = w.circuit, .wire = w.wire, .uses = w.uses, .child = w.child, .source = if (w.kind == .child_cell) .first_root else .public_input, .coordinate = w.coordinate, .negative = w.negative };
}
pub fn scheduleDigest(wires: []const Wire) ![32]u8 {
    if (wires.len == 0 or wires.len > 1 << 22) return error.InvalidEndpointJoinSchedule;
    var ch = core.proof_suites.Blake3.Channel{};
    ch.mixU32s(&.{ 0x42384a57, 1, @intCast(wires.len) });
    for (wires, 0..) |w, i| {
        if (w.uses == 0 or w.circuit >= core.fields.m31.Modulus or w.wire >= core.fields.m31.Modulus or (i > 0 and (wires[i - 1].circuit > w.circuit or (wires[i - 1].circuit == w.circuit and wires[i - 1].wire >= w.wire)))) return error.InvalidEndpointJoinSchedule;
        ch.mixU32s(&.{ w.circuit, w.wire, w.uses, w.child, @intFromEnum(w.source), w.coordinate, @intFromBool(w.negative) });
    }
    return ch.digestBytes();
}
pub fn sort(wires: []Wire) void {
    std.mem.sort(Wire, wires, {}, struct {
        fn less(_: void, a: Wire, b: Wire) bool {
            return a.circuit < b.circuit or (a.circuit == b.circuit and a.wire < b.wire);
        }
    }.less);
}
pub fn supply(wires: []const Wire, v: Values, relations: @import("air/universal_challenges.zig").UniversalRelations) !Q {
    try v.validate();
    _ = try scheduleDigest(wires);
    const relation = try relations.getExact(.recursion_wire);
    var sum = Q.zero();
    for (wires) |w| {
        const d = try relation.combineBase(&(.{ M.fromCanonical(w.circuit), M.fromCanonical(w.wire) } ++ try v.at(w)));
        const term = Q.fromBase(M.fromCanonical(w.uses)).mul(try d.inv());
        sum = if (w.negative) sum.sub(term) else sum.add(term);
    }
    return sum;
}
