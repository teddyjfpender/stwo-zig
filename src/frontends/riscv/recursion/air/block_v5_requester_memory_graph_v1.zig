//! Actual public-compensated requester root + compact memory root transition.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const R = @import("composition_graph_recorder.zig");
const Arena = @import("stable_graph_arena_v1.zig").Owned;
const Bus = @import("../block_v5_requester_memory_public_v1.zig");
const A = @import("block_v5_requester_memory_algebra_v1.zig");
const G = @import("block_v5_heterogeneous_scoped_graph_rows_v1.zig").Graph;
pub const Prepared = struct {
    arena: Arena,
    circuit: R.Circuit,
    inputs: []Q,
    values: []Q,
    sources: []Bus.Wire,
    pub fn deinit(self: *@This()) void {
        self.circuit.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn graph(self: *const @This()) G {
        return .{ .circuit = &self.circuit, .inputs = self.inputs, .values = self.values, .sources = self.sources };
    }
};
const Reader = struct {
    a: std.mem.Allocator,
    builder: *R.Builder,
    values: Bus.Values,
    inputs: std.ArrayList(Q) = .empty,
    sources: std.ArrayList(Bus.Wire) = .empty,
    fn word(self: *@This(), kind: @FieldType(Bus.Wire, "kind"), child: u32, coordinate: u32) ![4]R.Scalar {
        var symbols: [4]R.Scalar = undefined;
        for (&symbols, 0..) |*symbol, part| {
            const wire = Bus.Wire{ .circuit = 0, .wire = 0, .uses = 1, .kind = kind, .child = child, .coordinate = coordinate, .part = @intCast(part) };
            symbol.* = (try self.builder.input()).value;
            try self.inputs.append(self.a, Q.fromM31Array(try self.values.at(wire)));
            try self.sources.append(self.a, wire);
        }
        return symbols;
    }
    fn secure(self: *@This(), kind: @FieldType(Bus.Wire, "kind"), child: u32, coordinate: u32) ![4][4]R.Scalar {
        var symbols: [4][4]R.Scalar = undefined;
        for (&symbols, 0..) |*parts, limb| parts.* = try self.word(kind, child, coordinate + @as(u32, @intCast(limb)));
        return symbols;
    }
};
fn word(bytes: [4]R.Scalar) R.Scalar {
    var value = R.Scalar.zero();
    for (bytes, 0..) |byte, part| value = value.add(byte.mul(R.Scalar.fromBase(M.fromCanonical(@as(u32, 1) << @as(u5, @intCast(8 * part))))));
    return value;
}
fn secure(bytes: [4][4]R.Scalar) R.Scalar {
    var limbs: [4]R.Scalar = undefined;
    for (&limbs, bytes) |*limb, b| limb.* = word(b);
    return R.fromPartialEvals(limbs);
}
const Sink = struct {
    builder: *R.Builder,
    pub fn zero(self: *@This(), value: R.Scalar, _: anyerror) !void {
        try self.builder.constrainZero(value);
    }
};
pub fn prepare(backing: std.mem.Allocator, public: *const Bus.Owner) !Prepared {
    try public.validate();
    const p = public.policy;
    var arena = try Arena.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    var builder = R.Builder.init(a);
    defer builder.deinit();
    var reader = Reader{ .a = a, .builder = &builder, .values = .{ .public = public } };
    const requester_bytes = try reader.secure(.child_cell, 0, (try p.requester.transition()).first_cell);
    const memory_bytes = try reader.secure(.child_cell, 1, p.memory.transition_first);
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    var sink = Sink{ .builder = &builder };
    try A.close(R.Scalar, &sink, secure(requester_bytes), secure(memory_bytes));
    try builder.check();
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const inputs = try reader.inputs.toOwnedSlice(a);
    const sources = try reader.sources.toOwnedSlice(a);
    const values = try a.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(inputs, values);
    return .{ .arena = arena, .circuit = circuit, .inputs = inputs, .values = values, .sources = sources };
}
