//! Original child public bytes -> compact per-shard equations in one parent.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const R = @import("composition_graph_recorder.zig");
const Arena = @import("stable_graph_arena_v1.zig").Owned;
const Bus = @import("../block_v5_ram_range_forest_bus_v1.zig");
const Algebra = @import("block_v5_ram_range_forest_algebra_v1.zig");
const Geometry = @import("../block_v5_ram_range_forest_plan_v1.zig");
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
    values: Bus.SourceValues,
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
    pub fn zero(self: *@This(), value: R.Scalar) !void {
        try self.builder.constrainZero(value);
    }
};
const Bytes = struct { claims: [22][4][4]R.Scalar, counts: [3][2][4]R.Scalar, header: [12][4]R.Scalar };
fn smallCount(sink: *Sink, bytes: [2][4]R.Scalar, expected: u64) !void {
    if (expected >= core.fields.m31.Modulus) return error.RamRangeForestFieldCensus;
    try sink.zero(word(bytes[0]).sub(R.Scalar.fromBase(M.fromCanonical(@intCast(expected)))));
    for (bytes[1]) |byte| try sink.zero(byte);
}
pub fn prepare(backing: std.mem.Allocator, public: *const Bus.Owner) !Prepared {
    try public.validateSources();
    const node = try public.policy.forest.node(public.policy.index, public.policy.expected_plan);
    var arena = try Arena.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    var builder = R.Builder.init(a);
    defer builder.deinit();
    var reader = Reader{ .a = a, .builder = &builder, .values = .{ .public = public } };
    var children: [4]Bytes = undefined;
    for (public.children[0..public.child_count], children[0..public.child_count], 0..) |*optional, *bytes, index| {
        const ordinal: u32 = @intCast(index);
        switch (optional.*.?) {
            .ram => |*v| {
                // Four main buses and every original17 range plane; endpoint
                // count is original LE2, never a secure sum borrowed from host.
                for (bytes.claims[0..4], 0..) |*q, kind| q.* = try reader.secure(.child_cell, ordinal, v.normal.count_first + 2 + @as(u32, @intCast(4 * kind)));
                for (bytes.claims[5..], 0..) |*q, plane| q.* = try reader.secure(.child_cell, ordinal, v.normal.count_first + 18 + @as(u32, @intCast(4 * plane)));
                const positions = [_]u32{ v.normal.count_first, v.normal.count_first + 86, v.normal.count_first + 88 };
                for (&bytes.counts, positions) |*count, position| count.* = .{ try reader.word(.child_cell, ordinal, position), try reader.word(.child_cell, ordinal, position + 1) };
            },
            .range => |*v| {
                bytes.claims[0] = try reader.secure(.child_cell, ordinal, v.normal.sum_first);
                bytes.counts[0] = .{ try reader.word(.child_cell, ordinal, v.normal.count_first), try reader.word(.child_cell, ordinal, v.normal.count_first + 1) };
            },
            .node => |*v| {
                for (&bytes.claims, 0..) |*q, kind| q.* = try reader.secure(.child_cell, ordinal, v.normal.claim_first + @as(u32, @intCast(4 * kind)));
                const first = v.normal.word_first orelse return error.UntrustedRamRangeForestClaimLayout;
                for (&bytes.header, 0..) |*b, part| b.* = try reader.word(.child_cell, ordinal, first + @as(u32, @intCast(part)));
            },
        }
    }
    var output_bytes: [22][4][4]R.Scalar = undefined;
    for (&output_bytes, 0..) |*q, kind| q.* = try reader.secure(.output_slot, 0, Bus.CLAIM_FIRST + @as(u32, @intCast(4 * kind)));
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    var sink = Sink{ .builder = &builder };
    var input: [4][22]R.Scalar = @splat(@splat(R.Scalar.zero()));
    for (public.children[0..public.child_count], children[0..public.child_count], input[0..public.child_count], node.children[0..node.child_count]) |*optional, bytes, *claims, ref| switch (optional.*.?) {
        .ram => |*v| {
            if (ref != .ram) return error.UntrustedRamRangeForestNode;
            for (claims[0..4], bytes.claims[0..4]) |*q, b| q.* = secure(b);
            for (claims[5..], bytes.claims[5..]) |*q, b| q.* = secure(b);
            claims[4] = word(bytes.counts[1][0]);
            try smallCount(&sink, bytes.counts[0], v.policy.admitted.pin.claim.events);
            // Endpoint count is variable, bound by actual original lane AIR;
            // exact LE2 high word/whole-source endpoint join are mandatory.
            for (bytes.counts[1][1]) |byte| try sink.zero(byte);
            try smallCount(&sink, bytes.counts[2], v.policy.admitted.pin.request_count);
        },
        .range => |*v| {
            if (ref != .range or node.kind != .shard) return error.UntrustedRamRangeForestNode;
            claims[0] = secure(bytes.claims[0]);
            try smallCount(&sink, bytes.counts[0], v.policy.admitted.shard.request_count);
        },
        .node => |*v| {
            if (ref != .node) return error.UntrustedRamRangeForestNode;
            for (claims, bytes.claims) |*q, b| q.* = secure(b);
            for (bytes.header, v.summary.header) |b, expected| {
                // Full u32 equality uses all four separately authenticated
                // bytes: no modulo-M alias of high ordinal/request words.
                for (b, 0..) |byte, part| try sink.zero(byte.sub(R.Scalar.fromBase(M.fromCanonical((expected >> @as(u5, @intCast(8 * part))) & 255))));
            }
        },
    };
    var output: [22]R.Scalar = undefined;
    for (&output, output_bytes) |*q, b| q.* = secure(b);
    try Algebra.close(R.Scalar, &sink, node, input[0..public.child_count], output);
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
