//! Same-parent byte equations for exact PAGE roster coverage and original shared
//! source claims. Provider-only nodes have no fabricated PC/clock spans.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const R = @import("composition_graph_recorder.zig");
const Arena = @import("stable_graph_arena_v1.zig").Owned;
const Bus = @import("../block_v5_memory_source_page_forest_bus_v1.zig");
const A = @import("../block_v5_memory_source_page_forest_algebra_v1.zig");
const Graph = @import("block_v5_heterogeneous_scoped_graph_rows_v1.zig").Graph;
pub const Prepared = struct {
    arena: Arena,
    circuit: R.Circuit,
    inputs: []Q,
    values: []Q,
    sources: []Bus.Wire,
    pub const complete_source_authority = false;
    pub fn deinit(self: *Prepared) void {
        self.circuit.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn graph(self: *const Prepared) Graph {
        return .{ .circuit = &self.circuit, .inputs = self.inputs, .values = self.values, .sources = self.sources };
    }
};
const Reader = struct {
    a: std.mem.Allocator,
    builder: *R.Builder,
    public: Bus.Values,
    inputs: std.ArrayList(Q) = .empty,
    sources: std.ArrayList(Bus.Wire) = .empty,
    fn word(self: *Reader, kind: @FieldType(Bus.Wire, "kind"), child: u32, coordinate: u32) ![4]R.Scalar {
        var symbols: [4]R.Scalar = undefined;
        for (&symbols, 0..) |*symbol, part| {
            const wire = Bus.Wire{ .circuit = 0, .wire = 0, .uses = 1, .kind = kind, .child = child, .coordinate = coordinate, .part = @intCast(part) };
            symbol.* = (try self.builder.input()).value;
            try self.inputs.append(self.a, Q.fromM31Array(try self.public.at(wire)));
            try self.sources.append(self.a, wire);
        }
        return symbols;
    }
    fn claim(self: *Reader, kind: @FieldType(Bus.Wire, "kind"), child: u32, first: u32) ![4][4]R.Scalar {
        var out: [4][4]R.Scalar = undefined;
        for (&out, 0..) |*word_symbols, limb| word_symbols.* = try self.word(kind, child, try std.math.add(u32, first, @intCast(limb)));
        return out;
    }
};
fn scalarWord(bytes: [4]R.Scalar) R.Scalar {
    var out = R.Scalar.zero();
    for (bytes, 0..) |byte, part| out = out.add(byte.mul(R.Scalar.fromBase(M.fromCanonical(@as(u32, 1) << @as(u5, @intCast(8 * part))))));
    return out;
}
fn scalarClaim(bytes: [4][4]R.Scalar) R.Scalar {
    var limbs: [4]R.Scalar = undefined;
    for (&limbs, bytes) |*limb, word| limb.* = scalarWord(word);
    return R.fromPartialEvals(limbs);
}
const Sink = struct {
    builder: *R.Builder,
    pub fn zero(self: *@This(), value: R.Scalar) !void {
        try self.builder.constrainZero(value);
    }
};
/// Production caller supplies the independently reconstructed local Owner.
/// Original claims and all forwarded census cells are actual byte inputs.
pub fn prepare(backing: std.mem.Allocator, public: *const Bus.Owner) !Prepared {
    try public.validateSources();
    var arena = try Arena.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    var builder = R.Builder.init(a);
    defer builder.deinit();
    var reader = Reader{ .a = a, .builder = &builder, .public = .{ .public = public } };
    var claims: [5][A.CLAIM_COUNT][4][4]R.Scalar = undefined;
    var output: [6][4]R.Scalar = undefined;
    var counts: [4][6]R.Scalar = undefined;
    var row_words: [4][4]R.Scalar = undefined;
    var node_words: [4][6][4]R.Scalar = undefined;
    var ordinals: [4]?[4]R.Scalar = @splat(null);
    const node = try public.policy.forest.node(public.policy.index, public.policy.expected_plan);
    for (public.children[0..public.child_count], node.children[0..node.child_count], 0..) |*optional, _, child_index| {
        const ordinal: u32 = @intCast(child_index);
        const child = &optional.*.?;
        const normal = switch (child.*) {
            .raw => |*v| &v.normal,
            .fold => |*v| &v.normal,
            .node => |*v| &v.normal,
        };
        for (&claims[child_index], 0..) |*q, index| q.* = try reader.claim(.child_cell, ordinal, normal.claim_first + @as(u32, @intCast(4 * index)));
        switch (child.*) {
            .raw, .fold => {
                const is_raw = child.* == .raw;
                const first = normal.word_first orelse return error.UntrustedPageForestClaimLayout;
                const index_cell = first + @as(u32, if (is_raw) 19 else 27);
                ordinals[child_index] = try reader.word(.child_cell, ordinal, index_cell);
                const rows = try reader.word(.child_cell, ordinal, index_cell + 1);
                // All operation nodes follow the complete input prefix.
                row_words[child_index] = rows;
            },
            .node => {
                const first = normal.word_first orelse return error.UntrustedPageForestClaimLayout;
                for (0..6) |i| node_words[child_index][i] = try reader.word(.child_cell, ordinal, first + 3 + @as(u32, @intCast(i)));
            },
        }
    }
    for (&claims[4], 0..) |*q, index| q.* = try reader.claim(.output_slot, 0, Bus.CLAIM_FIRST + @as(u32, @intCast(4 * index)));
    for (&output, 0..) |*word, i| word.* = try reader.word(.output_slot, 0, 3 + @as(u32, @intCast(i)));
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    var sink = Sink{ .builder = &builder };
    var child_claims: [4][A.CLAIM_COUNT]R.Scalar = undefined;
    var census: [6]R.Scalar = @splat(R.Scalar.zero());
    var cursor = scalarWord(output[0]);
    for (public.children[0..public.child_count], node.children[0..node.child_count], 0..) |_, ref, child_index| {
        if (ref == .leaf) {
            const is_raw = ref.leaf < public.policy.forest.raw.len;
            counts[child_index] = .{ R.Scalar.fromBase(M.fromCanonical(ref.leaf)), R.Scalar.one(), R.Scalar.fromBase(M.fromCanonical(@intFromBool(is_raw))), R.Scalar.fromBase(M.fromCanonical(@intFromBool(!is_raw))), R.Scalar.zero(), R.Scalar.zero() };
            counts[child_index][if (is_raw) 4 else 5] = scalarWord(row_words[child_index]);
            const expected_ordinal: u32 = if (is_raw) ref.leaf else ref.leaf - @as(u32, @intCast(public.policy.forest.raw.len));
            try sink.zero(scalarWord(ordinals[child_index].?).sub(R.Scalar.fromBase(M.fromCanonical(expected_ordinal))));
        } else for (0..6) |i| {
            counts[child_index][i] = scalarWord(node_words[child_index][i]);
        }
        try sink.zero(counts[child_index][0].sub(cursor));
        cursor = cursor.add(counts[child_index][1]);
        for (1..6) |i| census[i] = census[i].add(counts[child_index][i]);
        for (&child_claims[child_index], claims[child_index]) |*value, bytes| value.* = scalarClaim(bytes);
    }
    try sink.zero(cursor.sub(scalarWord(output[0])).sub(scalarWord(output[1])));
    for (1..6) |i| try sink.zero(census[i].sub(scalarWord(output[i])));
    var exported: [A.CLAIM_COUNT]R.Scalar = undefined;
    for (&exported, claims[4]) |*value, bytes| value.* = scalarClaim(bytes);
    try A.merge(R.Scalar, child_claims[0..public.child_count], exported, &sink);
    if (public.policy.forest.geometry.root.? == public.policy.index) {
        try sink.zero(scalarWord(output[0]));
        try sink.zero(scalarWord(output[1]).sub(R.Scalar.fromBase(M.fromCanonical(public.policy.forest.geometry.leaves))));
        try A.close(R.Scalar, &public.policy.forest.context.admitted, exported, &sink);
    }
    try builder.check();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const input = try reader.inputs.toOwnedSlice(a);
    const sources = try reader.sources.toOwnedSlice(a);
    const evaluated = try a.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(input, evaluated);
    return .{ .arena = arena, .circuit = circuit, .inputs = input, .values = evaluated, .sources = sources };
}
