//! Genuine byte equations linking all local consumers to ONE original tail
//! provider. Coordinates are reconstructed from independently admitted layouts,
//! never selected by a received proof or a matching field-value search.
const std = @import("std");
const Arena = @import("stable_graph_arena_v1.zig").Owned;
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const R = @import("composition_graph_recorder.zig");
const Bus = @import("../block_v5_input_tail_ancestor_bus_v1.zig");
const Wire = Bus.Wire;
const Graph = @import("block_v5_heterogeneous_scoped_graph_rows_v1.zig").Graph;
pub const Coordinate = struct { child: u32, first: u32, words: u32 };
pub const Pair = struct { provider: Coordinate, consumer: Coordinate };
pub const Prepared = struct {
    arena: Arena,
    circuit: R.Circuit,
    inputs: []Q,
    values: []Q,
    sources: []Wire,
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
/// One equation body for actual production and independent mutation/OOM fixtures.
/// The typed production caller derives every Pair using original public layouts.
pub fn preparePairs(backing: std.mem.Allocator, values: anytype, pairs: []const Pair) !Prepared {
    var arena = try Arena.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    var builder = R.Builder.init(a);
    defer builder.deinit();
    var inputs: std.ArrayList(Q) = .empty;
    var sources: std.ArrayList(Wire) = .empty;
    var comparisons: std.ArrayList([2]R.Scalar) = .empty;
    for (pairs) |pair| {
        if (pair.provider.words != pair.consumer.words or pair.provider.words > 239) return error.UntrustedInputTailAncestorCell;
        for (0..pair.provider.words) |word| for (0..4) |part| {
            const coordinates = [_]Coordinate{ pair.provider, pair.consumer };
            var symbols: [2]R.Scalar = undefined;
            for (&symbols, coordinates) |*symbol, coordinate| {
                const wire = Wire{ .circuit = 0, .wire = 0, .uses = 1, .kind = .child_cell, .child = coordinate.child, .coordinate = try std.math.add(u32, coordinate.first, @intCast(word)), .part = @intCast(part) };
                symbol.* = (try builder.input()).value;
                try inputs.append(a, Q.fromM31Array(try values.at(wire)));
                try sources.append(a, wire);
            }
            try comparisons.append(a, symbols);
        };
    }
    // The original graph ABI requires every input to lead all operation nodes.
    // Keep exact pair/source order while recording equality operations afterward.
    {
        try builder.activate();
        defer builder.deactivate();
        for (comparisons.items) |symbols| try builder.constrainZero(symbols[0].sub(symbols[1]));
        try builder.check();
    }
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const input = try inputs.toOwnedSlice(a);
    const source = try sources.toOwnedSlice(a);
    const evaluation = try a.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(input, evaluation);
    return .{ .arena = arena, .circuit = circuit, .inputs = input, .sources = source, .values = evaluation };
}
pub fn derivePairs(a: std.mem.Allocator, public: *const Bus.Owner) ![]Pair {
    try public.validate();
    var pairs: std.ArrayList(Pair) = .empty;
    errdefer pairs.deinit(a);
    const first = public.normalized_carrier.public_first.?;
    for (public.consumers, 0..) |*consumer, ordinal| {
        const child: u32 = @intCast(ordinal + 1);
        const prefix = consumer.prefix_count;
        const p = &consumer.owner;
        try pairs.append(a, .{ .provider = .{ .child = 0, .first = first + 13, .words = 8 }, .consumer = .{ .child = child, .first = prefix + p.input_root_first, .words = 8 } });
        try pairs.append(a, .{ .provider = .{ .child = 0, .first = first + 2, .words = 1 }, .consumer = .{ .child = child, .first = prefix + 5, .words = 1 } });
        const head = try p.inputPrefix();
        try pairs.append(a, .{ .provider = .{ .child = 0, .first = first + 21, .words = @intCast(public.carrier.prefix_count) }, .consumer = .{ .child = child, .first = prefix + head.first_cell, .words = head.word_count } });
        for (public.carrier.frontier, 0..) |_, range| {
            const cv = try p.inputFrontier(@intCast(range));
            try pairs.append(a, .{ .provider = .{ .child = 0, .first = first + 21 + @as(u32, @intCast(public.carrier.prefix_count + 10 * range + 2)), .words = 8 }, .consumer = .{ .child = child, .first = prefix + cv.first_cell, .words = cv.word_count } });
        }
    }
    return pairs.toOwnedSlice(a);
}
pub fn prepare(a: std.mem.Allocator, public: *const Bus.Owner) !Prepared {
    const pairs = try derivePairs(a, public);
    defer a.free(pairs);
    return preparePairs(a, Bus.Values{ .public = public }, pairs);
}
