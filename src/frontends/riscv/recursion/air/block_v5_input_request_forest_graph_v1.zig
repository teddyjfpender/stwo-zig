//! Request propagation equations for genuine bounded forest parents. Each
//! child must be a real independently admitted WM/v2 or prior forest capture.
//! Own request cells enter the SAME graph through actual public output supply;
//! nothing is inferred from a digest/host sum. The final node binds one carrier.
const std = @import("std");
const Arena = @import("stable_graph_arena_v1.zig").Owned;
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const R = @import("composition_graph_recorder.zig");
const Bus = @import("../block_v5_heterogeneous_scoped_public_bus_v1.zig");
const Layout = @import("../block_v5_input_request_forest_public_v1.zig");
const Range = @import("../block_v5_input_request_forest_plan_v1.zig").Range;
const Wire = Bus.Wire;
const Graph = @import("block_v5_heterogeneous_scoped_graph_rows_v1.zig").Graph;
pub const Coordinate = struct { child: u32, first_cell: u32, word_count: u32 };
pub const Child = struct {
    root: Coordinate,
    length: Coordinate,
    prefix: Coordinate,
    frontier: []const Coordinate,
    first_cycle: ?Coordinate,
    last_cycle: ?Coordinate,
    first_window: ?Coordinate,
    window_count: ?Coordinate,
    /// None for original WM/v2 (exact1 physical leaf), present for forest nodes.
    leaf_count: ?Coordinate,
};
/// Pure routing descriptor. Production derives it from independently admitted
/// original node/input layouts; it is never proof or cryptographic admission.
pub const Descriptor = struct {
    carrier: bool,
    child_count: u32,
    range: Range,
    prefix_words: u32,
    frontier_count: usize,
    pub fn rangeCoordinates(_: *const @This()) struct { first: u32, count: u32, leaves: u32 } {
        return .{ .first = 4, .count = 5, .leaves = 6 };
    }
    pub fn firstCycle(_: *const @This()) Layout.Coordinate {
        return .{ .first_cell = 32, .word_count = 2 };
    }
    pub fn lastCycle(_: *const @This()) Layout.Coordinate {
        return .{ .first_cell = 34, .word_count = 2 };
    }
    pub fn inputRoot(_: *const @This()) Layout.Coordinate {
        return .{ .first_cell = 49, .word_count = 8 };
    }
    pub fn inputLength(_: *const @This()) Layout.Coordinate {
        return .{ .first_cell = 38, .word_count = 1 };
    }
    pub fn inputPrefix(self: *const @This()) Layout.Coordinate {
        return .{ .first_cell = 57, .word_count = self.prefix_words };
    }
    pub fn frontier(self: *const @This(), ordinal: usize) !Layout.Coordinate {
        if (ordinal >= self.frontier_count) return error.UntrustedInputRequestGraph;
        const offset = try std.math.add(usize, 57 + @as(usize, self.prefix_words), try std.math.add(usize, try std.math.mul(usize, 10, ordinal), 2));
        return .{ .first_cell = std.math.cast(u32, offset) orelse return error.Overflow, .word_count = 8 };
    }
};
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
const Inputs = struct {
    a: std.mem.Allocator,
    b: *R.Builder,
    inputs: std.ArrayList(Q) = .empty,
    sources: std.ArrayList(Wire) = .empty,
    symbols: std.ArrayList(R.Scalar) = .empty,
    gathering: bool = true,
    cursor: usize = 0,
    fn take(self: *@This(), values: anytype, wire: Wire) !R.Scalar {
        if (!self.gathering) {
            if (self.cursor >= self.symbols.items.len or !std.meta.eql(self.sources.items[self.cursor], wire)) return error.UntrustedInputRequestGraph;
            const symbol = self.symbols.items[self.cursor];
            self.cursor += 1;
            return symbol;
        }
        const symbol = (try self.b.input()).value;
        try self.inputs.append(self.a, Q.fromM31Array(try values.at(wire)));
        try self.sources.append(self.a, wire);
        try self.symbols.append(self.a, symbol);
        return symbol;
    }
    fn own(self: *@This(), values: anytype, coordinate: u32, part: u2) !R.Scalar {
        return self.take(values, .{ .circuit = 0, .wire = 0, .uses = 1, .kind = .output_slot, .coordinate = coordinate, .part = part });
    }
    fn child(self: *@This(), values: anytype, coordinate: Coordinate, word: u32, part: u2) !R.Scalar {
        if (word >= coordinate.word_count) return error.UntrustedInputRequestGraph;
        return self.take(values, .{ .circuit = 0, .wire = 0, .uses = 1, .kind = .child_cell, .child = coordinate.child, .coordinate = try std.math.add(u32, coordinate.first_cell, word), .part = part });
    }
    fn equal(self: *@This(), values: anytype, source: Coordinate, target: Layout.Coordinate) !void {
        if (source.word_count != target.word_count) return error.UntrustedInputRequestGraph;
        for (0..target.word_count) |word| for (0..4) |part| {
            const left = try self.child(values, source, @intCast(word), @intCast(part));
            const right = try self.own(values, try std.math.add(u32, target.first_cell, @intCast(word)), @intCast(part));
            if (!self.gathering) {
                try self.b.constrainZero(left.sub(right));
                try self.b.check();
            }
        };
    }
    fn clock(self: *@This(), values: anytype, coordinate: Coordinate) ![8]R.Scalar {
        if (coordinate.word_count != 2) return error.UntrustedInputRequestGraph;
        var out: [8]R.Scalar = undefined;
        for (&out, 0..) |*byte, index| byte.* = try self.child(values, coordinate, @intCast(index / 4), @intCast(index % 4));
        return out;
    }
    fn integer(self: *@This(), values: anytype, source: Coordinate) !R.Scalar {
        if (source.word_count != 1) return error.UntrustedInputRequestGraph;
        var bytes: [4]R.Scalar = undefined;
        for (&bytes, 0..) |*byte, part| byte.* = try self.child(values, source, 0, @intCast(part));
        if (self.gathering) return R.Scalar.zero();
        var result = R.Scalar.zero();
        for (bytes, 0..) |byte, part| result = result.add(byte.mul(R.Scalar.fromSecure(Q.fromBase(M.fromU64(@as(u64, 1) << @as(u6, @intCast(8 * part)))))));
        try self.b.check();
        return result;
    }
    fn ownInteger(self: *@This(), values: anytype, coordinate: u32) !R.Scalar {
        var bytes: [4]R.Scalar = undefined;
        for (&bytes, 0..) |*byte, part| byte.* = try self.own(values, coordinate, @intCast(part));
        if (self.gathering) return R.Scalar.zero();
        var result = R.Scalar.zero();
        for (bytes, 0..) |byte, part| result = result.add(byte.mul(R.Scalar.fromSecure(Q.fromBase(M.fromU64(@as(u64, 1) << @as(u6, @intCast(8 * part)))))));
        try self.b.check();
        return result;
    }
};
/// Pure exact equation body; production derives all Child coordinates from the
/// ORIGINAL typed layouts. Counts are independently bounded below2^30, making
/// their arithmetic injective in M31. Full clocks use eight separate byte cells.
pub fn prepare(backing: std.mem.Allocator, values: anytype, own: *const Layout.Owned, children: []const Child, carrier: ?Child, ranges: []const Range) !Prepared {
    const node = own.policy.forest.geometry.nodes[own.policy.index];
    return prepareForDescriptor(backing, values, .{ .carrier = node.kind == .carrier, .child_count = node.child_count, .range = node.range, .prefix_words = @intCast(own.policy.forest.input.prefix_count), .frontier_count = own.policy.forest.input.frontier.len }, children, carrier, ranges);
}
pub fn prepareForDescriptor(backing: std.mem.Allocator, values: anytype, descriptor: Descriptor, children: []const Child, carrier: ?Child, ranges: []const Range) !Prepared {
    if (children.len == 0 or children.len > 4 or children.len != ranges.len or descriptor.child_count != children.len or descriptor.prefix_words > 239 or descriptor.frontier_count > 32) return error.UntrustedInputRequestGraph;
    if (descriptor.carrier != (carrier != null) or descriptor.range.count >= 1 << 30 or descriptor.range.leaves >= 1 << 30) return error.UntrustedInputRequestGraph;
    const own = &descriptor;
    var arena = try Arena.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    var builder = R.Builder.init(a);
    defer builder.deinit();
    var inputs = Inputs{ .a = a, .b = &builder };
    // The recorder ABI requires every input to be a leading node. First walk
    // gathers ONLY sources/symbols; second exact walk records all operations.
    try equations(&inputs, values, own, children, carrier, ranges);
    inputs.gathering = false;
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    try equations(&inputs, values, own, children, carrier, ranges);
    if (inputs.cursor != inputs.symbols.items.len) return error.UntrustedInputRequestGraph;
    try builder.check();
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const in = try inputs.inputs.toOwnedSlice(a);
    const sources = try inputs.sources.toOwnedSlice(a);
    const evaluation = try a.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(in, evaluation);
    return .{ .arena = arena, .circuit = circuit, .inputs = in, .values = evaluation, .sources = sources };
}

fn equations(inputs: *Inputs, values: anytype, own: *const Descriptor, children: []const Child, carrier: ?Child, ranges: []const Range) !void {
    const output_ranges = own.rangeCoordinates();
    const output_first = try inputs.ownInteger(values, output_ranges.first);
    const output_count = try inputs.ownInteger(values, output_ranges.count);
    const output_leaves = try inputs.ownInteger(values, output_ranges.leaves);
    var total_count = R.Scalar.zero();
    var total_leaves = R.Scalar.zero();
    var previous_first: ?R.Scalar = null;
    var previous_count: ?R.Scalar = null;
    var previous_clock: ?[8]R.Scalar = null;
    for (children, ranges, 0..) |child, range, index| {
        if (range.count == 0 or range.count >= 1 << 30 or range.first >= 1 << 30 or range.leaves == 0 or range.leaves >= 1 << 30 or child.frontier.len != own.frontier_count) return error.UntrustedInputRequestGraph;
        try inputs.equal(values, child.root, own.inputRoot());
        try inputs.equal(values, child.length, own.inputLength());
        try inputs.equal(values, child.prefix, own.inputPrefix());
        for (child.frontier, 0..) |cv, ordinal| try inputs.equal(values, cv, try own.frontier(ordinal));
        const first = try inputs.integer(values, child.first_window orelse return error.UntrustedInputRequestGraph);
        const count = try inputs.integer(values, child.window_count orelse return error.UntrustedInputRequestGraph);
        const leaf_count = if (child.leaf_count) |coordinate| try inputs.integer(values, coordinate) else R.Scalar.one();

        if (!inputs.gathering) {
            if (previous_first) |p| try inputs.b.constrainZero(first.sub(p.add(previous_count.?))) else try inputs.b.constrainZero(first.sub(output_first));
            total_count = total_count.add(count);
            total_leaves = total_leaves.add(leaf_count);
            try inputs.b.check();
        }
        const first_clock = try inputs.clock(values, child.first_cycle orelse return error.UntrustedInputRequestGraph);
        const last_clock = try inputs.clock(values, child.last_cycle orelse return error.UntrustedInputRequestGraph);
        if (!inputs.gathering) {
            if (previous_clock) |last| {
                var sink = Sink{ .builder = inputs.b };
                try @import("block_v5_global_public_tuple_algebra_v1.zig").nextCycle(R.Scalar, &sink, last, first_clock);
                try inputs.b.check();
            }
        }
        previous_clock = last_clock;
        if (index == 0) try inputs.equal(values, child.first_cycle orelse return error.UntrustedInputRequestGraph, own.firstCycle());
        if (index + 1 == children.len) try inputs.equal(values, child.last_cycle orelse return error.UntrustedInputRequestGraph, own.lastCycle());
        previous_first = first;
        previous_count = count;
    }

    if (!inputs.gathering) {
        try inputs.b.constrainZero(total_count.sub(output_count));
        try inputs.b.constrainZero(total_leaves.sub(output_leaves));
        try inputs.b.check();
    }
    if (carrier) |provider| {
        if (provider.frontier.len != own.frontier_count or provider.first_cycle != null or provider.last_cycle != null or provider.first_window != null or provider.window_count != null or provider.leaf_count != null) return error.UntrustedInputRequestGraph;
        try inputs.equal(values, provider.root, own.inputRoot());
        try inputs.equal(values, provider.length, own.inputLength());
        try inputs.equal(values, provider.prefix, own.inputPrefix());
        for (provider.frontier, 0..) |cv, ordinal| try inputs.equal(values, cv, try own.frontier(ordinal));
    }
}

const Sink = struct {
    builder: *R.Builder,
    pub fn zero(self: *@This(), value: R.Scalar, _: anyerror) !void {
        try self.builder.check();
        try self.builder.constrainZero(value);
    }
};
