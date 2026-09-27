//! Actual lower-child-byte to upper-public-export equations. Every copied
//! descendant byte has two separate consumed inputs, even when values agree.
//! Optional native span output derives from genuine contributing child spans.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const r = @import("composition_graph_recorder.zig");
const S = r.Scalar;
const Bus = @import("../block_v5_heterogeneous_hierarchy_public_bus_v1.zig");
const Rows = @import("block_v5_heterogeneous_hierarchy_graph_rows_v1.zig");
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    circuit: r.Circuit,
    inputs: []Q,
    values: []Q,
    sources: []Bus.Wire,
    pub fn deinit(self: *Prepared) void {
        self.circuit.deinit();
        self.allocator.free(self.inputs);
        self.allocator.free(self.values);
        self.allocator.free(self.sources);
        self.* = undefined;
    }
    pub fn graph(self: *const Prepared) Rows.Graph {
        return .{ .circuit = &self.circuit, .inputs = self.inputs, .values = self.values, .sources = self.sources };
    }
};
const Equal = struct { left: usize, right: usize };
const Collector = struct {
    a: std.mem.Allocator,
    builder: *r.Builder,
    inputs: std.ArrayList(Q) = .empty,
    symbols: std.ArrayList(S) = .empty,
    sources: std.ArrayList(Bus.Wire) = .empty,
    equalities: std.ArrayList(Equal) = .empty,
    fn deinit(self: *Collector) void {
        self.inputs.deinit(self.a);
        self.symbols.deinit(self.a);
        self.sources.deinit(self.a);
        self.equalities.deinit(self.a);
    }
    fn input(self: *Collector, values: Bus.Values, source: Bus.Wire) !usize {
        if (self.inputs.items.len >= 1 << 24) return error.HeterogeneousHierarchyResourceLimit;
        const index = self.inputs.items.len;
        const tuple = try values.at(source);
        try self.inputs.append(self.a, Q.fromM31Array(tuple));
        try self.symbols.append(self.a, (try self.builder.input()).value);
        try self.sources.append(self.a, source);
        return index;
    }
    fn equal(self: *Collector, values: Bus.Values, left: Bus.Wire, right: Bus.Wire) !void {
        const l = try self.input(values, left);
        const rr = try self.input(values, right);
        try self.equalities.append(self.a, .{ .left = l, .right = rr });
    }
    fn spanWords(self: *Collector, values: Bus.Values, child: ?u32) ![6][4]usize {
        var result: [6][4]usize = undefined;
        for (&result, 0..) |*word_indices, i| for (word_indices, 0..) |*index, part| {
            index.* = try self.input(values, .{ .circuit = 0, .wire = 0, .uses = 1, .kind = if (child != null) .child_span else .export_span, .child = child orelse 0, .coordinate = @intCast(i), .part = @intCast(part) });
        };
        return result;
    }
};
fn word(symbols: []const S, indices: [4]usize) S {
    var value = S.zero();
    inline for (0..4) |part| value = value.add(symbols[indices[part]].mul(S.fromBase(core.fields.m31.M31.fromCanonical(@as(u32, 1) << @as(u5, @intCast(8 * part))))));
    return value;
}
pub fn prepare(a: std.mem.Allocator, values: Bus.Values) !Prepared {
    try values.validate();
    var builder = r.Builder.init(a);
    defer builder.deinit();
    var collected = Collector{ .a = a, .builder = &builder };
    defer collected.deinit();
    for (values.children, 0..) |*source, slot| for (source.exports) |exported| {
        const original = &values.plan.full.children[exported.ordinal];
        if (exported.count != original.cells.len) return error.InvalidHeterogeneousHierarchyExport;
        for (0..exported.count) |cell| for (0..4) |part| try collected.equal(values, .{ .circuit = 0, .wire = 0, .uses = 1, .kind = .child_cell, .child = @intCast(slot), .coordinate = exported.first + @as(u32, @intCast(cell)), .part = @intCast(part) }, .{ .circuit = 0, .wire = 0, .uses = 1, .kind = .export_cell, .child = exported.ordinal, .coordinate = @intCast(cell), .part = @intCast(part) });
    };
    const bounds = try values.plan.bounds(.{ .node = values.index });
    const selected = try @import("block_v5_heterogeneous_pairing_v1.zig").pairs(a, values.plan.full);
    defer a.free(selected);
    for (selected) |pair| if (pair.left >= bounds.first and pair.left - bounds.first < bounds.count and pair.right >= bounds.first and pair.right - bounds.first < bounds.count) {
        for (0..8) |cell| for (0..4) |part| try collected.equal(values, .{ .circuit = 0, .wire = 0, .uses = 1, .kind = .export_cell, .child = pair.left, .coordinate = pair.left_cell + @as(u32, @intCast(cell)), .part = @intCast(part) }, .{ .circuit = 0, .wire = 0, .uses = 1, .kind = .export_cell, .child = pair.right, .coordinate = pair.right_cell + @as(u32, @intCast(cell)), .part = @intCast(part) });
    };
    var spans: [4][6][4]usize = undefined;
    var span_count: usize = 0;
    for (values.children, 0..) |*source, slot| if (source.span != null) {
        spans[span_count] = try collected.spanWords(values, @intCast(slot));
        span_count += 1;
        // Native arithmetic leaves derive their span from their independently
        // admitted actual source shape. Intermediate spans must ALSO request
        // bytes from the genuinely verified lower-node transcript frame.
        if (source.ref == .node) {
            const first = source.span_cell orelse return error.InvalidHeterogeneousHierarchySpan;
            for (0..6) |cell| for (0..4) |part| try collected.equal(values, .{ .circuit = 0, .wire = 0, .uses = 1, .kind = .child_cell, .child = @intCast(slot), .coordinate = first + @as(u32, @intCast(cell)), .part = @intCast(part) }, .{ .circuit = 0, .wire = 0, .uses = 1, .kind = .child_span, .child = @intCast(slot), .coordinate = @intCast(cell), .part = @intCast(part) });
        }
    };
    const output = if (span_count != 0) try collected.spanWords(values, null) else null;
    return finish(a, &builder, &collected, spans[0..span_count], output);
}
fn finish(a: std.mem.Allocator, builder: *r.Builder, collected: *Collector, spans: []const [6][4]usize, output: ?[6][4]usize) !Prepared {
    const span_count = spans.len;
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    for (collected.equalities.items) |equal| try builder.constrainZero(collected.symbols.items[equal.left].sub(collected.symbols.items[equal.right]));
    // These exact byte-lifted span inputs are also used by the original
    // child's pc_clock composition. Repeat the three adjacency equations here
    // so the exported aggregate is independently linked to the same sources.
    for (0..span_count) |index| {
        if (index == 0) continue;
        const left = spans[index - 1];
        const right = spans[index];
        try builder.constrainZero(word(collected.symbols.items, right[0]).sub(word(collected.symbols.items, left[0]).add(word(collected.symbols.items, left[1]))));
        try builder.constrainZero(word(collected.symbols.items, right[2]).sub(word(collected.symbols.items, left[3]).add(S.one())));
        try builder.constrainZero(word(collected.symbols.items, right[4]).sub(word(collected.symbols.items, left[5])));
    }
    if (output) |o| {
        var counts = S.zero();
        for (spans) |child| counts = counts.add(word(collected.symbols.items, child[1]));
        const derived = [6]S{ word(collected.symbols.items, spans[0][0]), counts, word(collected.symbols.items, spans[0][2]), word(collected.symbols.items, spans[span_count - 1][3]), word(collected.symbols.items, spans[0][4]), word(collected.symbols.items, spans[span_count - 1][5]) };
        for (o, derived) |indices, expected| try builder.constrainZero(word(collected.symbols.items, indices).sub(expected));
    }
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const inputs = try collected.inputs.toOwnedSlice(a);
    errdefer a.free(inputs);
    const sources = try collected.sources.toOwnedSlice(a);
    errdefer a.free(sources);
    const evaluated = try a.alloc(Q, circuit.nodes.len);
    errdefer a.free(evaluated);
    try circuit.evaluateInto(inputs, evaluated);
    return .{ .allocator = a, .circuit = circuit, .inputs = inputs, .values = evaluated, .sources = sources };
}

/// Equation-only fixtures: these inputs are never a Source or Fresh receipt.
/// The canonical producer calls the same finish equation body after admission.
pub const testing = struct {
    pub const Equality = Equal;
    pub fn record(a: std.mem.Allocator, samples: []const Q, sources: []const Bus.Wire, equalities: []const Equal, spans: []const [6][4]usize, output: ?[6][4]usize) !Prepared {
        if (samples.len == 0 or samples.len != sources.len or spans.len > 4) return error.InvalidHeterogeneousGraphShape;
        for (samples) |sample| for (sample.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.UntrustedHeterogeneousGraphInput;
        for (equalities) |eq| if (eq.left >= samples.len or eq.right >= samples.len) return error.InvalidHeterogeneousGraphShape;
        for (spans) |span| for (span) |word_indices| for (word_indices) |index| if (index >= samples.len) return error.InvalidHeterogeneousGraphShape;
        if (output) |span| for (span) |word_indices| for (word_indices) |index| if (index >= samples.len) return error.InvalidHeterogeneousGraphShape;
        var builder = r.Builder.init(a);
        defer builder.deinit();
        var collected = Collector{ .a = a, .builder = &builder };
        defer collected.deinit();
        try collected.inputs.appendSlice(a, samples);
        try collected.sources.appendSlice(a, sources);
        try collected.equalities.appendSlice(a, equalities);
        for (samples) |_| try collected.symbols.append(a, (try builder.input()).value);
        return finish(a, &builder, &collected, spans, output);
    }
};
