//! Compact exports are actual equations over original leaf or lower compact
//! public bytes. Completed scope zeros and the exact signed accounting kernel
//! are included in the same parent arithmetic, not host summary receipts.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const R = @import("composition_graph_recorder.zig");
const S = R.Scalar;
const Bus = @import("../block_v5_heterogeneous_scoped_public_bus_v1.zig");
const Scoped = @import("../block_v5_heterogeneous_scoped_plan_v1.zig");
const Rows = @import("block_v5_heterogeneous_scoped_graph_rows_v1.zig");
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    circuit: R.Circuit,
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
const Word = [4]usize;
const Felt = [4]Word;
const Input = struct { requirement: u32, indices: Felt, negative: bool };
const Equality = struct { left: usize, right: usize };
const Collector = struct {
    a: std.mem.Allocator,
    builder: *R.Builder,
    inputs: std.ArrayList(Q) = .empty,
    symbols: std.ArrayList(S) = .empty,
    sources: std.ArrayList(Bus.Wire) = .empty,
    scopes: std.ArrayList(Input) = .empty,
    equalities: std.ArrayList(Equality) = .empty,
    fn deinit(self: *Collector) void {
        self.inputs.deinit(self.a);
        self.symbols.deinit(self.a);
        self.sources.deinit(self.a);
        self.scopes.deinit(self.a);
        self.equalities.deinit(self.a);
    }
    fn input(self: *Collector, values: Bus.Values, wire: Bus.Wire) !usize {
        if (self.inputs.items.len >= 1 << 22) return error.ScopedSummaryResourceLimit;
        const at = self.inputs.items.len;
        try self.inputs.append(self.a, Q.fromM31Array(try values.at(wire)));
        try self.sources.append(self.a, wire);
        try self.symbols.append(self.a, (try self.builder.input()).value);
        return at;
    }
    fn felt(self: *Collector, values: Bus.Values, kind: Bus.Kind, child: u32, first: u32) !Felt {
        var indices: Felt = undefined;
        for (&indices, 0..) |*word_indices, component| for (word_indices, 0..) |*at, part| {
            at.* = try self.input(values, .{ .circuit = 0, .wire = 0, .uses = 1, .kind = kind, .child = child, .coordinate = first + @as(u32, @intCast(component)), .part = @intCast(part) });
        };
        return indices;
    }
    fn byteFelt(self: *Collector, values: Bus.Values, child: u32, cell: u32, part: u2) !Felt {
        // One authenticated byte, other limbs are authenticated graph zero
        // constants. Marker maxInt means a constant, never a source request.
        var indices: Felt = @splat(@splat(std.math.maxInt(usize)));
        indices[0][0] = try self.input(values, .{ .circuit = 0, .wire = 0, .uses = 1, .kind = .child_cell, .child = child, .coordinate = cell, .part = part });
        return indices;
    }
    fn spanWords(self: *Collector, values: Bus.Values, child: ?u32) ![6]Word {
        var indices: [6]Word = undefined;
        for (&indices, 0..) |*word_indices, coordinate| for (word_indices, 0..) |*at, part| {
            at.* = try self.input(values, .{ .circuit = 0, .wire = 0, .uses = 1, .kind = if (child == null) .output_span else .child_span, .child = child orelse 0, .coordinate = @intCast(coordinate), .part = @intCast(part) });
        };
        return indices;
    }
};
fn liftWord(symbols: []const S, indices: Word) S {
    var value = S.zero();
    inline for (0..4) |part| if (indices[part] != std.math.maxInt(usize)) {
        value = value.add(symbols[indices[part]].mul(S.fromBase(M.fromCanonical(@as(u32, 1) << @as(u5, @intCast(8 * part))))));
    };
    return value;
}
fn liftFelt(symbols: []const S, indices: Felt) S {
    var value = S.zero();
    inline for (0..4) |component| {
        var basis: [4]M = @splat(M.zero());
        basis[component] = M.one();
        value = value.add(liftWord(symbols, indices[component]).mul(S.fromSecure(Q.fromM31Array(basis))));
    }
    return value;
}
const Sink = struct {
    builder: *R.Builder,
    pub fn zero(self: *@This(), value: S, _: anyerror) !void {
        try self.builder.constrainZero(value);
    }
};
pub fn prepare(a: std.mem.Allocator, values: Bus.Values) !Prepared {
    try values.validate();
    return recordAdmitted(a, values);
}
/// Exact canonical equation body for a separately validated immutable local
/// setup admission. The caller must preserve original source/AIR authority.
pub fn recordLocallyAdmitted(a: std.mem.Allocator, values: Bus.Values) !Prepared {
    return recordAdmitted(a, values);
}
fn recordAdmitted(a: std.mem.Allocator, values: Bus.Values) !Prepared {
    var builder = R.Builder.init(a);
    defer builder.deinit();
    var collected = Collector{ .a = a, .builder = &builder };
    defer collected.deinit();
    const route = values.routes.nodes[values.index];
    const ranges = try a.alloc(struct { first: usize, end: usize }, route.inputs.len);
    defer a.free(ranges);
    for (route.inputs, 0..) |id, input_index| {
        ranges[input_index].first = collected.scopes.items.len;
        const requirement = values.routes.scoped.requirements[id];
        for (values.children, 0..) |*child, slot| switch (child.ref) {
            .leaf => |ordinal| for (Scoped.Plan.termsFor(requirement, ordinal)) |term| {
                const indices = switch (term.selection) {
                    .byte => |ref| try collected.byteFelt(values, @intCast(slot), ref.cell, ref.part),
                    .words => |ref| block: {
                        var indices: Felt = undefined;
                        for (&indices, ref.selectors) |*word_indices, selector| {
                            const source_frame = values.routes.scoped.full.children[ordinal].frames[selector.frame];
                            const first = source_frame.first + selector.word;
                            for (word_indices, 0..) |*at, part| at.* = try collected.input(values, .{ .circuit = 0, .wire = 0, .uses = 1, .kind = .child_cell, .child = @intCast(slot), .coordinate = first, .part = @intCast(part) });
                        }
                        break :block indices;
                    },
                    .felt => |ref| block: {
                        const first = values.routes.scoped.full.children[ordinal].frames[ref.frame].first + 4 * ref.felt;
                        break :block try collected.felt(values, .child_cell, @intCast(slot), first);
                    },
                };
                try collected.scopes.append(a, .{ .requirement = id, .indices = indices, .negative = term.negative });
            },
            .node => |ordinal| {
                const ids = values.routes.nodes[ordinal].exports;
                if (Scoped.Plan.contains(ids, id)) {
                    const source_slot = try child.findSlot(id);
                    try collected.scopes.append(a, .{ .requirement = id, .indices = try collected.felt(values, .child_cell, @intCast(slot), source_slot.first), .negative = false });
                }
            },
        };
        ranges[input_index].end = collected.scopes.items.len;
    }
    const outputs = try a.alloc(Felt, route.exports.len);
    defer a.free(outputs);
    for (outputs, 0..) |*indices, slot| indices.* = try collected.felt(values, .output_slot, 0, @intCast(4 * slot));
    var spans: [4][6]Word = undefined;
    var span_count: usize = 0;
    for (values.children, 0..) |*child, slot| if (child.span != null) {
        spans[span_count] = try collected.spanWords(values, @intCast(slot));
        span_count += 1;
        if (child.ref == .node) {
            const first = child.span_cell orelse return error.InvalidScopedPublicSpan;
            for (0..6) |coordinate| for (0..4) |part| {
                const left = try collected.input(values, .{ .circuit = 0, .wire = 0, .uses = 1, .kind = .child_cell, .child = @intCast(slot), .coordinate = first + @as(u32, @intCast(coordinate)), .part = @intCast(part) });
                const right = spans[span_count - 1][coordinate][part];
                try collected.equalities.append(a, .{ .left = left, .right = right });
            };
        }
    };
    const span_output = if (span_count != 0) try collected.spanWords(values, null) else null;
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    const sums = try a.alloc(S, route.inputs.len);
    defer a.free(sums);
    for (sums, route.inputs, ranges) |*sum, id, range| {
        sum.* = S.zero();
        for (collected.scopes.items[range.first..range.end]) |input| {
            const contribution = liftFelt(collected.symbols.items, input.indices);
            sum.* = if (input.negative) sum.sub(contribution) else sum.add(contribution);
        }
        if (Scoped.Plan.contains(route.closed, id)) try builder.constrainZero(sum.*);
    }
    for (route.exports, outputs) |id, indices| {
        const at = std.sort.binarySearch(u32, route.inputs, id, struct {
            fn order(key: u32, item: u32) std.math.Order {
                return std.math.order(key, item);
            }
        }.order) orelse return error.InvalidScopedRoute;
        try builder.constrainZero(liftFelt(collected.symbols.items, indices).sub(sums[at]));
    }
    // Exact KNOWN signed accounting stays separate. The public program
    // boundary and register compensation are NOT yet exported by Semantic;
    // their two missing coordinates remain typed obligations. This equation
    // binds the known residual, never constrains it to zero or closes a block.
    if (values.routes.cohorts.root == .node and values.routes.cohorts.root.node == values.index) {
        const Join = @import("../../prover/block_v5_global_join_algebra_v1.zig");
        var coordinates: [11]S = @splat(S.zero());
        var seen: [11]bool = @splat(false);
        for (route.exports, outputs) |id, indices| {
            const key = values.routes.scoped.requirements[id].key;
            if (key.kind == .accounting) {
                if (key.scope != 0 or key.coordinate >= 11 or seen[key.coordinate]) return error.InvalidScopedPublicCensus;
                coordinates[key.coordinate] = liftFelt(collected.symbols.items, indices);
                seen[key.coordinate] = true;
            }
        }
        for ([_]usize{ 0, 1, 3, 4, 5, 6, 7, 9, 10 }) |coordinate| if (!seen[coordinate]) return error.InvalidScopedPublicCensus;
        if (seen[2] or seen[8]) return error.MissingAuthenticatedScopedCompensation;
        var accounting: Join.Accounting(S) = undefined;
        inline for (std.meta.fields(@TypeOf(accounting)), 0..) |field, i| @field(accounting, field.name) = coordinates[i];
        const byte_parts = [_]struct { sum: S }{.{ .sum = coordinates[9] }};
        try builder.constrainZero(Join.Algebra(S).residual(accounting, &byte_parts).sub(coordinates[10]));
    }
    for (collected.equalities.items) |equality| try builder.constrainZero(collected.symbols.items[equality.left].sub(collected.symbols.items[equality.right]));
    for (0..span_count) |index| if (index != 0) {
        const left = spans[index - 1];
        const right = spans[index];
        try builder.constrainZero(liftWord(collected.symbols.items, right[0]).sub(liftWord(collected.symbols.items, left[0]).add(liftWord(collected.symbols.items, left[1]))));
        try builder.constrainZero(liftWord(collected.symbols.items, right[2]).sub(liftWord(collected.symbols.items, left[3]).add(S.one())));
        try builder.constrainZero(liftWord(collected.symbols.items, right[4]).sub(liftWord(collected.symbols.items, left[5])));
    };
    if (span_output) |output| {
        var counts = S.zero();
        for (spans[0..span_count]) |child_span| counts = counts.add(liftWord(collected.symbols.items, child_span[1]));
        const expected = [6]S{ liftWord(collected.symbols.items, spans[0][0]), counts, liftWord(collected.symbols.items, spans[0][2]), liftWord(collected.symbols.items, spans[span_count - 1][3]), liftWord(collected.symbols.items, spans[0][4]), liftWord(collected.symbols.items, spans[span_count - 1][5]) };
        for (output, expected) |indices, value| try builder.constrainZero(liftWord(collected.symbols.items, indices).sub(value));
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
    return .{ .allocator = a, .circuit = circuit, .inputs = inputs, .sources = sources, .values = evaluated };
}

/// Pure equation views for tests; this grants no admission or proof authority.
pub const testing = struct {
    pub const record = recordAdmitted;
};
