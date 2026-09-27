//! Contract canonical native dot4 rows with their exact single-use query sources.
const std = @import("std");
const Q = @import("stwo_core").fields.qm31.QM31;
const M = @import("stwo_core").fields.m31.M31;
const deep = @import("blake3_native_deep.zig");
const old = @import("detached_opening_accumulate4_v1.zig");
const native = @import("native_pcs_opening4_v1.zig");
const scalar = @import("scalar_wire_source.zig");
const opening = @import("detached_opening_accumulation_plan.zig");
const matcher = @import("detached_pcs_opening_plan.zig");
const lower = @import("verifier_arithmetic_lowering.zig");
/// Only genuine four-query matches carry the large candidate payload. Most
/// arithmetic nodes cannot be opening candidates; allocating one optional
/// payload per graph node made this cold audit disproportionately large.
const CandidateIndex = struct {
    entries: std.ArrayList(matcher.Candidate) = .empty,
    fn deinit(self: *@This(), a: std.mem.Allocator) void {
        self.entries.deinit(a);
    }
    fn finish(self: *@This()) !void {
        std.mem.sort(matcher.Candidate, self.entries.items, {}, lessThan);
        for (self.entries.items, 0..) |entry, i| {
            if (i != 0 and self.entries.items[i - 1].opening.output_node == entry.opening.output_node) return error.InvalidNativePcsFusion;
        }
    }
    fn lessThan(_: void, left: matcher.Candidate, right: matcher.Candidate) bool {
        return left.opening.output_node < right.opening.output_node;
    }
    fn get(self: *const @This(), node: u32) ?matcher.Candidate {
        var first: usize = 0;
        var end = self.entries.items.len;
        while (first < end) {
            const middle = first + (end - first) / 2;
            const item = self.entries.items[middle];
            if (item.opening.output_node < node) first = middle + 1 else if (item.opening.output_node > node) end = middle else return item;
        }
        return null;
    }
};
pub const Rows = struct {
    allocator: std.mem.Allocator,
    opening: []old.Row,
    native: []native.Row,
    scalars: []scalar.Row,
    pub fn deinit(self: *Rows) void {
        self.allocator.free(self.opening);
        self.allocator.free(self.native);
        self.allocator.free(self.scalars);
        self.* = undefined;
    }
};
const Direct = @import("blake3_direct_cohort_columns_v1.zig");
const Stats = struct { opening: usize = 0, native: usize = 0, scalars: usize = 0 };
const CountSink = struct {
    counts: Stats = .{},
    fn opening(self: *@This(), _: old.Row) !void {
        self.counts.opening = try std.math.add(usize, self.counts.opening, 1);
    }
    fn nativeRow(self: *@This(), _: native.Row) !void {
        self.counts.native = try std.math.add(usize, self.counts.native, 1);
    }
    fn scalarRow(self: *@This(), _: scalar.Row) !void {
        self.counts.scalars = try std.math.add(usize, self.counts.scalars, 1);
    }
};
const RowSink = struct {
    a: std.mem.Allocator,
    retained: std.ArrayList(old.Row) = .empty,
    fused: std.ArrayList(native.Row) = .empty,
    kept: std.ArrayList(scalar.Row) = .empty,
    fn deinit(self: *@This()) void {
        self.retained.deinit(self.a);
        self.fused.deinit(self.a);
        self.kept.deinit(self.a);
    }
    fn opening(self: *@This(), row: old.Row) !void {
        try self.retained.append(self.a, row);
    }
    fn nativeRow(self: *@This(), row: native.Row) !void {
        try self.fused.append(self.a, row);
    }
    fn scalarRow(self: *@This(), row: scalar.Row) !void {
        try self.kept.append(self.a, row);
    }
    fn take(self: *@This()) !Rows {
        const owned_opening = try self.retained.toOwnedSlice(self.a);
        errdefer self.a.free(owned_opening);
        const owned_native = try self.fused.toOwnedSlice(self.a);
        errdefer self.a.free(owned_native);
        const owned_scalars = try self.kept.toOwnedSlice(self.a);
        return .{ .allocator = self.a, .opening = owned_opening, .native = owned_native, .scalars = owned_scalars };
    }
};
pub const Columns = struct {
    opening: Direct.ForAir(old),
    native: Direct.ForAir(native),
    scalars: Direct.ForAir(scalar),
    fn init(a: std.mem.Allocator, counts: Stats) !Columns {
        var opening_columns = try Direct.ForAir(old).init(a, counts.opening);
        errdefer opening_columns.deinit();
        var native_columns = try Direct.ForAir(native).init(a, counts.native);
        errdefer native_columns.deinit();
        const scalar_columns = try Direct.ForAir(scalar).init(a, counts.scalars);
        return .{ .opening = opening_columns, .native = native_columns, .scalars = scalar_columns };
    }
    pub fn deinit(self: *Columns) void {
        self.opening.deinit();
        self.native.deinit();
        self.scalars.deinit();
        self.* = undefined;
    }
    fn openingRow(self: *Columns, row: old.Row) !void {
        try self.opening.append(row);
    }
    fn nativeRow(self: *Columns, row: native.Row) !void {
        try self.native.append(row);
    }
    fn scalarRow(self: *Columns, row: scalar.Row) !void {
        try self.scalars.append(row);
    }
};
// Field and method cannot both be named opening. Keep a tiny typed adapter.
const ColumnSink = struct {
    columns: *Columns,
    fn opening(self: *@This(), row: old.Row) !void {
        try self.columns.openingRow(row);
    }
    fn nativeRow(self: *@This(), row: native.Row) !void {
        try self.columns.nativeRow(row);
    }
    fn scalarRow(self: *@This(), row: scalar.Row) !void {
        try self.columns.scalarRow(row);
    }
};
pub fn materialize(a: std.mem.Allocator, source: *const deep.Prepared, originals: []const old.Row, scalars: anytype) !Rows {
    try source.graph.validateEvaluation(&source.evaluation);
    return materializeGraph(a, source.graph.graph(), source.graph.bindings, source.evaluation.values, originals, scalars);
}
pub fn materializeColumns(a: std.mem.Allocator, source: *const deep.Prepared, originals: []const old.Row, scalars: anytype) !Columns {
    try source.graph.validateEvaluation(&source.evaluation);
    return materializeGraphColumns(a, source.graph.graph(), source.graph.bindings, source.evaluation.values, originals, scalars);
}
/// Additive fixed-only facade. Uses the SAME immutable MatchPlan and original
/// candidate matcher as live producer rows; no evaluated Deep.Prepared exists.
pub const Fixed = struct {
    allocator: std.mem.Allocator,
    lease: ?*@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
    opening: []@import("blake3_parent_row_storage.zig").FixedRow(old),
    native: []@import("blake3_parent_row_storage.zig").FixedRow(native),
    scalars: []@import("blake3_parent_row_storage.zig").FixedRow(scalar),
    pub fn deinit(self: *Fixed) void {
        const lease = self.lease;
        self.allocator.free(self.opening);
        self.allocator.free(self.native);
        self.allocator.free(self.scalars);
        self.* = undefined;
        if (lease) |owner| owner.destroy();
    }
};
pub fn materializeFixed(a: std.mem.Allocator, circuit: *const @import("pcs_deep_circuit.zig").Circuit, originals: []const @import("blake3_parent_row_storage.zig").FixedRow(old), scalars: []const @import("blake3_parent_row_storage.zig").FixedRow(scalar)) !Fixed {
    try circuit.validate();
    return materializeFixedGraph(a, circuit.graph(), circuit.bindings, originals, scalars);
}
fn materializeFixedGraph(a: std.mem.Allocator, g: @import("composition_circuit.zig").CircuitGraph, bindings: []const @import("pcs_deep_circuit.zig").InputBinding, originals: []const @import("blake3_parent_row_storage.zig").FixedRow(old), scalars: []const @import("blake3_parent_row_storage.zig").FixedRow(scalar)) !Fixed {
    try g.validate();
    const Storage = @import("blake3_parent_row_storage.zig");
    const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
    const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
    errdefer if (lease) |owner| owner.destroy();
    var plan = try MatchPlan.init(a, g, bindings);
    defer plan.deinit();
    const pending = try a.dupe(bool, plan.selected);
    defer a.free(pending);
    const emitted = try a.alloc(bool, plan.uses.len);
    defer a.free(emitted);
    @memset(emitted, false);
    var retained: std.ArrayList(Storage.FixedRow(old)) = .empty;
    defer retained.deinit(a);
    var fused: std.ArrayList(Storage.FixedRow(native)) = .empty;
    defer fused.deinit(a);
    var kept: std.ArrayList(Storage.FixedRow(scalar)) = .empty;
    defer kept.deinit(a);
    for (originals) |pp| {
        if (pp[1].v == 1502 and pp[11].v < emitted.len and emitted[pp[11].v]) return error.InvalidNativePcsFusion;
        const candidate = if (pp[1].v == 1502) plan.candidates.get(pp[11].v) else null;
        if (candidate) |c| {
            const item = c.opening;
            var lhs: [4]u32 = undefined;
            var rhs: [4]u32 = undefined;
            for (item.multiply_nodes, 0..) |node, i| {
                const operands = plan.graph.nodes[node].op.mul;
                lhs[i] = operands.lhs;
                rhs[i] = operands.rhs;
            }
            const expected = try old.fixedRow(.{ .circuit = 1502, .accumulator = item.accumulator_node, .lhs = lhs, .rhs = rhs, .output = item.output_node, .uses = plan.uses[item.output_node] });
            if (!std.meta.eql(pp, expected)) return error.InvalidNativePcsFusion;
            try fused.append(a, try native.fixedRow(.{ .circuit = 1502, .accumulator = item.accumulator_node, .queries = c.query_nodes, .weights = c.weight_nodes, .output = item.output_node, .uses = plan.uses[item.output_node] }));
            emitted[item.output_node] = true;
        } else try retained.append(a, pp);
    }
    if (fused.items.len != plan.candidates.entries.items.len) return error.InvalidNativePcsFusion;
    var removed: usize = 0;
    for (scalars) |pp| {
        const node = pp[1].v;
        if (pp[0].v == 1502 and node < plan.selected.len and plan.selected[node]) {
            const expected = Storage.compactFixed(scalar, try scalar.logicalRow(1502, node, 3, M.zero()));
            if (!std.meta.eql(pp, expected) or !pending[node]) return error.InvalidNativePcsFusion;
            pending[node] = false;
            removed += 1;
        } else try kept.append(a, pp);
    }
    if (removed != plan.candidates.entries.items.len * 4) return error.InvalidNativePcsFusion;
    const owned_opening = try retained.toOwnedSlice(a);
    errdefer a.free(owned_opening);
    const owned_native = try fused.toOwnedSlice(a);
    errdefer a.free(owned_native);
    const owned_scalars = try kept.toOwnedSlice(a);
    return .{ .allocator = a, .lease = lease, .opening = owned_opening, .native = owned_native, .scalars = owned_scalars };
}
fn materializeGraph(a: std.mem.Allocator, g: @import("composition_circuit.zig").CircuitGraph, bindings: []const @import("pcs_deep_circuit.zig").InputBinding, values: []const Q, originals: []const old.Row, scalars: anytype) !Rows {
    var sink = RowSink{ .a = a };
    defer sink.deinit();
    var plan = try MatchPlan.init(a, g, bindings);
    defer plan.deinit();
    try emitPlan(a, &plan, values, originals, scalars, &sink);
    return sink.take();
}
fn materializeGraphColumns(a: std.mem.Allocator, g: @import("composition_circuit.zig").CircuitGraph, bindings: []const @import("pcs_deep_circuit.zig").InputBinding, values: []const Q, originals: []const old.Row, scalars: anytype) !Columns {
    var plan = try MatchPlan.init(a, g, bindings);
    defer plan.deinit();
    var count = CountSink{};
    try emitPlan(a, &plan, values, originals, scalars, &count);
    var columns = try Columns.init(a, count.counts);
    errdefer columns.deinit();
    var sink = ColumnSink{ .columns = &columns };
    try emitPlan(a, &plan, values, originals, scalars, &sink);
    try columns.opening.requireFinished();
    try columns.native.requireFinished();
    try columns.scalars.requireFinished();
    return columns;
}
/// Graph matching is immutable and runs once for the count and scatter passes.
/// Only small per-pass consumption masks are reset; no second graph-wide scan
/// or rebuild of candidate payloads is needed.
const MatchPlan = struct {
    a: std.mem.Allocator,
    graph: @import("composition_circuit.zig").CircuitGraph,
    uses: []u32,
    selected: []bool,
    candidates: CandidateIndex,
    fn init(a: std.mem.Allocator, g: @import("composition_circuit.zig").CircuitGraph, bindings: []const @import("pcs_deep_circuit.zig").InputBinding) !@This() {
        const uses = try a.alloc(u32, g.nodes.len);
        errdefer a.free(uses);
        _ = try lower.computeLaneUseCountsInto(.{ .circuit_id = 1502, .active_in = .segment, .circuit_identity = g.identity_digest, .graph = g }, uses);
        const indices = try a.alloc(u32, g.nodes.len);
        defer a.free(indices);
        @memset(indices, 0);
        for (bindings, 0..) |binding, i| indices[binding.node_id] = @intCast(i + 1);
        const reserved = try a.alloc(bool, g.nodes.len);
        defer a.free(reserved);
        @memset(reserved, false);
        var matches: std.ArrayList(opening.Match) = .empty;
        defer matches.deinit(a);
        try opening.reserve(&matches, a, g, uses, reserved);
        var candidates = CandidateIndex{};
        errdefer candidates.deinit(a);
        const selected = try a.alloc(bool, g.nodes.len);
        errdefer a.free(selected);
        @memset(selected, false);
        for (matches.items) |item| if (matcher.match(g, uses, indices, bindings, item)) |candidate| {
            try candidates.entries.append(a, candidate);
            for (candidate.query_nodes) |node| {
                if (selected[node]) return error.InvalidNativePcsFusion;
                selected[node] = true;
            }
        };
        try candidates.finish();
        return .{ .a = a, .graph = g, .uses = uses, .selected = selected, .candidates = candidates };
    }
    fn deinit(self: *@This()) void {
        self.a.free(self.uses);
        self.a.free(self.selected);
        self.candidates.deinit(self.a);
        self.* = undefined;
    }
};
// One validation kernel for legacy rows, count admission and final columns.
fn emitPlan(a: std.mem.Allocator, plan: *const MatchPlan, values: []const Q, originals: []const old.Row, scalars: anytype, sink: anytype) !void {
    const g = plan.graph;
    const uses = plan.uses;
    const selected = plan.selected;
    const candidates = &plan.candidates;
    const candidate_count = candidates.entries.items.len;
    const pending = try a.dupe(bool, selected);
    defer a.free(pending);
    const emitted = try a.alloc(bool, uses.len);
    defer a.free(emitted);
    @memset(emitted, false);
    var fused_count: usize = 0;
    for (originals) |row| {
        const pp = row[old.PHYSICAL_MAIN_COLUMN_COUNT..];
        if (pp[1].v == 1502 and pp[11].v < emitted.len and emitted[pp[11].v]) return error.InvalidNativePcsFusion;
        const candidate = if (pp[1].v == 1502) candidates.get(pp[11].v) else null;
        if (candidate) |c| {
            const item = c.opening;
            var lhs: [4]u32 = undefined;
            var rhs: [4]u32 = undefined;
            var lv: [4]Q = undefined;
            var rv: [4]Q = undefined;
            var queries: [4]M = undefined;
            var weights: [4]Q = undefined;
            for (item.multiply_nodes, 0..) |node, i| {
                const operands = g.nodes[node].op.mul;
                lhs[i] = operands.lhs;
                rhs[i] = operands.rhs;
                lv[i] = values[lhs[i]];
                rv[i] = values[rhs[i]];
                const words = values[c.query_nodes[i]].toM31Array();
                if (!words[1].isZero() or !words[2].isZero() or !words[3].isZero()) return error.InvalidNativePcsFusion;
                queries[i] = words[0];
                weights[i] = values[c.weight_nodes[i]];
            }
            const expected = try old.logicalRow(.{ .circuit = 1502, .accumulator = item.accumulator_node, .lhs = lhs, .rhs = rhs, .output = item.output_node, .uses = uses[item.output_node] }, values[item.accumulator_node], lv, rv, values[item.output_node]);
            for (row, expected) |actual, wanted| if (!actual.eql(wanted)) return error.InvalidNativePcsFusion;
            try sink.nativeRow(try native.logicalRow(.{ .circuit = 1502, .accumulator = item.accumulator_node, .queries = c.query_nodes, .weights = c.weight_nodes, .output = item.output_node, .uses = uses[item.output_node] }, values[item.accumulator_node], queries, weights, values[item.output_node]));
            fused_count += 1;
            emitted[item.output_node] = true;
        } else try sink.opening(row);
    }
    if (fused_count != candidate_count) return error.InvalidNativePcsFusion;
    var removed: usize = 0;
    const scalar_count = if (@typeInfo(@TypeOf(scalars)) == .@"struct") scalars.rowCount() else scalars.len;
    for (0..scalar_count) |index| {
        const row: scalar.Row = if (@typeInfo(@TypeOf(scalars)) == .@"struct") scalars.rowAt(index) else scalars[index];
        const node = row[2].v;
        if (row[1].v == 1502 and node < selected.len and selected[node]) {
            const expected = try scalar.logicalRow(1502, node, 3, values[node].toM31Array()[0]);
            for (row, expected) |actual, wanted| if (!actual.eql(wanted)) return error.InvalidNativePcsFusion;
            if (!pending[node]) return error.InvalidNativePcsFusion;
            pending[node] = false;
            removed += 1;
        } else try sink.scalarRow(row);
    }
    if (removed != candidate_count * 4) return error.InvalidNativePcsFusion;
}

fn requireColumnParity(comptime Air: type, a: std.mem.Allocator, rows: []const Air.Row, columns: anytype) !void {
    const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
    const storage = @import("blake3_parent_row_storage.zig");
    var projected: std.ArrayList(Column) = .empty;
    defer {
        for (projected.items) |column| a.free(column.values);
        projected.deinit(a);
    }
    try @import("blake3_row_columns.zig").project(Air, a, rows, columns.log, 1, &projected);
    try std.testing.expectEqual(projected.items.len, columns.main.len);
    for (projected.items, columns.main) |expected, actual| try std.testing.expectEqualSlices(M, expected.values, actual.values);
    try std.testing.expectEqual(rows.len, columns.fixed.len);
    for (rows, columns.fixed) |row, fixed| try std.testing.expectEqualDeep(storage.compactFixed(Air, row), fixed);
}

fn checkMatcherAllocation(a: std.mem.Allocator, g: @import("composition_circuit.zig").CircuitGraph, bindings: []const @import("pcs_deep_circuit.zig").InputBinding, values: []const Q, row: old.Row, scalars: []const scalar.Row) !void {
    var columns = try materializeGraphColumns(a, g, bindings, values, &.{row}, scalars);
    defer columns.deinit();
    try std.testing.expectEqual(@as(usize, 1), columns.native.fixed.len);
    try std.testing.expectEqual(@as(usize, 0), columns.opening.fixed.len);
    try std.testing.expectEqual(@as(usize, 0), columns.scalars.fixed.len);
}
fn checkBorrowedMatcherAllocation(a: std.mem.Allocator, g: @import("composition_circuit.zig").CircuitGraph, bindings: []const @import("pcs_deep_circuit.zig").InputBinding, values: []const Q, row: old.Row, scalars: []const scalar.Row) !void {
    var source = try Direct.ForAir(scalar).init(a, scalars.len);
    defer source.deinit();
    for (scalars) |value| try source.append(value);
    const borrowed = try @import("blake3_recursive_column_rows_v1.zig").ForAir(scalar).init(source.main, source.fixed);
    var columns = try materializeGraphColumns(a, g, bindings, values, &.{row}, borrowed);
    defer columns.deinit();
    // Both count and emission borrow one immutable original owner. Fused
    // output allocation and source consumption cannot invalidate that view.
    for (scalars, 0..) |value, i| try std.testing.expectEqualDeep(value, borrowed.rowAt(i));
    try std.testing.expectEqual(@as(usize, 1), columns.native.fixed.len);
    try std.testing.expectEqual(@as(usize, 0), columns.scalars.fixed.len);
}

test "native query sparse candidate index preserves all coordinate boundaries and duplicate rejection" {
    const a = std.testing.allocator;
    var index = CandidateIndex{};
    defer index.deinit(a);
    const base = matcher.Candidate{
        .opening = .{ .multiply_nodes = .{ 1, 2, 3, 4 }, .add_nodes = .{ 5, 6, 7, 8 }, .accumulator_node = 0, .output_node = 0 },
        .query_nodes = .{ 1, 3, 5, 7 },
        .queries = @splat(.{ .tree = 1, .column = 2, .query = 3 }),
        .weight_nodes = .{ 2, 4, 6, 8 },
    };
    for ([_]u32{ 65536, 7, std.math.maxInt(u32) - 1 }) |node| {
        var candidate = base;
        candidate.opening.output_node = node;
        try index.entries.append(a, candidate);
    }
    try index.finish();
    for ([_]u32{ 0, 6, 8, 65535, 65537, std.math.maxInt(u32) }) |node| try std.testing.expect(index.get(node) == null);
    for (index.entries.items) |expected| try std.testing.expectEqualDeep(expected, index.get(expected.opening.output_node).?);
    // Sparse coordinates never allocate storage through the largest node ID.
    try std.testing.expect(index.entries.capacity * @sizeOf(matcher.Candidate) < 4096);
    try index.entries.append(a, index.entries.items[0]);
    try std.testing.expectError(error.InvalidNativePcsFusion, index.finish());
}

test "native query fusion admission rejects altered missing and duplicate sources" {
    const a = std.testing.allocator;
    const graph = @import("composition_circuit.zig");
    const pcs = @import("pcs_deep_circuit.zig");
    var nodes: [17]graph.Node = undefined;
    var values: [17]Q = undefined;
    var bindings: [9]pcs.InputBinding = undefined;
    for (nodes[0..9], values[0..9], &bindings, 0..) |*node, *value, *b, i| {
        node.* = .{ .op = .input };
        value.* = Q.fromBase(M.fromCanonical(@intCast(i + 1)));
        b.* = .{ .node_id = @intCast(i), .source = if (i % 2 == 1) .{ .queried_value = .{ .tree = 0, .column = @intCast(i), .query = 0 } } else .active_selector };
    }
    const queries: [4]u32 = .{ 1, 3, 5, 7 };
    const weights: [4]u32 = .{ 2, 4, 6, 8 };
    var lhs: [4]Q = undefined;
    var rhs: [4]Q = undefined;
    var scalars: [4]scalar.Row = undefined;
    for (0..4) |i| {
        const mul: u32 = @intCast(9 + 2 * i);
        const acc: u32 = if (i == 0) 0 else mul - 1;
        nodes[mul] = .{ .op = .{ .mul = .{ .lhs = queries[i], .rhs = weights[i] } } };
        nodes[mul + 1] = .{ .op = .{ .add = .{ .lhs = acc, .rhs = mul } } };
        lhs[i] = values[queries[i]];
        rhs[i] = values[weights[i]];
        values[mul] = lhs[i].mul(rhs[i]);
        values[mul + 1] = values[acc].add(values[mul]);
        scalars[i] = try scalar.logicalRow(1502, queries[i], 3, lhs[i].toM31Array()[0]);
    }
    const g = try graph.CircuitGraph.authenticate(&nodes, &.{16}, graph.computeGraphDigest(&nodes, &.{16}));
    const row = try old.logicalRow(.{ .circuit = 1502, .accumulator = 0, .lhs = queries, .rhs = weights, .output = 16, .uses = 1 }, values[0], lhs, rhs, values[16]);
    try std.testing.checkAllAllocationFailures(a, checkMatcherAllocation, .{ g, @as([]const pcs.InputBinding, &bindings), @as([]const Q, &values), row, @as([]const scalar.Row, &scalars) });
    try checkBorrowedMatcherAllocation(a, g, &bindings, &values, row, &scalars);
    try std.testing.checkAllAllocationFailures(a, checkBorrowedMatcherAllocation, .{ g, @as([]const pcs.InputBinding, &bindings), @as([]const Q, &values), row, @as([]const scalar.Row, &scalars) });
    var actual = try materializeGraph(a, g, &bindings, &values, &.{row}, &scalars);
    defer actual.deinit();
    try std.testing.expectEqual(@as(usize, 1), actual.native.len);
    try std.testing.expectEqual(@as(usize, 0), actual.opening.len);
    try std.testing.expectEqual(@as(usize, 0), actual.scalars.len);
    var direct = try materializeGraphColumns(a, g, &bindings, &values, &.{row}, &scalars);
    defer direct.deinit();
    try requireColumnParity(old, a, actual.opening, &direct.opening);
    try requireColumnParity(native, a, actual.native, &direct.native);
    try requireColumnParity(scalar, a, actual.scalars, &direct.scalars);
    // A sparse query island in a larger authenticated graph keeps identical
    // proof rows and fixed metadata without a candidate payload per node.
    const large_nodes = try a.alloc(graph.Node, 65536);
    defer a.free(large_nodes);
    @memset(large_nodes, .{ .op = .{ .constant = .{ 0, 0, 0, 0 } } });
    @memcpy(large_nodes[0..nodes.len], &nodes);
    const large_values = try a.alloc(Q, large_nodes.len);
    defer a.free(large_values);
    @memset(large_values, Q.zero());
    @memcpy(large_values[0..values.len], &values);
    const large_graph = try graph.CircuitGraph.authenticate(large_nodes, &.{16}, graph.computeGraphDigest(large_nodes, &.{16}));
    var large_direct = try materializeGraphColumns(a, large_graph, &bindings, large_values, &.{row}, &scalars);
    defer large_direct.deinit();
    try requireColumnParity(old, a, actual.opening, &large_direct.opening);
    try requireColumnParity(native, a, actual.native, &large_direct.native);
    try requireColumnParity(scalar, a, actual.scalars, &large_direct.scalars);
    try std.testing.expectError(error.InvalidNativePcsFusion, materializeGraphColumns(a, g, &bindings, &values, &.{}, &scalars));
    try std.testing.expectError(error.InvalidNativePcsFusion, materializeGraphColumns(a, g, &bindings, &values, &.{ row, row }, &scalars));
    try std.testing.expectError(error.InvalidNativePcsFusion, materializeGraphColumns(a, g, &bindings, &values, &.{row}, scalars[1..]));
    var bad_scalar = scalars;
    bad_scalar[0][0] = bad_scalar[0][0].add(M.one());
    try std.testing.expectError(error.InvalidNativePcsFusion, materializeGraphColumns(a, g, &bindings, &values, &.{row}, &bad_scalar));
    for (0..scalars.len) |index| for (0..scalar.LOGICAL_INPUT_COUNT) |column| {
        var changed = scalars;
        changed[index][column] = changed[index][column].add(M.one());
        try std.testing.expectError(error.InvalidNativePcsFusion, materializeGraph(a, g, &bindings, &values, &.{row}, &changed));
    };
    for (0..old.LOGICAL_INPUT_COUNT) |column| {
        var changed = row;
        changed[column] = changed[column].add(M.one());
        try std.testing.expectError(error.InvalidNativePcsFusion, materializeGraph(a, g, &bindings, &values, &.{changed}, &scalars));
    }
    try std.testing.expectError(error.InvalidNativePcsFusion, materializeGraph(a, g, &bindings, &values, &.{}, &scalars));
    try std.testing.expectError(error.InvalidNativePcsFusion, materializeGraph(a, g, &bindings, &values, &.{ row, row }, &scalars));
    try std.testing.expectError(error.InvalidNativePcsFusion, materializeGraph(a, g, &bindings, &values, &.{row}, scalars[1..]));
    try std.testing.expectError(error.InvalidNativePcsFusion, materializeGraph(a, g, &bindings, &values, &.{row}, &(scalars ++ .{scalars[0]})));
    const extra = try scalar.logicalRow(1504, 1, 2, M.one());
    var retained = try materializeGraph(a, g, &bindings, &values, &.{row}, &(scalars ++ .{extra}));
    defer retained.deinit();
    try std.testing.expectEqual(@as(usize, 1), retained.scalars.len);
    try std.testing.expectEqualDeep(extra, retained.scalars[0]);
    // Exercise all three nonempty direct outputs, including a valid dot4 that
    // is retained because it is outside the native-query circuit.
    const retained_opening = try old.logicalRow(.{ .circuit = 1504, .accumulator = 0, .lhs = queries, .rhs = weights, .output = 16, .uses = 1 }, values[0], lhs, rhs, values[16]);
    var mixed_old = try materializeGraph(a, g, &bindings, &values, &.{ row, retained_opening }, &(scalars ++ .{extra}));
    defer mixed_old.deinit();
    var mixed_direct = try materializeGraphColumns(a, g, &bindings, &values, &.{ row, retained_opening }, &(scalars ++ .{extra}));
    defer mixed_direct.deinit();
    try requireColumnParity(old, a, mixed_old.opening, &mixed_direct.opening);
    try requireColumnParity(native, a, mixed_old.native, &mixed_direct.native);
    try requireColumnParity(scalar, a, mixed_old.scalars, &mixed_direct.scalars);
    const storage = @import("blake3_parent_row_storage.zig");
    var owned = storage.Prepared{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = 0 };
    inline for (0..storage.Airs.len) |i| owned.fixed[i] = &.{};
    defer owned.deinit();
    inline for (.{ 12, 18, 19 }, .{ &mixed_direct.scalars, &mixed_direct.opening, &mixed_direct.native }) |slot, cohort| {
        const taken = try cohort.take();
        owned.main[slot] = taken.main;
        owned.fixed[slot] = taken.fixed;
    }
    owned.releaseCohort(19);
    owned.releaseRows();
    try std.testing.expectEqual(@as(usize, 0), try owned.retainedBytes());
}

fn checkFixedMatcherAllocation(a: std.mem.Allocator, g: @import("composition_circuit.zig").CircuitGraph, bindings: []const @import("pcs_deep_circuit.zig").InputBinding, pp: @import("blake3_parent_row_storage.zig").FixedRow(old), scalar_pp: []const @import("blake3_parent_row_storage.zig").FixedRow(scalar)) !void {
    var result = try materializeFixedGraph(a, g, bindings, &.{pp}, scalar_pp);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 1), result.native.len);
}
test "recursive fixed roster: original native PCS matcher parity mutation and allocation rollback" {
    // Original arithmetic-only graph oracle; NOT proof or successful admission.
    const a = std.testing.allocator;
    const graph = @import("composition_circuit.zig");
    const pcs = @import("pcs_deep_circuit.zig");
    var nodes: [17]graph.Node = undefined;
    var values: [17]Q = undefined;
    var bindings: [9]pcs.InputBinding = undefined;
    for (nodes[0..9], values[0..9], &bindings, 0..) |*node, *value, *b, i| {
        node.* = .{ .op = .input };
        value.* = Q.fromBase(M.fromCanonical(@intCast(i + 1)));
        b.* = .{ .node_id = @intCast(i), .source = if (i % 2 == 1) .{ .queried_value = .{ .tree = 0, .column = @intCast(i), .query = 0 } } else .active_selector };
    }
    const queries: [4]u32 = .{ 1, 3, 5, 7 };
    const weights: [4]u32 = .{ 2, 4, 6, 8 };
    var lhs: [4]Q = undefined;
    var rhs: [4]Q = undefined;
    var scalars: [4]scalar.Row = undefined;
    for (0..4) |i| {
        const mul: u32 = @intCast(9 + 2 * i);
        const acc: u32 = if (i == 0) 0 else mul - 1;
        nodes[mul] = .{ .op = .{ .mul = .{ .lhs = queries[i], .rhs = weights[i] } } };
        nodes[mul + 1] = .{ .op = .{ .add = .{ .lhs = acc, .rhs = mul } } };
        lhs[i] = values[queries[i]];
        rhs[i] = values[weights[i]];
        values[mul] = lhs[i].mul(rhs[i]);
        values[mul + 1] = values[acc].add(values[mul]);
        scalars[i] = try scalar.logicalRow(1502, queries[i], 3, lhs[i].toM31Array()[0]);
    }
    const g = try graph.CircuitGraph.authenticate(&nodes, &.{16}, graph.computeGraphDigest(&nodes, &.{16}));
    const row = try old.logicalRow(.{ .circuit = 1502, .accumulator = 0, .lhs = queries, .rhs = weights, .output = 16, .uses = 1 }, values[0], lhs, rhs, values[16]);

    const Storage = @import("blake3_parent_row_storage.zig");
    const pp = Storage.compactFixed(old, row);
    var scalar_pp: [4]Storage.FixedRow(scalar) = undefined;
    for (scalars, &scalar_pp) |source, *out| out.* = Storage.compactFixed(scalar, source);
    var actual = try materializeGraph(a, g, &bindings, &values, &.{row}, &scalars);
    defer actual.deinit();
    var fixed = try materializeFixedGraph(a, g, &bindings, &.{pp}, &scalar_pp);
    defer fixed.deinit();
    try std.testing.expectEqual(actual.opening.len, fixed.opening.len);
    try std.testing.expectEqual(actual.native.len, fixed.native.len);
    try std.testing.expectEqual(actual.scalars.len, fixed.scalars.len);
    for (actual.native, fixed.native) |source, tail| try std.testing.expectEqualDeep(Storage.compactFixed(native, source), tail);
    try std.testing.checkAllAllocationFailures(a, checkFixedMatcherAllocation, .{ g, &bindings, pp, &scalar_pp });
    for (0..pp.len) |coordinate| {
        var changed = pp;
        changed[coordinate] = changed[coordinate].add(M.one());
        try std.testing.expectError(error.InvalidNativePcsFusion, materializeFixedGraph(a, g, &bindings, &.{changed}, &scalar_pp));
    }
    var changed = scalar_pp;
    changed[0][2] = changed[0][2].add(M.one());
    try std.testing.expectError(error.InvalidNativePcsFusion, materializeFixedGraph(a, g, &bindings, &.{pp}, &changed));
}
