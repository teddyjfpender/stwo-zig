//! Pure topology, original scalar equations, real row arithmetic and tuple
//! custody. No fake verifier capture, guest, commitments or prover calls.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Coverage = @import("block_v5_recursive_coverage_plan_v1.zig");
const Topology = @import("../recursion/block_v5_heterogeneous_hierarchy_plan_v1.zig");
const Frames = @import("../recursion/block_v5_heterogeneous_hierarchy_frames_v1.zig");
const Bus = @import("../recursion/block_v5_heterogeneous_hierarchy_public_bus_v1.zig");
const Export = @import("../recursion/air/block_v5_heterogeneous_hierarchy_exports_v1.zig");
const Graph = @import("../recursion/air/block_v5_heterogeneous_hierarchy_graph_rows_v1.zig");
fn topology(a: std.mem.Allocator, count: usize, fan: Coverage.FanIn, mutations: bool) !void {
    const physical = try a.alloc(Coverage.Physical, count);
    defer a.free(physical);
    for (physical, 0..) |*leaf, index| {
        leaf.* = .{ .kind = if (index < 67) .native_arithmetic else .range16, .subtype = if (index < 67) .capacity_v1 else .range16_v1, .index = @intCast(index), .logical = .{ @intCast(index), 0 }, .logical_count = 1, .instance_id = @splat(1), .roots = @splat(@splat(1)) };
    }
    var current: std.ArrayList(Coverage.Ref) = .empty;
    defer current.deinit(a);
    for (0..count) |i| try current.append(a, .{ .leaf = @intCast(i) });
    var nodes: std.ArrayList(Coverage.Node) = .empty;
    defer nodes.deinit(a);
    while (current.items.len > 1) {
        var next: std.ArrayList(Coverage.Ref) = .empty;
        errdefer next.deinit(a);
        var at: usize = 0;
        while (at < current.items.len) {
            const take = @min(@as(usize, @intFromEnum(fan)), current.items.len - at);
            if (take == 1) {
                try next.append(a, current.items[at]);
            } else {
                var node = Coverage.Node{ .children = undefined, .child_count = @intCast(take), .first_leaf = 0, .leaf_count = 0, .schema_counts = @splat(0) };
                for (current.items[at..][0..take], 0..) |ref, slot| {
                    node.children[slot] = ref;
                    const bounds = switch (ref) {
                        .leaf => |ordinal| block: {
                            var schema: [Coverage.KIND_COUNT]u32 = @splat(0);
                            schema[@intFromEnum(physical[ordinal].kind)] = 1;
                            break :block Topology.Bounds{ .first = ordinal, .count = 1, .schema = schema };
                        },
                        .node => |ordinal| Topology.Bounds{ .first = nodes.items[ordinal].first_leaf, .count = nodes.items[ordinal].leaf_count, .schema = nodes.items[ordinal].schema_counts },
                    };
                    if (slot == 0) node.first_leaf = bounds.first;
                    node.leaf_count += bounds.count;
                    for (&node.schema_counts, bounds.schema) |*sum, n| sum.* += n;
                }
                try nodes.append(a, node);
                try next.append(a, .{ .node = @intCast(nodes.items.len - 1) });
            }
            at += take;
        }
        current.deinit(a);
        current = next;
    }
    try Topology.checkTopology(a, physical, nodes.items, current.items[0], fan, .{});
    if (count > 1 and mutations) {
        const root = current.items[0].node;
        try std.testing.expectEqual(@as(u32, @intCast(count)), nodes.items[root].leaf_count);
        try std.testing.expectEqual(@as(u32, 67), nodes.items[root].schema_counts[@intFromEnum(Coverage.Kind.native_arithmetic)]);
        const original = nodes.items[root].children[0];
        nodes.items[root].children[0] = .{ .node = root };
        try std.testing.expectError(error.InvalidHeterogeneousHierarchyTopology, Topology.checkTopology(a, physical, nodes.items, current.items[0], fan, .{}));
        nodes.items[root].children[0] = original;
        try std.testing.expectError(error.HeterogeneousHierarchyResourceLimit, Topology.checkTopology(a, physical, nodes.items, current.items[0], fan, .{ .max_leaves = count - 1 }));
    }
}
test "heterogeneous hierarchy: genuine exact topology has 67 native spans plus providers without rounded leaves" {
    try topology(std.testing.allocator, 75, .pair, true);
    try topology(std.testing.allocator, 75, .quartet, true);
    try topology(std.testing.allocator, 1, .quartet, true);
}
test "heterogeneous hierarchy: topology allocation failures preserve exact leaf and node ownership" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, topologyAllocation, .{});
}
fn makeGraph(a: std.mem.Allocator) !Export.Prepared {
    var inputs: [136]Q = undefined;
    var sources: [136]Bus.Wire = undefined;
    var equalities: [32]Export.testing.Equality = undefined;
    for (0..32) |i| {
        inputs[2 * i] = Q.fromBase(M.fromCanonical(@intCast(i + 1)));
        inputs[2 * i + 1] = inputs[2 * i];
        equalities[i] = .{ .left = 2 * i, .right = 2 * i + 1 };
    }
    const words = [_][6]u32{ .{ 0, 40, 1, 40, 10, 50 }, .{ 40, 27, 41, 67, 50, 77 }, .{ 0, 67, 1, 67, 10, 77 } };
    var indices: [3][6][4]usize = undefined;
    for (words, &indices, 0..) |span, *word_indices, s| for (span, word_indices, 0..) |word, *parts, w| for (parts, 0..) |*index, part| {
        index.* = 64 + s * 24 + w * 4 + part;
        inputs[index.*] = Q.fromBase(M.fromCanonical((word >> @as(u5, @intCast(8 * part))) & 255));
    };
    // Pure source-coordinate views; they are never normalized Source/Fresh.
    for (&sources, 0..) |*source, i| source.* = .{ .circuit = 0, .wire = 0, .uses = 1, .kind = .child_cell, .child = 0, .coordinate = @intCast(i), .part = 0 };
    return Export.testing.record(a, &inputs, &sources, &equalities, indices[0..2], indices[2]);
}
test "heterogeneous hierarchy: forwarding graph constrains each lower byte and exact span adjacency and aggregate" {
    var graph = try makeGraph(std.testing.allocator);
    defer graph.deinit();
    const mutations = [_]usize{ 1, 64 + 24, 64 + 24 + 8, 64 + 24 + 16, 64 + 48 + 4, 64 + 48 + 20 };
    for (mutations) |index| {
        graph.inputs[index] = graph.inputs[index].add(Q.one());
        try std.testing.expectError(error.UnsatisfiedCircuit, graph.circuit.evaluateInto(graph.inputs, graph.values));
        graph.inputs[index] = graph.inputs[index].sub(Q.one());
        try graph.circuit.evaluateInto(graph.inputs, graph.values);
    }
}
test "heterogeneous hierarchy: graph allocation failures and noncanonical or out-of-bounds source reject" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, graphAllocation, .{});
    var malformed = Q.one();
    malformed.c0.a.v = core.fields.m31.Modulus;
    const source = Bus.Wire{ .circuit = 1, .wire = 1, .uses = 1, .kind = .child_cell, .coordinate = 0 };
    try std.testing.expectError(error.UntrustedHeterogeneousGraphInput, Export.testing.record(std.testing.allocator, &.{malformed}, &.{source}, &.{}, &.{}, null));
    try std.testing.expectError(error.InvalidHeterogeneousGraphShape, Export.testing.record(std.testing.allocator, &.{Q.one()}, &.{source}, &.{.{ .left = 0, .right = 1 }}, &.{}, null));
}
fn graphAllocation(a: std.mem.Allocator) !void {
    var graph = try makeGraph(a);
    defer graph.deinit();
}
test "heterogeneous hierarchy: provider span absence and node export schedules remain distinct and exact" {
    var provider: [1]Frames.Source = undefined;
    provider[0].span = null;
    const values = Bus.Values{ .plan = undefined, .index = 0, .children = &provider, .pins = &.{} };
    try std.testing.expectError(error.InvalidHeterogeneousHierarchySpan, values.at(.{ .circuit = 1, .wire = 1, .uses = 1, .kind = .child_span, .coordinate = 0 }));
    const wire = Bus.Wire{ .circuit = 1, .wire = 1, .uses = 2, .kind = .child_cell, .coordinate = 3, .part = 0 };
    const original = try Bus.scheduleDigest(&.{wire});
    var changed = wire;
    changed.kind = .export_cell;
    try std.testing.expect(!std.meta.eql(original, try Bus.scheduleDigest(&.{changed})));
    try std.testing.expectError(error.InvalidHeterogeneousHierarchySchedule, Bus.scheduleDigest(&.{ wire, wire }));
}
fn checkGraphRows(a: std.mem.Allocator, lowered: *const Graph.Lowered, values: Bus.Values) !void {
    const Storage = @import("../recursion/air/blake3_parent_row_storage.zig");
    const Direct = @import("../recursion/air/direct_constraint_program.zig");
    const Relations = @import("../recursion/air/relation_interaction.zig");
    var tuples = std.AutoHashMap([6]u32, M).init(a);
    defer tuples.deinit();
    inline for (.{ 2, 3, 4, 5, 18 }) |cohort| {
        const Air = Storage.Airs[cohort];
        var definition = if (@hasDecl(Air, "Location")) try Air.build(a, .generated) else try Air.build(a);
        defer definition.deinit();
        const direct = try Direct.authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
        const Runtime = Relations.Runtime(Air.LOGICAL_INPUT_COUNT, Air.RELATION_EVENT_COUNT, Air.LOOKUP_BATCH_SIZE);
        const event_ids = if (@typeInfo(@TypeOf(definition.events)) == .@"struct") definition.events.ordered() else definition.events;
        const relations = try Runtime.authenticate(&definition.arena, Air.SEMANTIC_DIGEST, event_ids);
        const columns = try @import("../recursion/air/blake3_recursive_column_rows_v1.zig").ForAir(Air).init(lowered.rows.main[cohort], lowered.rows.fixed[cohort]);
        for (0..columns.rowCount()) |index| {
            const row = columns.rowAt(index);
            var scratch: [Direct.MAX_NODES]M = undefined;
            var roots_direct: [Direct.MAX_CONSTRAINTS]M = undefined;
            try direct.evaluateBaseInto(&row, &scratch, roots_direct[0..direct.constraint_count]);
            for (roots_direct[0..direct.constraint_count]) |value| if (!value.isZero()) return error.NonzeroHeterogeneousRowEquation;
            for (relations.preparedEntries(row)) |entry| {
                if (entry.domain != .recursion_wire or entry.arity != 6) return error.UnexpectedHeterogeneousRowRelation;
                var key: [6]u32 = undefined;
                for (&key, entry.values[0..6]) |*coordinate, value| coordinate.* = value.toM31Array()[0].v;
                const bucket = try tuples.getOrPut(key);
                if (!bucket.found_existing) bucket.value_ptr.* = M.zero();
                bucket.value_ptr.* = bucket.value_ptr.add(entry.numerator.toM31Array()[0]);
            }
        }
    }
    for (lowered.wires) |wire| {
        const coordinates = try values.at(wire);
        const bucket = try tuples.getOrPut(.{ wire.circuit, wire.wire, coordinates[0].v, coordinates[1].v, coordinates[2].v, coordinates[3].v });
        if (!bucket.found_existing) bucket.value_ptr.* = M.zero();
        bucket.value_ptr.* = bucket.value_ptr.add(M.fromCanonical(wire.uses));
    }
    var iterator = tuples.valueIterator();
    while (iterator.next()) |weight| if (!weight.isZero()) return error.UnclosedHeterogeneousGraphWire;
}
fn rowAllocation(a: std.mem.Allocator) !void {
    var graph = try makeGraph(a);
    defer graph.deinit();
    const cells = try a.alloc([4]M, graph.inputs.len);
    defer a.free(cells);
    for (cells, graph.inputs) |*cell, input| cell.* = input.toM31Array();
    var views: [1]Frames.Source = undefined;
    views[0].cells = cells;
    const values = Bus.Values{ .plan = undefined, .index = 0, .children = &views, .pins = &.{} };
    var lowered = try Graph.testing.lowerGraph(a, graph.graph(), values);
    defer lowered.deinit();
    try checkGraphRows(a, &lowered, values);
}
test "heterogeneous hierarchy: forwarded coordinates lower to actual parent equations and exact original public tuple closure" {
    const a = std.testing.allocator;
    var graph = try makeGraph(a);
    defer graph.deinit();
    const cells = try a.alloc([4]M, graph.inputs.len);
    defer a.free(cells);
    for (cells, graph.inputs) |*cell, input| cell.* = input.toM31Array();
    var views: [1]Frames.Source = undefined;
    views[0].cells = cells;
    const values = Bus.Values{ .plan = undefined, .index = 0, .children = &views, .pins = &.{} };
    var lowered = try Graph.testing.lowerGraph(a, graph.graph(), values);
    defer lowered.deinit();
    try checkGraphRows(a, &lowered, values);
    lowered.wires[0].uses += 1;
    try std.testing.expectError(error.UnclosedHeterogeneousGraphWire, checkGraphRows(a, &lowered, values));
    lowered.wires[0].uses -= 1;
    const column = lowered.rows.main[5][16];
    const at = @import("../recursion/air/framework_interaction.zig").committedRow(0, column.log_size);
    @constCast(column.values)[at] = column.values[at].add(M.one());
    try std.testing.expectError(error.NonzeroHeterogeneousRowEquation, checkGraphRows(a, &lowered, values));
}
test "heterogeneous hierarchy: genuine row lowering releases every allocation on failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, rowAllocation, .{});
}

fn topologyAllocation(a: std.mem.Allocator) !void {
    try topology(a, 75, .quartet, false);
}
