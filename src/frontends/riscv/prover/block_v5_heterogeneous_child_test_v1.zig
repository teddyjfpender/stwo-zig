//! Bounded pure metadata/byte-source/equation checks. Never invokes a prover,
//! creates a fake capture, or promotes a source descriptor to closure.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const C = @import("block_v5_recursive_coverage_plan_v1.zig");
const F = @import("../recursion/block_v5_heterogeneous_child_frames_v1.zig");
const D = @import("../recursion/block_v5_heterogeneous_leaf_definition_v1.zig");
const B = @import("../recursion/block_v5_heterogeneous_public_bus_v1.zig");
const P = @import("../recursion/air/block_v5_heterogeneous_pairing_v1.zig");
const R = @import("../recursion/block_v5_heterogeneous_parent_receiver_v1.zig");
const GraphRows = @import("../recursion/air/block_v5_heterogeneous_graph_rows_v1.zig");
fn bytes(word: u32) [4]M {
    return .{ M.fromCanonical(word & 255), M.fromCanonical((word >> 8) & 255), M.fromCanonical((word >> 16) & 255), M.fromCanonical(word >> 24) };
}
fn roots() [8][4]M {
    var result: [8][4]M = undefined;
    for (&result, 0..) |*cell, i| cell.* = bytes(0xdead0000 + @as(u32, @intCast(i)));
    return result;
}
test "heterogeneous recursion: all eight genuine typed families preserve explicit subtype and missing legacy fusion" {
    const subtypes = [_]C.Subtype{ .native_v3, .capacity_v1, .capacity_fused_v1, .caller_family11_v1, .caller_fused_v1, .ram_lanes_v1, .range16_v1, .rom_v1, .six_table_lookup_v1 };
    const expected = [_]C.Kind{ .native_arithmetic, .native_arithmetic, .native_fused, .caller_arithmetic, .caller_fused, .ram_lanes, .range16, .rom, .native_lookup };
    inline for (subtypes, expected) |subtype, kind| {
        try std.testing.expectEqual(kind, D.kind(subtype));
        const Definition = D.ForSubtype(subtype);
        try std.testing.expect(@hasDecl(Definition, "Receiver") and @hasDecl(Definition, "Prepared") and @hasDecl(Definition, "Protocol"));
    }
    try std.testing.expectEqual(C.Kind.native_fused, D.kindRuntime(.native_fused_v2));
    try std.testing.expect(R.OpenEquation.aggregate_joins_pending);
    try std.testing.expectEqual(@as(usize, 10), R.OpenEquation.source_authorities_pending);
}
test "heterogeneous recursion: original root word frames and integer widths remain exact and cell mutation rejects" {
    const words = [_]u32{ 0x01020304, 0x89abcdef, 0xffffffff, 0, 0xaabbccdd, 0x80000000, 0x12345678, 0xfedcba98 };
    const frames = [_]F.Frame{ .{ .first = 0, .operation = .{ .words = &words } }, .{ .first = 8, .operation = .{ .integer = 0xfedcba9876543210 } } };
    var cells: [10][4]M = undefined;
    for (words, cells[0..8]) |word, *cell| cell.* = bytes(word);
    cells[8] = bytes(0x76543210);
    cells[9] = bytes(0xfedcba98);
    try F.testing.validateFrameCells(&frames, &cells);
    var digest: [32]u8 = undefined;
    for (words, 0..) |word, i| std.mem.writeInt(u32, digest[4 * i ..][0..4], word, .little);
    try std.testing.expectEqual(@as(u32, 0), try F.testing.rootOffset(&frames, digest));
    cells[9][3] = M.zero();
    try std.testing.expectError(error.MutatedHeterogeneousChild, F.testing.validateFrameCells(&frames, &cells));
    digest[1] ^= 1;
    try std.testing.expectError(error.MissingHeterogeneousAuthenticatedRoot, F.testing.rootOffset(&frames, digest));
}
fn graph(a: std.mem.Allocator) !void {
    const cells = roots();
    // Slice views for the pure graph, not validated Child/proof receipts.
    var children: [2]F.Child = undefined;
    for (&children) |*child| child.cells = &cells;
    var prepared = try P.testing.record(a, &children, &.{.{ .left = 0, .right = 1, .left_cell = 0, .right_cell = 0 }});
    defer prepared.deinit();
    try prepared.circuit.evaluateInto(prepared.inputs, prepared.values);
}
test "heterogeneous recursion: actual root pairing scalar graph rejects mismatched coordinate and preserves source ordinal" {
    const cells = roots();
    var children: [2]F.Child = undefined;
    for (&children) |*child| child.cells = &cells;
    var prepared = try P.testing.record(std.testing.allocator, &children, &.{.{ .left = 0, .right = 1, .left_cell = 0, .right_cell = 0 }});
    defer prepared.deinit();
    try std.testing.expectEqual(@as(usize, 64), prepared.inputs.len);
    try std.testing.expectEqual(@as(u32, 1), prepared.sources[1].child);
    prepared.inputs[1] = prepared.inputs[1].add(Q.one());
    try std.testing.expectError(error.UnsatisfiedCircuit, prepared.circuit.evaluateInto(prepared.inputs, prepared.values));
    prepared.inputs[1] = prepared.inputs[1].sub(Q.one());
    try prepared.circuit.evaluateInto(prepared.inputs, prepared.values);
}
test "heterogeneous recursion: root pairing allocation failures and malformed source extent are clean" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, graph, .{});
    const cells = roots();
    var children: [2]F.Child = undefined;
    children[0].cells = cells[0..7];
    children[1].cells = &cells;
    try std.testing.expectError(error.InvalidHeterogeneousPairing, P.testing.record(std.testing.allocator, &children, &.{.{ .left = 0, .right = 1, .left_cell = 0, .right_cell = 0 }}));
    var malformed = cells;
    malformed[0][0].v = core.fields.m31.Modulus;
    children[0].cells = &malformed;
    try std.testing.expectError(error.NoncanonicalHeterogeneousChild, P.testing.record(std.testing.allocator, &children, &.{.{ .left = 0, .right = 1, .left_cell = 0, .right_cell = 0 }}));
}
test "heterogeneous recursion: provider has no virtual PC span and public schedule rejects duplicate or relabeled coordinates" {
    var children: [1]F.Child = undefined;
    const child = &children[0];
    child.span = null;
    child.cells = &.{};
    child.terms = &.{};
    const values = B.Values{ .policy = .{ .plan = undefined, .children = &children, .expected = &.{} } };
    try std.testing.expectError(error.HeterogeneousProviderHasNativeSpan, values.at(.{ .circuit = 1, .wire = 1, .uses = 1, .child = 0, .kind = .native_span, .coordinate = 0 }));
    const wire = B.Wire{ .circuit = 1, .wire = 1, .uses = 1, .child = 0, .kind = .frame_cell, .coordinate = 0 };
    _ = try B.scheduleDigest(&.{wire});
    try std.testing.expectError(error.InvalidHeterogeneousSchedule, B.scheduleDigest(&.{ wire, wire }));
    var changed = wire;
    changed.part = 1;
    try std.testing.expectError(error.InvalidHeterogeneousSchedule, B.scheduleDigest(&.{changed}));
    changed = wire;
    changed.child = B.MAX_CHILDREN;
    try std.testing.expectError(error.InvalidHeterogeneousSchedule, B.scheduleDigest(&.{changed}));
}
test "heterogeneous recursion: exact once bookkeeping fails incomplete census without asserting proof authority" {
    const used = try std.testing.allocator.alloc(bool, 3);
    @memset(used, false);
    var census = @import("../recursion/block_v5_heterogeneous_policy_v1.zig").Census{ .a = std.testing.allocator, .used = used };
    defer census.deinit();
    try std.testing.expectError(error.IncompleteHeterogeneousCoverage, census.requireComplete());
    @memset(used, true);
    try census.requireComplete();
    used[1] = false;
    try std.testing.expectError(error.IncompleteHeterogeneousCoverage, census.requireComplete());
}
fn checkGraphRows(a: std.mem.Allocator, lowered: *const GraphRows.Lowered, children: []const F.Child) !void {
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
        const value = children[wire.child].cells[wire.coordinate][wire.part];
        const bucket = try tuples.getOrPut(.{ wire.circuit, wire.wire, value.v, 0, 0, 0 });
        if (!bucket.found_existing) bucket.value_ptr.* = M.zero();
        bucket.value_ptr.* = bucket.value_ptr.add(M.fromCanonical(wire.uses));
    }
    var iterator = tuples.valueIterator();
    while (iterator.next()) |weight| if (!weight.isZero()) return error.UnclosedHeterogeneousGraphWire;
}
fn graphRowsAllocation(a: std.mem.Allocator) !void {
    const cells = roots();
    var children: [2]F.Child = undefined;
    for (&children) |*child| child.cells = &cells;
    var prepared = try P.testing.record(a, &children, &.{.{ .left = 0, .right = 1, .left_cell = 0, .right_cell = 0 }});
    defer prepared.deinit();
    var lowered = try GraphRows.testing.lowerGraph(a, .{ .circuit = &prepared.circuit, .inputs = prepared.inputs, .values = prepared.values, .sources = prepared.sources }, &children);
    defer lowered.deinit();
    try checkGraphRows(a, &lowered, &children);
}
test "heterogeneous recursion: original pairing equations lower to genuine parent rows and exact public tuple closure" {
    const a = std.testing.allocator;
    const cells = roots();
    var children: [2]F.Child = undefined;
    for (&children) |*child| child.cells = &cells;
    var prepared = try P.testing.record(a, &children, &.{.{ .left = 0, .right = 1, .left_cell = 0, .right_cell = 0 }});
    defer prepared.deinit();
    var lowered = try GraphRows.testing.lowerGraph(a, .{ .circuit = &prepared.circuit, .inputs = prepared.inputs, .values = prepared.values, .sources = prepared.sources }, &children);
    defer lowered.deinit();
    try std.testing.expectEqual(@as(usize, 64), lowered.wires.len);
    try std.testing.expectEqual(@as(usize, 32), lowered.rows.fixed[5].len);
    try checkGraphRows(a, &lowered, &children);
    lowered.wires[0].uses += 1;
    try std.testing.expectError(error.UnclosedHeterogeneousGraphWire, checkGraphRows(a, &lowered, &children));
    lowered.wires[0].uses -= 1;
    const column = lowered.rows.main[5][16]; // Actual linear output coefficient.
    const at = @import("../recursion/air/framework_interaction.zig").committedRow(0, column.log_size);
    @constCast(column.values)[at] = column.values[at].add(M.one());
    try std.testing.expectError(error.NonzeroHeterogeneousRowEquation, checkGraphRows(a, &lowered, &children));
}
test "heterogeneous recursion: graph lowering validates source identity evaluation ownership and allocation failures" {
    const a = std.testing.allocator;
    try std.testing.checkAllAllocationFailures(a, graphRowsAllocation, .{});
    const cells = roots();
    var children: [2]F.Child = undefined;
    for (&children) |*child| child.cells = &cells;
    var prepared = try P.testing.record(a, &children, &.{.{ .left = 0, .right = 1, .left_cell = 0, .right_cell = 0 }});
    defer prepared.deinit();
    const graph_input = GraphRows.Graph{ .circuit = &prepared.circuit, .inputs = prepared.inputs, .values = prepared.values, .sources = prepared.sources };
    prepared.sources[0].cell = 99;
    try std.testing.expectError(error.InvalidHeterogeneousGraphSource, GraphRows.testing.lowerGraph(a, graph_input, &children));
    prepared.sources[0].cell = 0;
    prepared.inputs[0] = prepared.inputs[0].add(Q.one());
    try std.testing.expectError(error.UntrustedHeterogeneousGraphInput, GraphRows.testing.lowerGraph(a, graph_input, &children));
    prepared.inputs[0] = prepared.inputs[0].sub(Q.one());
    prepared.values[0] = prepared.values[0].add(Q.one());
    try std.testing.expectError(error.MutatedHeterogeneousGraphEvaluation, GraphRows.testing.lowerGraph(a, graph_input, &children));
}
