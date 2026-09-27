//! Pure original row/compiler oracles. No capture, verifier success or key is
//! manufactured. Fixtures never commit/prove/open a device/run a segment.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Storage = @import("../recursion/air/blake3_parent_row_storage.zig");
const Direct = @import("../recursion/air/blake3_direct_cohort_columns_v1.zig");
const OriginalNamespace = @import("../recursion/air/blake3_parent_rebase.zig");
const Namespace = @import("../recursion/air/block_v5_recursive_fixed_namespace_v1.zig");
const Graph = @import("../recursion/air/block_v5_recursive_fixed_graph_attach_v1.zig");
const OriginalGraph = @import("../recursion/air/block_v5_heterogeneous_scoped_graph_rows_v1.zig");
const Attach = @import("../recursion/block_v5_recursive_fixed_attachments_v1.zig");
const Bus = @import("../recursion/block_v5_heterogeneous_scoped_public_bus_v1.zig");
const Boundary = @import("../recursion/air/blake3_boundary.zig");
const Supply = @import("../recursion/air/block_v5_closed_public_supply_v1.zig");
const R = @import("../recursion/air/composition_graph_recorder.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Fusion = @import("../recursion/air/arithmetic_fusion_rows.zig");
const Arithmetic = @import("../recursion/block_v5_recursive_parent_fixed_assembly_v1.zig").Arithmetic;
const C = @import("../recursion/air/composition_circuit.zig");
fn empty(a: std.mem.Allocator) !Storage.Prepared {
    var out = Storage.Prepared{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = 0 };
    inline for (0..Storage.Airs.len) |i| out.fixed[i] = &.{};
    errdefer out.deinit();
    inline for (Storage.Airs, 0..) |Air, i| {
        var emitter = try Direct.ForAir(Air).init(a, 0);
        defer emitter.deinit();
        const columns = try emitter.take();
        out.main[i] = columns.main;
        out.fixed[i] = columns.fixed;
    }
    return out;
}
fn put(comptime slot: usize, rows: *Storage.Prepared, logical: Storage.Airs[slot].Row) !void {
    var emitter = try Direct.ForAir(Storage.Airs[slot]).init(rows.allocator, 1);
    defer emitter.deinit();
    try emitter.append(logical);
    const columns = try emitter.take();
    rows.releaseCohort(slot);
    rows.main[slot] = columns.main;
    rows.fixed[slot] = columns.fixed;
}
const Values = struct {
    coordinates: [4]M = .{ M.fromCanonical(9), M.fromCanonical(3), M.zero(), M.one() },
    pub fn validate(_: @This()) !void {}
    pub fn at(self: @This(), wire: Bus.Wire) ![4]M {
        if (wire.child >= 4 or wire.coordinate != 0 or wire.kind != .child_cell) return error.InvalidTestCoordinates;
        return self.coordinates;
    }
};
test "recursive fixed attachment: original rebase exact identity and inactive MAIN fail closed" {
    const a = std.testing.allocator;
    var rows = try empty(a);
    defer rows.deinit();
    try put(2, &rows, try Boundary.logicalRow(17, 3, M.one(), 9));
    // Structural inactive row only, not cryptographic admission. Original AIR
    // gates circuit equality by in_circuit=0; a private ID cannot be inferred.
    var inactive: Storage.Airs[4].Row = @splat(M.zero());
    inactive[inactive.len - 3] = M.one();
    try put(4, &rows, inactive);
    var plan = try Namespace.prepare(a, rows.fixed, 1);
    defer plan.deinit();
    try plan.validateLive(&rows);
    try std.testing.expectError(error.MissingRecursiveFixedMainIdentifierPort, plan.requireIndependentMainPort());
    @constCast(rows.main[4][9].values)[0] = M.fromCanonical(99);
    try std.testing.expectError(error.UntrustedRecursiveFixedNamespace, plan.validateLive(&rows));
    @constCast(rows.main[4][9].values)[0] = M.zero();
    var expected = try OriginalNamespace.prepare(a, &rows, 1);
    defer expected.deinit();
    try std.testing.expectEqual(try expected.identity(), try plan.identity());
}
fn identifierAllocation(a: std.mem.Allocator, arithmetic: *const Arithmetic) !void {
    var identifiers = try Fusion.materializeIdentifiers(a, &arithmetic.plan, arithmetic.reference, .segment_leaf);
    defer identifiers.deinit();
    try std.testing.expectEqual(@as(usize, 3), identifiers.inverse.len);
}
test "recursive fixed attachment: original identifier emission parity for both selected modes" {
    const a = std.testing.allocator;
    const nodes = [_]C.Node{ .{ .op = .input }, .{ .op = .{ .inverse = 0 } }, .{ .op = .{ .neg = 1 } }, .{ .op = .{ .add = .{ .lhs = 1, .rhs = 2 } } } };
    const graph = try C.CircuitGraph.authenticate(&nodes, &.{3}, C.computeGraphDigest(&nodes, &.{3}));
    var arithmetic = try Arithmetic.init(a, .{ graph, graph, graph });
    defer arithmetic.deinit();
    const evaluations = [_]@import("../recursion/air/verifier_arithmetic_lowering.zig").Evaluation{.{ .circuit_identity = graph.identity_digest, .values = &.{ Q.one(), Q.one(), Q.one().neg(), Q.zero() } }} ** 6;
    for ([_]@import("../recursion/air/proof_kind.zig").ProofKind{ .segment_leaf, .binary_node }) |kind| {
        var identifiers = try Fusion.materializeIdentifiers(a, &arithmetic.plan, arithmetic.reference, kind);
        defer identifiers.deinit();
        var rows = try Fusion.materialize(a, &arithmetic.plan, arithmetic.reference, .{ .lanes = &evaluations }, kind);
        defer rows.deinit();
        try std.testing.expectEqual(rows.inverse.len, identifiers.inverse.len);
        try std.testing.expectEqual(rows.linear.len, identifiers.linear.len);
        for (rows.inverse, identifiers.inverse) |row, id| try std.testing.expectEqual(row[9].toU32(), id);
        for (rows.linear, identifiers.linear) |row, id| try std.testing.expectEqual(row[1].toU32(), id);
        var fixed: Storage.FixedTuple(false) = undefined;
        inline for (0..Storage.Airs.len) |i| fixed[i] = &.{};
        const inverse = try a.alloc(Storage.FixedRow(Storage.Airs[4]), rows.inverse.len);
        defer a.free(inverse);
        for (rows.inverse, inverse) |row, *tail| tail.* = Storage.compactFixed(Storage.Airs[4], row);
        const linear = try a.alloc(Storage.FixedRow(Storage.Airs[5]), rows.linear.len);
        defer a.free(linear);
        for (rows.linear, linear) |row, *tail| tail.* = Storage.compactFixed(Storage.Airs[5], row);
        fixed[4] = inverse;
        fixed[5] = linear;
        var plan = try Namespace.prepareForArithmetic(a, fixed, 1, .{ .plan = &arithmetic.plan, .reference = arithmetic.reference, .kind = kind });
        defer plan.deinit();
        try plan.requireIndependentMainPort();
        // Counts are tied to the actual shared emission, not guessed from
        // selected fixed schedules or a supplied identifier list.
        fixed[4] = inverse[0 .. inverse.len - 1];
        try std.testing.expectError(error.InvalidRecursiveFixedIdentifierCount, Namespace.prepareForArithmetic(a, fixed, 1, .{ .plan = &arithmetic.plan, .reference = arithmetic.reference, .kind = kind }));
    }
    try std.testing.checkAllAllocationFailures(a, identifierAllocation, .{&arithmetic});
}
fn graphAllocation(a: std.mem.Allocator) !void {
    var builder = R.Builder.init(a);
    defer builder.deinit();
    const left = (try builder.input()).value;
    const right = (try builder.input()).value;
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    try builder.constrainZero(left.sub(right));
    builder.deactivate();
    var circuit = try builder.finish();
    defer circuit.deinit();
    const sources = [_]Bus.Wire{
        .{ .circuit = 0, .wire = 0, .uses = 1, .kind = .child_cell, .child = 0, .coordinate = 0 },
        .{ .circuit = 0, .wire = 0, .uses = 1, .kind = .child_cell, .child = 1, .coordinate = 0 },
    };
    var fixed = try Graph.Owned.derive(a, &circuit, &sources);
    defer fixed.deinit();
    const value = Q.fromM31Array((Values{}).coordinates);
    const inputs = [_]Q{ value, value };
    const evaluated = try a.alloc(Q, circuit.nodes.len);
    defer a.free(evaluated);
    try circuit.evaluateInto(&inputs, evaluated);
    var original = try OriginalGraph.materializeLocallyAdmittedFor(a, .{ .circuit = &circuit, .inputs = &inputs, .values = evaluated, .sources = &sources }, Values{});
    defer original.deinit();
    try fixed.validateLive(&original);
    var namespace = try Namespace.prepare(a, fixed.fixed, 5);
    defer namespace.deinit();
    try namespace.validateLive(&original.rows);
}
fn graphFixedAllocation(a: std.mem.Allocator, circuit: *const R.Circuit, sources: []const Bus.Wire) !void {
    var fixed = try Graph.Owned.derive(a, circuit, sources);
    defer fixed.deinit();
}
test "recursive fixed attachment: exact original graph rows wire uses and identity" {
    try graphAllocation(std.testing.allocator);
}
test "recursive fixed attachment: graph compiler allocation rollback" {
    const a = std.testing.allocator;
    var builder = R.Builder.init(a);
    defer builder.deinit();
    const left = (try builder.input()).value;
    const right = (try builder.input()).value;
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    try builder.constrainZero(left.sub(right));
    builder.deactivate();
    var circuit = try builder.finish();
    defer circuit.deinit();
    const sources = [_]Bus.Wire{
        .{ .circuit = 0, .wire = 0, .uses = 1, .kind = .child_cell, .child = 0, .coordinate = 0 },
        .{ .circuit = 0, .wire = 0, .uses = 1, .kind = .child_cell, .child = 1, .coordinate = 0 },
    };
    try std.testing.checkAllAllocationFailures(a, graphFixedAllocation, .{ &circuit, @as([]const Bus.Wire, &sources) });
}
test "recursive fixed attachment: original public read weights term ordinal and span rejection" {
    const Collect = @import("../recursion/air/block_v5_recursive_fixed_child_suppliers_v1.zig");
    const T = @import("../recursion/air/blake3_transcript_witness.zig");
    const Source = @import("../recursion/air/blake3_execution_composition.zig").Source;
    const a = std.testing.allocator;
    var builder = R.Builder.init(a);
    defer builder.deinit();
    const left = (try builder.input()).value;
    const right = (try builder.input()).value;
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    try builder.constrainZero(left.sub(right));
    builder.deactivate();
    var circuit = try builder.finish();
    defer circuit.deinit();
    const roots = [_]T.RootReads{.{ .operation = 0, .source = .{ .circuit = 77, .first_wire = 5 }, .uses = .{ 1, 2, 3, 4, 5, 6, 7, 8 } }};
    const payloads = [_]T.PayloadReads{.{ .operation = 1, .source = .{ .circuit = 77, .first_wire = 13 }, .uses = &.{ 9, 0, 1 } }};
    const transcript_fixed = .{ .root_reads = &roots, .payload_reads = &payloads };
    var sources = [_]Source{ .{ .packed_public_input = 0 }, .{ .packed_public_input = 1 } };
    const composition = .{ .circuit = &circuit, .sources = &sources };
    const wires = try Collect.collect(a, transcript_fixed, composition, 1, 2, 77);
    defer a.free(wires);
    try std.testing.expectEqual(@as(usize, 11), wires.len);
    for (wires[0..8], 0..) |wire, i| {
        try std.testing.expectEqual(i + 5, wire.coordinate);
        try std.testing.expectEqual(i + 1, wire.uses);
        try std.testing.expectEqual(@as(u32, 2), wire.child);
    }
    try std.testing.expectEqual(@as(u32, 13), wires[8].coordinate);
    try std.testing.expectEqual(@as(u32, 9), wires[8].uses);
    try std.testing.expectEqual(@as(u32, 15), wires[9].coordinate);
    try std.testing.expect(wires[10].negative and wires[10].kind == .child_term and wires[10].uses == 1 and wires[10].coordinate == 0);
    try std.testing.expectError(error.InvalidV5NestedPublicSchedule, Collect.collect(a, transcript_fixed, composition, 0, 2, 77));
    sources[0] = .{ .public_input = 0 };
    try std.testing.expectError(error.UnexpectedScopedChildSpanInput, Collect.collect(a, transcript_fixed, composition, 1, 2, 77));
}
fn attachmentAllocation(a: std.mem.Allocator) !void {
    var rows = try empty(a);
    defer rows.deinit();
    try put(2, &rows, try Boundary.privateCoordinates(17, 0, M.one(), (Values{}).coordinates));
    const wire = Bus.Wire{ .circuit = 17, .wire = 0, .uses = 7, .negative = true, .child = 0, .kind = .child_cell, .coordinate = 0 };
    var ports = try Attach.Scoped.init(a, .{});
    defer ports.deinit();
    try ports.appendChild(rows.fixed, &.{wire});
    const namespace_identity = ports.attachments.items[0];
    var namespace = try OriginalNamespace.prepare(a, &rows, 1);
    defer namespace.deinit();
    try std.testing.expectEqual(try namespace.identity(), namespace_identity);
    try OriginalNamespace.apply(&rows, &namespace, namespace_identity);
    const mapped = ports.wires.items[0];
    var parent = @import("../recursion/blake3_execution_parent_preparation.zig").Prepared{ .rows = rows, .context = undefined };
    // A structural original row-storage oracle, no valid parent context/key.
    const closure = try Supply.append(a, &parent.rows, &.{mapped}, Values{}, .{});
    rows = parent.rows;
    try std.testing.expectEqual(closure, try ports.closePublicSupply(Values{}, .{}));
    try std.testing.expectEqual(@as(usize, 0), ports.wires.items.len);
    inline for (0..Storage.Airs.len) |i| {
        try std.testing.expectEqual(rows.fixed[i].len, ports.fixed[i].items.len);
        for (rows.fixed[i], ports.fixed[i].items) |original, fixed| try std.testing.expectEqualDeep(original, fixed);
    }
    try std.testing.expectError(error.MissingRecursiveFixedFamilyAdmission, ports.requireClosedSetup());
}
test "recursive fixed attachment: original signed supplier boundary and join order" {
    try attachmentAllocation(std.testing.allocator);
}
test "recursive fixed attachment: exact four child bound rejects fifth without mutation" {
    var ports = try Attach.Scoped.init(std.testing.allocator, .{});
    defer ports.deinit();
    var fixed: Storage.FixedTuple(false) = undefined;
    inline for (0..Storage.Airs.len) |i| fixed[i] = &.{};
    var boundary = [_]Storage.FixedRow(Storage.Airs[2]){Storage.compactFixed(Storage.Airs[2], try Boundary.logicalRow(19, 0, M.one(), 7))};
    fixed[2] = &boundary;
    for (0..4) |child| try ports.appendChild(fixed, &.{.{ .circuit = 19, .wire = 0, .uses = 1, .kind = .child_cell, .child = @intCast(child), .coordinate = 0 }});
    const before = ports.next_namespace;
    try std.testing.expectError(error.InvalidRecursiveFixedChildCount, ports.appendChild(fixed, &.{}));
    try std.testing.expectEqual(before, ports.next_namespace);
    try std.testing.expectEqual(@as(usize, 4), ports.fixed[2].items.len);
    for (ports.wires.items, 0..) |wire, child| {
        try std.testing.expectEqual(child + 1, wire.circuit);
        try std.testing.expectEqual(child, wire.child);
    }
}
fn attachmentNewAllocation(a: std.mem.Allocator) !void {
    var ports = try Attach.Scoped.init(a, .{});
    defer ports.deinit();
    var fixed: Storage.FixedTuple(false) = undefined;
    inline for (0..Storage.Airs.len) |i| fixed[i] = &.{};
    var boundary = [_]Storage.FixedRow(Storage.Airs[2]){Storage.compactFixed(Storage.Airs[2], try Boundary.logicalRow(19, 0, M.one(), 7))};
    fixed[2] = &boundary;
    try ports.appendChild(fixed, &.{.{ .circuit = 19, .wire = 0, .uses = 1, .kind = .child_cell, .coordinate = 0 }});
    _ = try ports.closePublicSupply(Values{}, .{});
}
test "recursive fixed attachment: full allocation failure cleanup and original owner release" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, attachmentNewAllocation, .{});
    // Fault the new graph-only compiler separately: do not repeatedly build
    // the full original live row oracle at every graph allocation index.
    const budget = try Budget.create(std.testing.allocator, 8 << 20);
    var ports = Attach.Scoped.init(budget.allocator(), .{}) catch |failure| {
        budget.destroy();
        return failure;
    };
    budget.destroy();
    defer ports.deinit();
    var fixed: Storage.FixedTuple(false) = undefined;
    inline for (0..Storage.Airs.len) |i| fixed[i] = &.{};
    var boundary = [_]Storage.FixedRow(Storage.Airs[2]){Storage.compactFixed(Storage.Airs[2], try Boundary.logicalRow(19, 0, M.one(), 7))};
    fixed[2] = &boundary;
    try ports.appendChild(fixed, &.{.{ .circuit = 19, .wire = 0, .uses = 1, .kind = .child_cell, .coordinate = 0 }});
    _ = try ports.closePublicSupply(Values{}, .{});
}
