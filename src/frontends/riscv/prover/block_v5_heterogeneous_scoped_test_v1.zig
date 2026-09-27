//! Pure coordinate/equation models only. No model Source below is validated
//! as authority, no Verified capture is invented, no producer is called.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const P = @import("../recursion/block_v5_heterogeneous_scoped_plan_v1.zig");
const C = @import("../recursion/block_v5_heterogeneous_scoped_cohorts_v1.zig");
const Routes = @import("../recursion/block_v5_heterogeneous_scoped_routes_v1.zig");
const Source = @import("../recursion/block_v5_heterogeneous_scoped_source_v1.zig");
const Bus = @import("../recursion/block_v5_heterogeneous_scoped_public_bus_v1.zig");
const E = @import("../recursion/air/block_v5_heterogeneous_scoped_equations_v1.zig");
const G = @import("../recursion/air/block_v5_heterogeneous_scoped_graph_rows_v1.zig");
fn cells(value: Q) [4][4]M {
    var result: [4][4]M = undefined;
    for (&result, value.toM31Array()) |*word, limb| for (word, 0..) |*byte, part| {
        byte.* = M.fromCanonical((limb.v >> @as(u5, @intCast(8 * part))) & 255);
    };
    return result;
}
const Fixture = struct {
    scoped: P.Plan = undefined,
    cohorts: C.Plan = undefined,
    routes: Routes.Plan = undefined,
    requirements: [1]P.Requirement = .{.{ .key = .{ .kind = .state, .scope = 7, .coordinate = 0 }, .terms = &.{}, .disposition = .zero_when_complete }},
    route_nodes: [4]Routes.Node = undefined,
    sources: [2]Source.Source = undefined,
    left: [4][4]M,
    right: [4][4]M,
    slots: [1]Source.Slot = .{.{ .requirement = 0, .first = 0 }},
    exports: [1]u32 = .{0},
    outputs: [1]Q,
    fn init(left: Q, right: Q) Fixture {
        return .{ .left = cells(left), .right = cells(right), .outputs = .{left.add(right)} };
    }
    fn values(self: *Fixture, closed: bool) Bus.Values {
        self.scoped.requirements = &self.requirements;
        self.cohorts.root = .{ .node = 3 }; // Pure current-node equation, not whole-root authority.
        self.routes.scoped = &self.scoped;
        self.routes.cohorts = &self.cohorts;
        self.routes.nodes = &self.route_nodes;
        self.route_nodes[0] = .{ .inputs = &self.exports, .exports = &self.exports, .closed = &.{} };
        self.route_nodes[1] = self.route_nodes[0];
        self.route_nodes[2] = .{ .inputs = &self.exports, .exports = if (closed) &.{} else &self.exports, .closed = if (closed) &self.exports else &.{} };
        self.sources[0].ref = .{ .node = 0 };
        self.sources[1].ref = .{ .node = 1 };
        self.sources[0].cells = &self.left;
        self.sources[1].cells = &self.right;
        for (&self.sources) |*source| {
            source.slots = &self.slots;
            source.span = null;
        }
        return .{ .routes = &self.routes, .index = 2, .children = &self.sources, .pins = &.{}, .outputs = if (closed) &.{} else &self.outputs };
    }
};
test "scoped hierarchy: genuine byte-lifted compact merge preserves all four QM31 limbs and rejects output/source mutation" {
    const a = std.testing.allocator;
    var fixture = Fixture.init(Q.fromU32Unchecked(3, 5, 7, 11), Q.fromU32Unchecked(13, 17, 19, 23));
    var graph = try E.testing.record(a, fixture.values(false));
    defer graph.deinit();
    try std.testing.expectEqual(@as(usize, 48), graph.inputs.len); // Two lower fields + one output.
    const last = graph.inputs.len - 1;
    graph.inputs[last] = graph.inputs[last].add(Q.one());
    try std.testing.expectError(error.UnsatisfiedCircuit, graph.circuit.evaluateInto(graph.inputs, graph.values));
    graph.inputs[last] = graph.inputs[last].sub(Q.one());
    try graph.circuit.evaluateInto(graph.inputs, graph.values);
    graph.inputs[0] = graph.inputs[0].add(Q.one());
    try std.testing.expectError(error.UnsatisfiedCircuit, graph.circuit.evaluateInto(graph.inputs, graph.values));
}
test "scoped hierarchy: complete keyed scope is constrained zero rather than discarded or canceled across windows" {
    const a = std.testing.allocator;
    var correct = Fixture.init(Q.one(), Q.zero().sub(Q.one()));
    var graph = try E.testing.record(a, correct.values(true));
    defer graph.deinit();
    try std.testing.expectEqual(@as(usize, 32), graph.inputs.len);
    var deficit = Fixture.init(Q.one(), Q.zero());
    try std.testing.expectError(error.UnsatisfiedCircuit, E.testing.record(a, deficit.values(true)));
}
fn allocation(a: std.mem.Allocator) !void {
    var fixture = Fixture.init(Q.fromU32Unchecked(3, 5, 7, 11), Q.fromU32Unchecked(13, 17, 19, 23));
    var graph = try E.testing.record(a, fixture.values(false));
    defer graph.deinit();
    var rows = try G.testing.lowerGraph(a, graph.graph(), fixture.values(false));
    defer rows.deinit();
}
test "scoped hierarchy: compact original row lowering cleans every allocation and detects stale independent bytes" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocation, .{});
    const a = std.testing.allocator;
    var fixture = Fixture.init(Q.one(), Q.one());
    var graph = try E.testing.record(a, fixture.values(false));
    defer graph.deinit();
    fixture.left[0][0] = M.fromCanonical(2);
    try std.testing.expectError(error.UntrustedHeterogeneousGraphInput, G.testing.lowerGraph(a, graph.graph(), fixture.values(false)));
}
test "scoped hierarchy: exact contribution source selection and pending scoped disposition cannot flatten table kinds" {
    const refs = [_]P.Term{ .{ .selection = .{ .byte = .{ .child = 1, .cell = 0, .part = 0 } } }, .{ .selection = .{ .byte = .{ .child = 4, .cell = 0, .part = 0 } }, .negative = true } };
    const requirement = P.Requirement{ .key = .{ .kind = .pairing, .scope = 9, .coordinate = 0 }, .terms = &refs, .disposition = .zero_when_complete };
    try std.testing.expect(P.Plan.participates(requirement, &.{1}));
    try std.testing.expect(!P.Plan.complete(requirement, &.{1}));
    try std.testing.expect(P.Plan.complete(requirement, &.{ 1, 4 }));
    try std.testing.expectEqual(@as(usize, 1), P.Plan.termsFor(requirement, 4).len);
    try std.testing.expect(P.Plan.termsFor(requirement, 4)[0].negative);
    try std.testing.expectEqual(@as(usize, 0), P.Plan.termsFor(requirement, 3).len);
    const key0 = P.Key{ .kind = .lookup, .scope = 3, .coordinate = 0 };
    const key1 = P.Key{ .kind = .lookup, .scope = 3, .coordinate = 1 };
    try std.testing.expect(!std.meta.eql(key0, key1));
}
fn multi(a: std.mem.Allocator, accounting: bool) !E.Prepared {
    const count: usize = if (accounting) 9 else 2;
    const requirements = try a.alloc(P.Requirement, count);
    defer a.free(requirements);
    const ids = try a.alloc(u32, count);
    defer a.free(ids);
    const slots = try a.alloc(Source.Slot, count);
    defer a.free(slots);
    const left = try a.alloc([4]M, 4 * count);
    defer a.free(left);
    const right = try a.alloc([4]M, 4 * count);
    defer a.free(right);
    const outputs = try a.alloc(Q, count);
    defer a.free(outputs);
    for (requirements, ids, slots, 0..) |*requirement, *id, *slot, i| {
        id.* = @intCast(i);
        slot.* = .{ .requirement = @intCast(i), .first = @intCast(4 * i) };
        const coordinate: u32 = if (accounting) ([_]u32{ 0, 1, 3, 4, 5, 6, 7, 9, 10 })[i] else 0;
        requirement.* = .{ .key = .{ .kind = if (accounting) .accounting else .state, .scope = if (accounting) 0 else @intCast(i), .coordinate = coordinate }, .terms = &.{}, .disposition = if (accounting) .retain else .zero_when_complete };
        const value = if (accounting) switch (coordinate) {
            0, 9 => Q.one(),
            7 => Q.one().add(Q.one()),
            else => Q.zero(),
        } else if (i == 0) Q.one() else Q.zero().sub(Q.one());
        const encoded = cells(value);
        @memcpy(left[4 * i ..][0..4], &encoded);
        const zeros = cells(Q.zero());
        @memcpy(right[4 * i ..][0..4], &zeros);
        outputs[i] = value;
    }
    var source_views: [2]Source.Source = undefined;
    source_views[0].cells = left;
    source_views[1].cells = right;
    for (&source_views, 0..) |*source, index| {
        source.ref = .{ .node = @intCast(index) };
        source.slots = slots;
        source.span = null;
    }
    var routes: Routes.Plan = undefined;
    var scoped: P.Plan = undefined;
    var cohorts: C.Plan = undefined;
    var nodes: [4]Routes.Node = undefined;
    scoped.requirements = requirements;
    cohorts.root = .{ .node = if (accounting) 2 else 3 };
    routes.scoped = &scoped;
    routes.cohorts = &cohorts;
    routes.nodes = &nodes;
    nodes[0] = .{ .inputs = ids, .exports = ids, .closed = &.{} };
    nodes[1] = nodes[0];
    nodes[2] = .{ .inputs = ids, .exports = if (accounting) ids else &.{}, .closed = if (accounting) &.{} else ids };
    return E.testing.record(a, .{ .routes = &routes, .index = 2, .children = &source_views, .pins = &.{}, .outputs = if (accounting) outputs else &.{} });
}
test "scoped hierarchy: deficits and surpluses in two execution scopes cannot cancel at complete node" {
    try std.testing.expectError(error.UnsatisfiedCircuit, multi(std.testing.allocator, false));
}
test "scoped hierarchy: original known residual constrains auxiliary sign and once byte total while compensations remain open" {
    var graph = try multi(std.testing.allocator, true);
    defer graph.deinit();
    // Each scope records 16 bytes from each of two children; the nine known output
    // fields follow. Mutate both source and its proposed output together so
    // merge equality stays satisfied: the original accounting equation fails.
    const source_auxiliary = 6 * 32;
    const output_auxiliary = 9 * 32 + 6 * 16;
    graph.inputs[source_auxiliary] = graph.inputs[source_auxiliary].add(Q.one());
    graph.inputs[output_auxiliary] = graph.inputs[output_auxiliary].add(Q.one());
    try std.testing.expectError(error.UnsatisfiedCircuit, graph.circuit.evaluateInto(graph.inputs, graph.values));
    graph.inputs[source_auxiliary] = graph.inputs[source_auxiliary].sub(Q.one());
    graph.inputs[output_auxiliary] = graph.inputs[output_auxiliary].sub(Q.one());
    try graph.circuit.evaluateInto(graph.inputs, graph.values);
    const source_byte = 7 * 32;
    const output_byte = 9 * 32 + 7 * 16;
    graph.inputs[source_byte] = Q.zero();
    graph.inputs[output_byte] = Q.zero();
    try std.testing.expectError(error.UnsatisfiedCircuit, graph.circuit.evaluateInto(graph.inputs, graph.values));
}

fn checkGraphRows(a: std.mem.Allocator, lowered: *const G.Lowered, values: Bus.Values) !void {
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

test "scoped hierarchy: actual shared parent row equations and original public tuples close exact lower summary requests" {
    const a = std.testing.allocator;
    var fixture = Fixture.init(Q.fromU32Unchecked(3, 5, 7, 11), Q.fromU32Unchecked(13, 17, 19, 23));
    const values = fixture.values(false);
    var graph = try E.testing.record(a, values);
    defer graph.deinit();
    var lowered = try G.testing.lowerGraph(a, graph.graph(), values);
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
const RoutingFixture = struct {
    scoped: P.Plan = undefined,
    cohorts: C.Plan = undefined,
    // Coordinate/topology metadata only; no Child/Fresh is constructed.
    leaves: [5]@import("../recursion/block_v5_heterogeneous_child_frames_v1.zig").Child = undefined,
    nodes: [3]C.Node = undefined,
    requirements: [4]P.Requirement = undefined,
    terms: [6]P.Term = undefined,
    fn init(self: *@This()) void {
        self.scoped.full.children = &self.leaves;
        self.scoped.digest = @splat(1);
        self.scoped.requirements = &self.requirements;
        self.cohorts.nodes = &self.nodes;
        self.cohorts.root = .{ .node = 2 };
        self.nodes = .{
            .{ .children = .{ .{ .leaf = 0 }, .{ .leaf = 1 }, undefined, undefined }, .child_count = 2, .descendants = &.{ 0, 1 }, .span = null },
            .{ .children = .{ .{ .leaf = 2 }, .{ .leaf = 3 }, undefined, undefined }, .child_count = 2, .descendants = &.{ 2, 3 }, .span = null },
            .{ .children = .{ .{ .node = 0 }, .{ .node = 1 }, .{ .leaf = 4 }, undefined }, .child_count = 3, .descendants = &.{ 0, 1, 2, 3, 4 }, .span = null },
        };
        const ordinals = [_]u32{ 0, 1, 1, 2, 0, 4 };
        for (&self.terms, ordinals) |*term, ordinal| term.* = .{ .selection = .{ .byte = .{ .child = ordinal, .cell = 0, .part = 0 } } };
        self.requirements = .{
            .{ .key = .{ .kind = .state, .scope = 0, .coordinate = 0 }, .terms = self.terms[0..2], .disposition = .zero_when_complete },
            .{ .key = .{ .kind = .state, .scope = 1, .coordinate = 0 }, .terms = self.terms[2..4], .disposition = .zero_when_complete },
            .{ .key = .{ .kind = .program, .scope = 0, .coordinate = 0 }, .terms = self.terms[4..6], .disposition = .retain },
            .{ .key = .{ .kind = .open, .scope = 0, .coordinate = 0 }, .terms = &.{}, .disposition = .retain },
        };
    }
};
fn routingAllocation(a: std.mem.Allocator) !void {
    var fixture: RoutingFixture = undefined;
    fixture.init();
    var routes = try Routes.testing.routeMetadata(a, &fixture.scoped, &fixture.cohorts, .{});
    defer routes.deinit();
    try std.testing.expectEqualSlices(u32, &.{0}, routes.nodes[0].closed);
    try std.testing.expectEqualSlices(u32, &.{ 1, 2 }, routes.nodes[0].exports);
    try std.testing.expectEqualSlices(u32, &.{1}, routes.nodes[1].exports);
    try std.testing.expectEqualSlices(u32, &.{1}, routes.nodes[2].closed);
    try std.testing.expectEqualSlices(u32, &.{ 2, 3 }, routes.nodes[2].exports);
}
test "scoped hierarchy: canonical exact five-leaf routing closes only complete LCA scopes and preserves open zero exports" {
    try routingAllocation(std.testing.allocator);
    var fixture: RoutingFixture = undefined;
    fixture.init();
    try std.testing.expectError(error.ScopedRouteResourceLimit, Routes.testing.routeMetadata(std.testing.allocator, &fixture.scoped, &fixture.cohorts, .{ .max_slot_ids = 1 }));
    fixture.nodes[2].children[2] = .{ .leaf = 0 }; // Missing physical 4 plus duplicate 0.
    try std.testing.expectError(error.InvalidScopedRoute, Routes.testing.routeMetadata(std.testing.allocator, &fixture.scoped, &fixture.cohorts, .{}));
    fixture.init();
    fixture.nodes[0].children[0] = .{ .node = 2 }; // Genuine topological cycle.
    try std.testing.expectError(error.InvalidScopedRoute, Routes.testing.routeMetadata(std.testing.allocator, &fixture.scoped, &fixture.cohorts, .{}));
}
test "scoped hierarchy: exact route constructor releases every capped ownership allocation" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, routingAllocation, .{});
}
test "scoped hierarchy: re-sealed selectors signs and terms cannot replace independently derived semantic recipe" {
    const terms = [_]P.Term{ .{ .selection = .{ .byte = .{ .child = 0, .cell = 7, .part = 0 } } }, .{ .selection = .{ .byte = .{ .child = 1, .cell = 9, .part = 0 } }, .negative = true } };
    const expected = [_]P.Requirement{.{ .key = .{ .kind = .pairing, .scope = 0, .coordinate = 0 }, .terms = &terms, .disposition = .zero_when_complete }};
    var proposed_terms = terms;
    var proposed = expected;
    proposed[0].terms = &proposed_terms;
    var plan: P.Plan = undefined; // Only the pure identity/comparison view below.
    plan.mapping = .{ .plan = @splat(1), .coverage = @splat(2), .source_seal = @splat(3) };
    plan.requirements = &proposed;
    plan.digest = plan.identity();
    try P.testing.requireNormativeRecipe(plan.requirements, &expected);
    proposed_terms[0].selection.byte.cell = 8;
    plan.mapping.plan[0] ^= 1;
    plan.digest = plan.identity(); // A consistent unkeyed re-seal is no authority.
    try std.testing.expectError(error.UntrustedScopedSummaryRecipe, P.testing.requireNormativeRecipe(plan.requirements, &expected));
    proposed_terms = terms;
    proposed_terms[1].negative = false;
    plan.digest = plan.identity();
    try std.testing.expectError(error.UntrustedScopedSummaryRecipe, P.testing.requireNormativeRecipe(plan.requirements, &expected));
    proposed_terms = terms;
    proposed[0].terms = proposed_terms[0..1];
    plan.digest = plan.identity();
    try std.testing.expectError(error.UntrustedScopedSummaryRecipe, P.testing.requireNormativeRecipe(plan.requirements, &expected));
}

test "scoped hierarchy: original reordered word-frame claims lift identical QM31 and reject canonical limb violations" {
    const a = std.testing.allocator;
    const claim = Q.fromU32Unchecked(0x7e121314, 0x018080ff, 0x7ffffffd, 0x10203040);
    const limbs = claim.toM31Array();
    var words = [_]u32{ limbs[2].v, 999, limbs[0].v, limbs[3].v, limbs[1].v };
    var encoded: [5][4]M = undefined;
    for (&encoded, words) |*cell, word| for (cell, 0..) |*byte, part| {
        byte.* = M.fromCanonical((word >> @as(u5, @intCast(8 * part))) & 255);
    };
    const Original = @import("../recursion/block_v5_heterogeneous_child_frames_v1.zig");
    const frames = [_]Original.Frame{.{ .first = 0, .operation = .{ .words = &words } }};
    var original: [1]Original.Child = undefined; // Pure source coordinate model.
    original[0].frames = &frames;
    original[0].cells = &encoded;
    const selection = P.Selection{ .words = .{ .child = 0, .selectors = .{ .{ .frame = 0, .word = 2 }, .{ .frame = 0, .word = 4 }, .{ .frame = 0, .word = 0 }, .{ .frame = 0, .word = 3 } } } };
    const terms = [_]P.Term{.{ .selection = selection }};
    var fixture = Fixture.init(Q.zero(), Q.zero());
    var values = fixture.values(false);
    fixture.requirements[0].terms = &terms;
    fixture.scoped.full.children = &original;
    fixture.sources[0].ref = .{ .leaf = 0 };
    fixture.sources[0].cells = &encoded;
    fixture.sources[0].slots = &.{};
    fixture.outputs[0] = claim;
    values.children = &fixture.sources;
    try std.testing.expect((try fixture.scoped.value(selection)).eql(claim));
    var graph = try E.testing.record(a, values);
    defer graph.deinit();
    var lowered = try G.testing.lowerGraph(a, graph.graph(), values);
    defer lowered.deinit();
    try checkGraphRows(a, &lowered, values);
    graph.inputs[0] = graph.inputs[0].add(Q.one());
    try std.testing.expectError(error.UnsatisfiedCircuit, graph.circuit.evaluateInto(graph.inputs, graph.values));
    // This is raw malformed public-wire data, not a forbidden field constructor.
    words[2] = core.fields.m31.Modulus;
    try std.testing.expectError(error.NoncanonicalGlobalJoinSource, fixture.scoped.value(selection));
}
test "scoped hierarchy: provider-only span absence and exact source kind/multiplicity schedules remain distinct" {
    var provider: [1]Source.Source = undefined;
    provider[0].span = null;
    const values = Bus.Values{ .routes = undefined, .index = 0, .children = &provider, .pins = &.{}, .outputs = &.{} };
    try std.testing.expectError(error.InvalidScopedPublicSpan, values.at(.{ .circuit = 1, .wire = 1, .uses = 1, .kind = .child_span, .coordinate = 0 }));
    const wire = Bus.Wire{ .circuit = 1, .wire = 1, .uses = 2, .kind = .child_cell, .coordinate = 3, .part = 0 };
    const digest = try Bus.scheduleDigest(&.{wire});
    var changed = wire;
    changed.kind = .output_slot;
    try std.testing.expect(!std.meta.eql(digest, try Bus.scheduleDigest(&.{changed})));
    changed = wire;
    changed.uses += 1;
    try std.testing.expect(!std.meta.eql(digest, try Bus.scheduleDigest(&.{changed})));
    try std.testing.expectError(error.InvalidScopedPublicSchedule, Bus.scheduleDigest(&.{ wire, wire }));
}

fn exactCohortAllocation(a: std.mem.Allocator) !void {
    const Original = @import("../recursion/block_v5_heterogeneous_child_frames_v1.zig");
    var children: [75]Original.Child = undefined; // Pure provider topology only.
    for (&children) |*child| child.span = null;
    var full: @import("../recursion/block_v5_heterogeneous_policy_v1.zig").Policy = undefined;
    full.children = &children;
    var plan = try C.testing.foldMetadata(a, full, .{});
    defer plan.deinit();
    try std.testing.expect(plan.root == .node);
    try std.testing.expectEqual(@as(usize, 75), plan.nodes[plan.root.node].descendants.len);
    for (plan.nodes) |node| {
        try std.testing.expect(node.child_count >= 2 and node.child_count <= 4);
        try std.testing.expect(node.span == null);
    }
    for (plan.nodes[plan.root.node].descendants, 0..) |id, ordinal| try std.testing.expectEqual(@as(u32, @intCast(ordinal)), id);
}
test "scoped hierarchy: exact 75-leaf compact cohorts use carried tails and provider span absence under hard census caps" {
    try exactCohortAllocation(std.testing.allocator);
    const Original = @import("../recursion/block_v5_heterogeneous_child_frames_v1.zig");
    var children: [75]Original.Child = undefined;
    for (&children) |*child| child.span = null;
    var full: @import("../recursion/block_v5_heterogeneous_policy_v1.zig").Policy = undefined;
    full.children = &children;
    try std.testing.expectError(error.ScopedCohortResourceLimit, C.testing.foldMetadata(std.testing.allocator, full, .{ .max_nodes = 1 }));
    try std.testing.expectError(error.ScopedCohortResourceLimit, C.testing.foldMetadata(std.testing.allocator, full, .{ .max_descendant_ids = 74 }));
    full.children = children[0..1];
    var single = try C.testing.foldMetadata(std.testing.allocator, full, .{});
    defer single.deinit();
    try std.testing.expect(single.root == .leaf and single.root.leaf == 0 and single.nodes.len == 0);
}
test "scoped hierarchy: exact compact cohort metadata ownership handles every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, exactCohortAllocation, .{});
}
