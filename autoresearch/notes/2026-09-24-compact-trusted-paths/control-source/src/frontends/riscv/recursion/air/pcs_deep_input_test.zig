//! Exactness, authenticated-graph, mutation, and performance gates for row 24.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const degree = @import("../../air/lang/degree.zig");
const digest = @import("../../air/lang/digest.zig");
const relation = @import("../../air/lang/relation.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const types = @import("../../air/lang/types.zig");
const circuit = @import("composition_circuit.zig");
const component = @import("pcs_deep_input.zig");
const interaction_mod = @import("pcs_deep_input_relation.zig");
const support = @import("test_support.zig");
const universal = @import("universal_challenges.zig");
const witness = @import("pcs_deep_input_witness.zig");

const TREE_0 = [_]u32{ 5, 4 };
const TREE_1 = [_]u32{3};
const TREES = [_]witness.TreeProfile{
    .{ .column_log_sizes = &TREE_0 },
    .{ .column_log_sizes = &TREE_1 },
};
const PROFILE = witness.LaneProfile{
    .sample_count = 2,
    .query_count = 2,
    .lifting_log_size = 5,
    .trees = &TREES,
};
const INPUT_COUNT: usize = 95;
const NODE_COUNT: usize = 2 * INPUT_COUNT - 1;
const OUTPUTS = [_]u32{NODE_COUNT - 1};
const CIRCUIT_IDS = [_]u32{ 101, 102, 103 };
const TOTAL_ROWS: usize = 3 * INPUT_COUNT;

test "R-012 PCS-DEEP input preserves exact Stark-V row-24 geometry and seal" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    try std.testing.expectEqual(@as(usize, 2), definition.main.physical().len);
    try std.testing.expectEqual(@as(usize, 18), definition.preprocessed.physical().len);
    try std.testing.expectEqual(@as(usize, 6), definition.parameters.physical().len);
    try std.testing.expectEqual(@as(usize, 3), definition.constraints.len);
    try std.testing.expectEqual(@as(usize, 8), definition.events.len);
    var degrees = try degree.analyze(std.testing.allocator, &definition.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(
        @as(degree.Degree, component.MAXIMUM_CONSTRAINT_DEGREE),
        degrees.maximumConstraintDegree(),
    );
    const identity = try digest.computeIdentity(&definition.arena);
    try std.testing.expectEqualStrings(
        component.SEMANTIC_DIGEST_HEX,
        &std.fmt.bytesToHex(identity.bytes, .lower),
    );
    const binding = try witness.Binding.canonical(&definition);
    _ = try witness.Executor.init(&definition, &binding);
    try std.testing.expectEqualStrings(
        witness.BINDING_DIGEST_HEX,
        &std.fmt.bytesToHex(binding.identityDigest(), .lower),
    );

    const plan = try interaction_mod.authenticate(&definition);
    try std.testing.expectEqual(@as(usize, 4), interaction_mod.Runtime.BATCH_COUNT);
    try std.testing.expectEqual(@as(usize, 16), interaction_mod.Runtime.INTERACTION_COLUMN_COUNT);
    const domains = [_]relation.Domain{
        .recursion_verifier_input_word,
        .recursion_trace_query_value,
        .recursion_verifier_randomness_word,
        .recursion_verifier_randomness_word,
        .recursion_query_bit_value,
        .recursion_query_position,
        .recursion_pcs_deep_answer_word,
        .recursion_wire,
    };
    const roles = [_]relation.Role{
        .consume, .consume, .consume, .consume, .consume, .consume, .emit, .emit,
    };
    for (plan.events, domains, roles) |event, domain, role| {
        try std.testing.expectEqual(domain, event.domain);
        try std.testing.expectEqual(role, event.role);
    }
}

test "R-012 PCS-DEEP static profile is exact and closed" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const profile = try static_profile.collect(std.testing.allocator, &definition.arena, .{
        .physical_main_columns = component.PHYSICAL_MAIN_COLUMN_COUNT,
        .lookup_layout = .{
            .batch_size = component.LOOKUP_BATCH_SIZE,
            .interaction_coordinates_per_batch = 4,
        },
    });
    try profile.validate();
    try std.testing.expectEqual(@as(u32, 26), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 3), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 8), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 4), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 16), profile.interaction_columns);
    try std.testing.expectEqual(@as(u32, 4), profile.maximum_logical_constraint_degree);
    try std.testing.expectEqual(@as(u32, 0), profile.nodes_outside_constraint_effect_closure);
}

test "R-012 PCS-DEEP graph authority derives every source and use count" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const reference = try fixture.reference();
    try reference.validate();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    try preprocessing.validateAgainstAuthority(reference);
    try std.testing.expectEqual(@as(usize, TOTAL_ROWS), preprocessing.rows.len);
    try std.testing.expectEqual(@as(u32, 9), preprocessing.log_size);

    try expectSource(preprocessing.rows[0], .active_selector);
    try expectSource(preprocessing.rows[1], .{ .sampled_value_word = .{ .sample = 0, .word = 0 } });
    try expectSource(preprocessing.rows[8], .{ .sampled_value_word = .{ .sample = 1, .word = 3 } });
    try expectSource(preprocessing.rows[9], .{ .queried_value = .{ .tree = 0, .column = 0, .query = 0 } });
    try expectSource(preprocessing.rows[14], .{ .queried_value = .{ .tree = 1, .column = 0, .query = 1 } });
    try expectSource(preprocessing.rows[15], .{ .oods_seed_word = 0 });
    try expectSource(preprocessing.rows[19], .{ .deep_randomness_word = 0 });
    try expectSource(preprocessing.rows[23], .{ .query_bit = .{ .query = 0, .bit = 0 } });
    try expectSource(preprocessing.rows[54], .{ .query_position = 0 });
    try expectSource(preprocessing.rows[86], .{ .query_position = 1 });
    try expectSource(preprocessing.rows[87], .{ .answer_word = .{ .query = 0, .word = 0 } });
    try expectSource(preprocessing.rows[94], .{ .answer_word = .{ .query = 1, .word = 3 } });
    for (preprocessing.rows) |row| try std.testing.expectEqual(@as(u32, 1), row.use_count);

    preprocessing.rows[0].use_count += 1;
    try std.testing.expectError(
        error.AuthorityMismatch,
        preprocessing.validateAgainst(reference),
    );
}

test "R-012 PCS-DEEP witnesses and direct constraints cover every universal mode" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const reference = try fixture.reference();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();

    for (std.enums.values(witness.ProofKind)) |kind| {
        var values = try Values.init(std.testing.allocator, reference, kind);
        defer values.deinit();
        const input = values.inputWitness(reference);
        for (preprocessing.rows, 0..) |_, row_index| {
            const logical = try witness.logicalRow(
                reference,
                &preprocessing,
                row_index,
                input,
                kind,
            );
            try expectSatisfied(&definition, logical);
        }
    }

    var segment = try Values.init(std.testing.allocator, reference, .segment_leaf);
    defer segment.deinit();
    const forged = segment.inputWitness(reference);
    segment.storage[INPUT_COUNT] = M31.one();
    try std.testing.expectError(
        error.InvalidWitness,
        witness.logicalRow(reference, &preprocessing, INPUT_COUNT, forged, .segment_leaf),
    );
    segment.storage[INPUT_COUNT] = M31.zero();
    segment.storage[0] = M31.zero();
    try std.testing.expectError(
        error.InvalidWitness,
        witness.logicalRow(reference, &preprocessing, 0, forged, .segment_leaf),
    );
}

test "R-012 PCS-DEEP relation tuples bind every source answer and wire" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const reference = try fixture.reference();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    var values = try Values.init(std.testing.allocator, reference, .segment_leaf);
    defer values.deinit();
    const input = values.inputWitness(reference);
    const cases = [_]struct {
        row: usize,
        event: usize,
        role: relation.Role,
        value_index: usize,
    }{
        .{ .row = 1, .event = 0, .role = .consume, .value_index = 4 },
        .{ .row = 9, .event = 1, .role = .consume, .value_index = 4 },
        .{ .row = 15, .event = 2, .role = .consume, .value_index = 4 },
        .{ .row = 19, .event = 3, .role = .consume, .value_index = 4 },
        .{ .row = 23, .event = 4, .role = .consume, .value_index = 3 },
        .{ .row = 54, .event = 5, .role = .consume, .value_index = 4 },
        .{ .row = 87, .event = 6, .role = .emit, .value_index = 3 },
    };
    for (cases) |case| {
        const logical = try witness.logicalRow(
            reference,
            &preprocessing,
            case.row,
            input,
            .segment_leaf,
        );
        const entries = try plan.entries(
            &definition.arena,
            component.SEMANTIC_DIGEST,
            definition.events,
            logical,
        );
        for (entries, 0..) |entry, event| {
            const expected = if (event == case.event)
                if (case.role == .consume) QM31.one().neg() else QM31.one()
            else if (event == 7)
                QM31.one()
            else
                QM31.zero();
            try std.testing.expect(entry.numerator.eql(expected));
        }
        try std.testing.expect(entries[case.event].values[case.value_index].eql(
            QM31.fromBase(logical[1]),
        ));
    }

    const inactive = try witness.logicalRow(
        reference,
        &preprocessing,
        INPUT_COUNT + 1,
        input,
        .segment_leaf,
    );
    const inactive_entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        inactive,
    );
    for (inactive_entries) |entry| try std.testing.expect(entry.numerator.isZero());
}

test "R-012 PCS-DEEP direct writers are allocation-free padded and atomic" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const reference = try fixture.reference();
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var preprocessing = try witness.Preprocessed.init(measured.allocator(), reference);
    defer preprocessing.deinit();
    try std.testing.expectEqual(@as(usize, 2), measured.alloc_index);
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    var values = try Values.init(std.testing.allocator, reference, .binary_node);
    defer values.deinit();
    const input = values.inputWitness(reference);
    const size = @as(usize, 1) << @intCast(preprocessing.log_size);

    const pp_storage = try std.testing.allocator.alloc(
        M31,
        component.PREPROCESSED_COLUMN_COUNT * size,
    );
    defer std.testing.allocator.free(pp_storage);
    var pp_columns: [component.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    splitColumns(component.PREPROCESSED_COLUMN_COUNT, size, pp_storage, &pp_columns);
    const before_preprocessed = measured.alloc_index;
    try executor.generatePreprocessedInto(&preprocessing, reference, &pp_columns);
    try std.testing.expectEqual(before_preprocessed, measured.alloc_index);

    const storage = try std.testing.allocator.alloc(M31, component.PHYSICAL_MAIN_COLUMN_COUNT * size);
    defer std.testing.allocator.free(storage);
    var columns: [component.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
    splitColumns(component.PHYSICAL_MAIN_COLUMN_COUNT, size, storage, &columns);
    const before_main = measured.alloc_index;
    try executor.generateMainInto(
        &preprocessing,
        reference,
        &columns,
        input,
        .binary_node,
    );
    try std.testing.expectEqual(before_main, measured.alloc_index);
    for (columns) |column| for (column[preprocessing.rows.len..]) |value|
        try std.testing.expect(value.isZero());

    const sentinel = M31.fromCanonical(12345);
    @memset(storage, sentinel);
    var short_columns = columns;
    short_columns[0] = short_columns[0][0 .. size - 1];
    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generateMainInto(
            &preprocessing,
            reference,
            &short_columns,
            input,
            .binary_node,
        ),
    );
    for (storage) |value| try std.testing.expect(value.eql(sentinel));

    var aliased_columns = columns;
    aliased_columns[1] = aliased_columns[0];
    try std.testing.expectError(
        error.AliasedDestination,
        executor.generateMainInto(
            &preprocessing,
            reference,
            &aliased_columns,
            input,
            .binary_node,
        ),
    );
    for (storage) |value| try std.testing.expect(value.eql(sentinel));

    var aliased_input = input;
    aliased_input.lanes[1].input_values = storage[0..INPUT_COUNT];
    storage[0] = M31.one();
    try std.testing.expectError(
        error.AliasedInput,
        executor.generateMainInto(
            &preprocessing,
            reference,
            &columns,
            aliased_input,
            .binary_node,
        ),
    );
    try std.testing.expect(storage[0].eql(M31.one()));
    for (storage[1..]) |value| try std.testing.expect(value.eql(sentinel));
}

test "R-012 PCS-DEEP interaction stays five allocations and failure atomic" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const reference = try fixture.reference();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    var values = try Values.init(std.testing.allocator, reference, .segment_leaf);
    defer values.deinit();
    const input = values.inputWitness(reference);
    const logical = try witness.logicalRow(reference, &preprocessing, 1, input, .segment_leaf);
    const rows = [_]interaction_mod.Row{logical};
    const relations = universal.UniversalRelations.dummy();
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    {
        var interaction = try plan.generateInteraction(
            measured.allocator(),
            &definition.arena,
            component.SEMANTIC_DIGEST,
            definition.events,
            &rows,
            witness.MIN_LOG_SIZE,
            &relations,
        );
        defer interaction.deinit(measured.allocator());
        try std.testing.expectEqual(@as(usize, 5), measured.alloc_index);
        try plan.validateInteraction(
            std.testing.allocator,
            &definition.arena,
            component.SEMANTIC_DIGEST,
            definition.events,
            &rows,
            witness.MIN_LOG_SIZE,
            &relations,
            &interaction,
        );
    }
    try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        interactionFailureCase,
        .{ &definition, &plan, &rows, witness.MIN_LOG_SIZE, &relations },
    );
}

test "R-012 PCS-DEEP construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        componentFailureCase,
        .{},
    );
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const reference = try fixture.reference();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        preprocessingFailureCase,
        .{reference},
    );
}

const Fixture = struct {
    allocator: std.mem.Allocator,
    nodes: []circuit.Node,
    bindings: []witness.InputBinding,
    graph: circuit.CircuitGraph,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const input_count = try PROFILE.inputCount();
        try std.testing.expectEqual(INPUT_COUNT, input_count);
        const nodes = try allocator.alloc(circuit.Node, NODE_COUNT);
        errdefer allocator.free(nodes);
        for (nodes[0..INPUT_COUNT]) |*node| node.* = .{ .op = .input };
        for (1..INPUT_COUNT) |input_index| {
            const node_index = INPUT_COUNT + input_index - 1;
            nodes[node_index] = .{ .op = .{ .add = .{
                .lhs = @intCast(if (input_index == 1) 0 else node_index - 1),
                .rhs = @intCast(input_index),
            } } };
        }
        const bindings = try allocator.alloc(witness.InputBinding, INPUT_COUNT);
        errdefer allocator.free(bindings);
        for (bindings, 0..) |*binding, index| binding.* = .{
            .node_id = @intCast(index),
            .source = (try witness.expectedSource(PROFILE, index)).?,
        };
        const graph_digest = circuit.computeGraphDigest(nodes, &OUTPUTS);
        return .{
            .allocator = allocator,
            .nodes = nodes,
            .bindings = bindings,
            .graph = try circuit.CircuitGraph.authenticate(nodes, &OUTPUTS, graph_digest),
        };
    }

    fn deinit(self: *Fixture) void {
        self.allocator.free(self.bindings);
        self.allocator.free(self.nodes);
        self.* = undefined;
    }

    fn lanes(self: *const Fixture) [3]witness.Lane {
        var result: [3]witness.Lane = undefined;
        for (&result, CIRCUIT_IDS, 0..) |*lane, circuit_id, verifier_id| lane.* = .{
            .verifier_id = @intCast(verifier_id),
            .circuit_id = circuit_id,
            .profile = PROFILE,
            .graph = self.graph,
            .bindings = self.bindings,
        };
        return result;
    }

    fn reference(self: *const Fixture) !witness.Reference {
        const lane_values = self.lanes();
        return witness.Reference.authenticate(
            lane_values,
            witness.computeReferenceDigest(lane_values),
        );
    }
};

const Values = struct {
    allocator: std.mem.Allocator,
    storage: []M31,

    fn init(
        allocator: std.mem.Allocator,
        reference: witness.Reference,
        kind: witness.ProofKind,
    ) !Values {
        const storage = try allocator.alloc(M31, TOTAL_ROWS);
        errdefer allocator.free(storage);
        for (reference.lanes, 0..) |lane, lane_index| {
            const active = switch (lane.verifier_id) {
                witness.SEGMENT_VERIFIER_ID => kind == .segment_leaf,
                witness.LEFT_RECURSION_VERIFIER_ID, witness.RIGHT_RECURSION_VERIFIER_ID => kind == .binary_node,
                else => unreachable,
            };
            const lane_values = storage[lane_index * INPUT_COUNT ..][0..INPUT_COUNT];
            for (lane_values, lane.bindings, 0..) |*value, binding, index| {
                value.* = if (!active)
                    M31.zero()
                else if (std.meta.activeTag(binding.source) == .active_selector)
                    M31.one()
                else
                    M31.fromCanonical(@intCast(1000 * lane_index + index + 1));
            }
        }
        return .{ .allocator = allocator, .storage = storage };
    }

    fn deinit(self: *Values) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }

    fn inputWitness(self: *const Values, reference: witness.Reference) witness.InputWitness {
        var lanes: [3]witness.LaneWitness = undefined;
        for (&lanes, reference.lanes, 0..) |*target, lane, lane_index| target.* = .{
            .verifier_id = lane.verifier_id,
            .circuit_id = lane.circuit_id,
            .graph_digest = lane.graph.identity_digest,
            .input_values = self.storage[lane_index * INPUT_COUNT ..][0..INPUT_COUNT],
        };
        return .{ .lanes = lanes };
    }
};

fn expectSource(row: witness.Row, expected: witness.Source) !void {
    try std.testing.expect(std.meta.eql(expected, row.source));
}

fn expectSatisfied(
    definition: *const component.Definition,
    inputs: [component.LOGICAL_INPUT_COUNT]M31,
) !void {
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &inputs);
    defer std.testing.allocator.free(values);
    for (definition.constraints) |constraint_id| {
        const constraint = definition.arena.constraint(constraint_id).?;
        try std.testing.expect(values[types.idIndex(constraint.root)].isZero());
    }
}

fn componentFailureCase(allocator: std.mem.Allocator) !void {
    var definition = try component.build(allocator);
    defer definition.deinit();
}

fn preprocessingFailureCase(
    allocator: std.mem.Allocator,
    reference: witness.Reference,
) !void {
    var preprocessing = try witness.Preprocessed.init(allocator, reference);
    defer preprocessing.deinit();
}

fn interactionFailureCase(
    allocator: std.mem.Allocator,
    definition: *const component.Definition,
    plan: *const interaction_mod.Plan,
    rows: []const interaction_mod.Row,
    log_size: u32,
    relations: *const universal.UniversalRelations,
) !void {
    var interaction = try plan.generateInteraction(
        allocator,
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        rows,
        log_size,
        relations,
    );
    defer interaction.deinit(allocator);
}

fn splitColumns(
    comptime count: usize,
    size: usize,
    storage: []M31,
    columns: *[count][]M31,
) void {
    for (columns, 0..) |*column, index| column.* = storage[index * size ..][0..size];
}
