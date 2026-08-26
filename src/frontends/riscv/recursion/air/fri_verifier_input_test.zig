//! Exact row-29 FRI-circuit input authority, interaction, and hot-path gates.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const degree = @import("../../air/lang/degree.zig");
const digest = @import("../../air/lang/digest.zig");
const relation = @import("../../air/lang/relation.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const types = @import("../../air/lang/types.zig");
const circuit_mod = @import("fri_verifier_circuit.zig");
const component = @import("fri_verifier_input.zig");
const interaction_mod = @import("fri_verifier_input_relation.zig");
const support = @import("test_support.zig");
const universal = @import("universal_challenges.zig");
const witness = @import("fri_verifier_input_witness.zig");

const WIDTHS = [_]u32{4};
const PROFILE = circuit_mod.Profile{
    .lifting_log_size = 4,
    .log_blowup_factor = 1,
    .log_last_layer_degree_bound = 1,
    .fold_widths = &WIDTHS,
    .query_count = 1,
};
const INPUTS_PER_LANE: usize = 67;
const TOTAL_ROWS: usize = 3 * INPUTS_PER_LANE;
const CIRCUIT_IDS = [_]u32{ 301, 302, 303 };

test "R-012 FRI verifier input preserves exact row-29 geometry and seals" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    try std.testing.expectEqual(@as(usize, 2), definition.main.physical().len);
    try std.testing.expectEqual(@as(usize, 20), definition.preprocessed.physical().len);
    try std.testing.expectEqual(@as(usize, 8), definition.parameters.physical().len);
    try std.testing.expectEqual(@as(usize, 3), definition.constraints.len);
    try std.testing.expectEqual(@as(usize, 9), definition.events.len);

    var degrees = try degree.analyze(std.testing.allocator, &definition.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(
        @as(degree.Degree, component.MAXIMUM_CONSTRAINT_DEGREE),
        degrees.maximumConstraintDegree(),
    );
    const identity_value = try digest.computeIdentity(&definition.arena);
    try std.testing.expectEqualStrings(
        component.SEMANTIC_DIGEST_HEX,
        &std.fmt.bytesToHex(identity_value.bytes, .lower),
    );
    const binding = try witness.Binding.canonical(&definition);
    _ = try witness.Executor.init(&definition, &binding);
    try std.testing.expectEqualStrings(
        witness.BINDING_DIGEST_HEX,
        &std.fmt.bytesToHex(binding.identityDigest(), .lower),
    );

    const plan = try interaction_mod.authenticate(&definition);
    try std.testing.expectEqual(@as(usize, 5), interaction_mod.Runtime.BATCH_COUNT);
    try std.testing.expectEqual(@as(usize, 20), interaction_mod.Runtime.INTERACTION_COLUMN_COUNT);
    const domains = [_]relation.Domain{
        .recursion_pcs_deep_answer_word,
        .recursion_fri_merkle_value_word,
        .recursion_verifier_randomness_word,
        .recursion_query_bit_value,
        .recursion_fri_verifier_route_word,
        .recursion_fri_verifier_route_word,
        .recursion_fri_verifier_route_word,
        .recursion_verifier_input_word,
        .recursion_wire,
    };
    for (plan.events, domains, 0..) |event, domain, index| {
        try std.testing.expectEqual(domain, event.domain);
        try std.testing.expectEqual(
            if (index == domains.len - 1) relation.Role.emit else relation.Role.consume,
            event.role,
        );
    }
}

test "R-012 FRI verifier input static profile is exact and closed" {
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
    try std.testing.expectEqual(@as(u32, 30), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 3), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 9), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 5), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 20), profile.interaction_columns);
    try std.testing.expectEqual(@as(u32, 4), profile.maximum_logical_constraint_degree);
    try std.testing.expectEqual(@as(u32, 0), profile.nodes_outside_constraint_effect_closure);
}

test "R-012 FRI verifier input schedule is graph-derived and binding ordered" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try fixture.reference.validateAuthority();
    var preprocessing = try witness.Preprocessed.init(
        std.testing.allocator,
        fixture.reference,
    );
    defer preprocessing.deinit();
    try preprocessing.validateAgainstAuthority(std.testing.allocator, fixture.reference);
    try std.testing.expectEqual(@as(usize, TOTAL_ROWS), preprocessing.rows.len);
    try std.testing.expectEqual(@as(u32, 8), preprocessing.log_size);

    for (fixture.reference.lanes, 0..) |lane, lane_index| {
        const scratch = try std.testing.allocator.alloc(u32, lane.circuit.nodes.len);
        defer std.testing.allocator.free(scratch);
        const uses = try circuit_mod.computeUseCountsInto(lane.circuit, scratch);
        for (lane.circuit.bindings, 0..) |binding, binding_index| {
            const row = preprocessing.rows[lane_index * INPUTS_PER_LANE + binding_index];
            try std.testing.expectEqual(@as(u8, @intCast(lane_index)), row.lane);
            try std.testing.expectEqual(@as(u32, @intCast(binding_index)), row.binding);
            try std.testing.expectEqual(@as(u32, @intCast(lane_index)), row.verifier_id);
            try std.testing.expectEqual(CIRCUIT_IDS[lane_index], row.circuit_id);
            try std.testing.expectEqual(binding.node_id, row.node_id);
            try std.testing.expectEqual(uses[binding.node_id], row.use_count);
            try std.testing.expect(std.meta.eql(binding.source, row.source));
            try std.testing.expectEqual(@as(u32, 1), row.row_mask);
            try std.testing.expectEqual(@as(u32, @intFromBool(lane_index == 0)), row.segment_mask);
            try std.testing.expectEqual(@as(u32, @intFromBool(lane_index != 0)), row.binary_mask);
        }
    }

    const active = preprocessing.rows[0];
    try std.testing.expect(std.meta.eql(circuit_mod.InputSource.active_selector, active.source));
    try std.testing.expectEqual([9]u32{ 0, 0, 0, 0, 0, 0, 0, 0, 1 }, active.source_masks);
    try std.testing.expectEqual([4]u32{ 0, 0, 0, 0 }, active.source_indices);
    const deep = preprocessing.rows[1];
    try std.testing.expect(std.meta.eql(
        circuit_mod.InputSource{ .deep_answer_word = .{ .query = 0, .word = 0 } },
        deep.source,
    ));
    try std.testing.expectEqual([9]u32{ 1, 0, 0, 0, 0, 0, 0, 0, 0 }, deep.source_masks);
    try std.testing.expectEqual([4]u32{ 0, 0, 0, 0 }, deep.source_indices);

    preprocessing.rows[1].use_count +%= 1;
    try std.testing.expectError(
        error.AuthorityMismatch,
        preprocessing.validateAgainst(fixture.reference),
    );
}

test "R-012 FRI verifier input evaluates real circuits in every proof mode" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, fixture.reference);
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);

    const cases = [_]witness.ProofKind{ .segment_leaf, .binary_node, .empty_leaf };
    for (cases) |kind| {
        try fixture.evaluate(kind);
        const evaluations = fixture.evaluations();
        const active_lanes = switch (kind) {
            .segment_leaf => [_]bool{ true, false, false },
            .binary_node => [_]bool{ false, true, true },
            .empty_leaf => [_]bool{ false, false, false },
        };
        for (0..3) |lane| {
            const row_index = lane * INPUTS_PER_LANE;
            const logical = try witness.logicalRow(
                fixture.reference,
                &preprocessing,
                row_index,
                evaluations,
                kind,
            );
            try expectSatisfied(&definition, logical);
            try std.testing.expectEqual(@as(u32, 1), logical[0].toU32());
            try std.testing.expectEqual(@as(u32, @intFromBool(active_lanes[lane])), logical[1].toU32());
            const entries = try plan.entries(
                &definition.arena,
                component.SEMANTIC_DIGEST,
                definition.events,
                logical,
            );
            for (entries[0..8]) |entry| try std.testing.expect(entry.numerator.isZero());
            try std.testing.expect(entries[8].numerator.eql(
                QM31.fromBase(M31.fromCanonical(if (active_lanes[lane])
                    preprocessing.rows[row_index].use_count
                else
                    0)),
            ));
            try std.testing.expectEqual(CIRCUIT_IDS[lane], entries[8].values[0].toM31Array()[0].toU32());
        }
    }
}

test "R-012 FRI verifier input relation signs domains and tuples are exact" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try fixture.evaluate(.segment_leaf);
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, fixture.reference);
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);

    const deep = try witness.logicalRow(
        fixture.reference,
        &preprocessing,
        1,
        fixture.evaluations(),
        .segment_leaf,
    );
    const entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        deep,
    );
    try std.testing.expect(entries[0].numerator.eql(QM31.one().neg()));
    for (entries[1..8]) |entry| try std.testing.expect(entry.numerator.isZero());
    try std.testing.expect(entries[8].numerator.eql(
        QM31.fromBase(M31.fromCanonical(preprocessing.rows[1].use_count)),
    ));
    try std.testing.expectEqual(@as(u32, 0), entries[0].values[0].toM31Array()[0].toU32());
    try std.testing.expectEqual(@as(u32, 0), entries[0].values[1].toM31Array()[0].toU32());
    try std.testing.expectEqual(@as(u32, 0), entries[0].values[2].toM31Array()[0].toU32());
    try std.testing.expect(entries[0].values[3].isZero());

    const inactive_deep = try witness.logicalRow(
        fixture.reference,
        &preprocessing,
        INPUTS_PER_LANE + 1,
        fixture.evaluations(),
        .segment_leaf,
    );
    const inactive_entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        inactive_deep,
    );
    for (inactive_entries) |entry| try std.testing.expect(entry.numerator.isZero());
}

test "R-012 FRI verifier input writers are allocation-free padded and failure atomic" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try fixture.evaluate(.binary_node);
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var preprocessing = try witness.Preprocessed.init(measured.allocator(), fixture.reference);
    defer preprocessing.deinit();
    try std.testing.expectEqual(@as(usize, 2), measured.alloc_index);
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const size = @as(usize, 1) << @intCast(preprocessing.log_size);

    const pp_storage = try std.testing.allocator.alloc(
        M31,
        component.PREPROCESSED_COLUMN_COUNT * size,
    );
    defer std.testing.allocator.free(pp_storage);
    var pp_columns: [component.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    splitColumns(component.PREPROCESSED_COLUMN_COUNT, size, pp_storage, &pp_columns);
    const before_pp = measured.alloc_index;
    try executor.generatePreprocessedInto(&preprocessing, fixture.reference, &pp_columns);
    try std.testing.expectEqual(before_pp, measured.alloc_index);

    const main_storage = try std.testing.allocator.alloc(
        M31,
        component.PHYSICAL_MAIN_COLUMN_COUNT * size,
    );
    defer std.testing.allocator.free(main_storage);
    var main_columns: [component.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
    splitColumns(component.PHYSICAL_MAIN_COLUMN_COUNT, size, main_storage, &main_columns);
    const before_main = measured.alloc_index;
    try executor.generateMainInto(
        &preprocessing,
        fixture.reference,
        &main_columns,
        fixture.evaluations(),
        .binary_node,
    );
    try std.testing.expectEqual(before_main, measured.alloc_index);
    for (main_columns) |column| for (column[preprocessing.rows.len..]) |value|
        try std.testing.expect(value.isZero());

    const sentinel = M31.fromCanonical(12345);
    @memset(main_storage, sentinel);
    var duplicate = main_columns;
    duplicate[1] = duplicate[0];
    try std.testing.expectError(
        error.AliasedDestination,
        executor.generateMainInto(
            &preprocessing,
            fixture.reference,
            &duplicate,
            fixture.evaluations(),
            .binary_node,
        ),
    );
    for (main_storage) |value| try std.testing.expect(value.eql(sentinel));
}

test "R-012 FRI verifier input rejects reference circuit row and evaluation mutation" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try fixture.evaluate(.segment_leaf);
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, fixture.reference);
    defer preprocessing.deinit();

    fixture.circuits[0].identity_digest[0] ^= 1;
    try std.testing.expectError(error.AuthorityMismatch, fixture.reference.validate());
    fixture.circuits[0].identity_digest[0] ^= 1;
    try fixture.reference.validate();

    const node = fixture.circuits[0].bindings[1].node_id;
    fixture.evaluation_slots[0].values[node] = fixture.evaluation_slots[0].values[node].add(QM31.one());
    try std.testing.expectError(
        error.InvalidWitness,
        witness.logicalRow(
            fixture.reference,
            &preprocessing,
            1,
            fixture.evaluations(),
            .segment_leaf,
        ),
    );
    fixture.evaluation_slots[0].values[node] = fixture.evaluation_slots[0].values[node].sub(QM31.one());

    preprocessing.rows[0].circuit_id +%= 1;
    try std.testing.expectError(
        error.AuthorityMismatch,
        preprocessing.validateAgainst(fixture.reference),
    );
}

test "R-012 FRI verifier input construction interaction and circuit release every failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        circuitFailureCase,
        .{},
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        componentFailureCase,
        .{},
    );

    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try fixture.evaluate(.segment_leaf);
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, fixture.reference);
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    const logical = try witness.logicalRow(
        fixture.reference,
        &preprocessing,
        1,
        fixture.evaluations(),
        .segment_leaf,
    );
    const rows = [_]interaction_mod.Row{logical};
    const relations = universal.UniversalRelations.dummy();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        interactionFailureCase,
        .{ &definition, &plan, &rows, witness.MIN_LOG_SIZE, &relations },
    );
}

const Fixture = struct {
    allocator: std.mem.Allocator,
    circuits: *[3]circuit_mod.Circuit,
    reference: witness.Reference,
    zero_fixtures: [3]ZeroFixture,
    evaluation_slots: [3]circuit_mod.Evaluation,
    evaluation_live: [3]bool,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const circuits = try allocator.create([3]circuit_mod.Circuit);
        errdefer allocator.destroy(circuits);
        var initialized: usize = 0;
        errdefer for (circuits[0..initialized]) |*circuit| circuit.deinit();
        for (circuits) |*circuit| {
            circuit.* = try circuit_mod.build(allocator, PROFILE);
            initialized += 1;
        }
        const reference = try witness.Reference.seal(.{
            .{ .verifier_id = 0, .circuit_id = CIRCUIT_IDS[0], .circuit = &circuits[0] },
            .{ .verifier_id = 1, .circuit_id = CIRCUIT_IDS[1], .circuit = &circuits[1] },
            .{ .verifier_id = 2, .circuit_id = CIRCUIT_IDS[2], .circuit = &circuits[2] },
        });
        return .{
            .allocator = allocator,
            .circuits = circuits,
            .reference = reference,
            .zero_fixtures = undefined,
            .evaluation_slots = undefined,
            .evaluation_live = .{ false, false, false },
        };
    }

    fn evaluate(self: *Fixture, kind: witness.ProofKind) !void {
        self.releaseEvaluations();
        const active = switch (kind) {
            .segment_leaf => [_]bool{ true, false, false },
            .binary_node => [_]bool{ false, true, true },
            .empty_leaf => [_]bool{ false, false, false },
        };
        for (&self.evaluation_slots, &self.zero_fixtures, self.circuits, active, 0..) |
            *evaluation,
            *zero,
            *circuit,
            lane_active,
            lane,
        | {
            zero.* = zeroWitness(lane_active);
            evaluation.* = try circuit.evaluate(std.testing.allocator, zero.witness());
            self.evaluation_live[lane] = true;
        }
    }

    fn evaluations(self: *const Fixture) witness.Evaluations {
        std.debug.assert(self.evaluation_live[0] and self.evaluation_live[1] and self.evaluation_live[2]);
        return .{
            .segment = &self.evaluation_slots[0],
            .left = &self.evaluation_slots[1],
            .right = &self.evaluation_slots[2],
        };
    }

    fn releaseEvaluations(self: *Fixture) void {
        for (&self.evaluation_slots, &self.evaluation_live) |*evaluation, *live| if (live.*) {
            evaluation.deinit();
            live.* = false;
        };
    }

    fn deinit(self: *Fixture) void {
        self.releaseEvaluations();
        for (self.circuits) |*circuit| circuit.deinit();
        self.allocator.destroy(self.circuits);
        self.* = undefined;
    }
};

const ZeroFixture = struct {
    active: bool,
    deep: [1]QM31,
    authenticated: [4]QM31,
    authenticated_layers: [1][]const QM31,
    alphas: [1]QM31,
    raw_queries: [1]M31,
    positions: [1]M31,
    position_layers: [1][]const M31,
    offsets: [1]M31,
    offset_layers: [1][]const M31,
    last_positions: [1]M31,
    coefficients: [2]QM31,

    fn witness(self: *ZeroFixture) circuit_mod.Witness {
        self.authenticated_layers = .{&self.authenticated};
        self.position_layers = .{&self.positions};
        self.offset_layers = .{&self.offsets};
        return .{
            .active = self.active,
            .deep_answers = &self.deep,
            .authenticated_values = &self.authenticated_layers,
            .fri_alphas = &self.alphas,
            .raw_queries = &self.raw_queries,
            .fri_positions = &self.position_layers,
            .fri_offsets = &self.offset_layers,
            .last_layer_positions = &self.last_positions,
            .last_layer_coefficients = &self.coefficients,
        };
    }
};

fn zeroWitness(active: bool) ZeroFixture {
    return .{
        .active = active,
        .deep = .{QM31.zero()},
        .authenticated = [_]QM31{QM31.zero()} ** 4,
        .authenticated_layers = undefined,
        .alphas = .{QM31.zero()},
        .raw_queries = .{M31.zero()},
        .positions = .{M31.zero()},
        .position_layers = undefined,
        .offsets = .{M31.zero()},
        .offset_layers = undefined,
        .last_positions = .{M31.zero()},
        .coefficients = [_]QM31{QM31.zero()} ** 2,
    };
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

fn circuitFailureCase(allocator: std.mem.Allocator) !void {
    var circuit = try circuit_mod.build(allocator, PROFILE);
    defer circuit.deinit();
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
