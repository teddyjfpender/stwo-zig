const std = @import("std");
const stwo_core = @import("stwo_core");

const circle = stwo_core.circle;
const constraints = stwo_core.constraints;
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const canonic = stwo_core.poly.circle.canonic;

const subject = @import("recursion_air_composition_circuit.zig");
const graph_mod = @import("air/composition_circuit.zig");
const control = @import("air/control.zig");
const control_relation = @import("air/control_relation.zig");
const direct = @import("air/direct_constraint_program.zig");
const manifest_mod = @import("air/universal_adapter_manifest.zig");
const roster = @import("air/universal_roster.zig");
const provider = @import("air/universal_shared_provider.zig");
const range_bridge = @import("air/range_check_8_8_bridge.zig");
const span_statement = @import("span_statement.zig");
const universal = @import("air/universal_challenges.zig");
const poseidon_air = @import("../air/memory_commitment/poseidon2_air.zig");
const table_interaction = @import("../air/lookups/tables/interaction.zig");

const LOG_SIZE: u32 = 4;
const PROTOCOL_DEGREE: u8 = 3;
const FRI_LOG_BLOWUP: u32 = 1;
const COMPOSITION_COLUMN_COUNT: usize = 8;
const CORE_ROW_COUNT: usize = @intFromEnum(roster.Component.poseidon2);

const FakeComponent = struct {
    log_size: u32,
    placement: manifest_mod.Placement,
    parameters: [control.PROOF_KIND_PARAMETER_COUNT]M31,
    direct: direct.Program,
    relation_plan: control_relation.Plan,
};

test "binary composition session records exact 36 by 3 programs and matches native Horner evaluation" {
    const allocator = std.testing.allocator;
    var definition = try control.build(allocator);
    defer definition.deinit();
    const program = try direct.authenticate(
        &definition.arena,
        control.SEMANTIC_DIGEST,
        control.LOGICAL_INPUT_COUNT,
    );
    const relation_plan = try control_relation.authenticate(&definition);
    const manifest = try testManifest();
    var capture = try CaptureFixture.init(allocator, &manifest);
    defer capture.deinit();
    const relations = universal.UniversalRelations.dummy();
    var provider_relations = try provider.SharedProviderRelations.init(&relations);
    const poseidon_partials = testPoseidonPartials();
    var poseidon = try provider.Poseidon2Adapter.init(
        &manifest,
        LOG_SIZE,
        1,
        &provider_relations,
        &relations,
        poseidon_partials,
    );
    var range_definition = try range_bridge.build(allocator);
    defer range_definition.deinit();
    const range_binding = try range_bridge.Binding.canonical(&range_definition);
    const range_executor = try range_bridge.Executor.init(
        &range_definition,
        &range_binding,
    );
    var range = try provider.RangeCheck8x8Adapter.init(
        &range_definition,
        &range_executor,
        &manifest,
        &provider_relations,
        &relations,
        QM31.zero(),
    );

    var session = try subject.Session.create(allocator, &manifest, capture.view());
    var session_live = true;
    defer if (session_live) session.deinit();
    try recordPrograms(
        session,
        &manifest,
        program,
        relation_plan,
        &poseidon,
        &range,
    );
    var cached_denominators: usize = 0;
    for (session.denominator_cache) |entry|
        cached_denominators += @intFromBool(entry != null);
    try std.testing.expectEqual(@as(usize, 2), cached_denominators);
    try std.testing.expect(session.denominator_cache[LOG_SIZE] != null);
    try std.testing.expect(session.denominator_cache[range_bridge.LOG_SIZE] != null);
    var circuit = try session.finish();
    session_live = false;
    defer circuit.deinit();
    try circuit.validate();

    try std.testing.expectEqual(@as(usize, 36), circuit.statistics.roster_rows_per_kind[0]);
    try std.testing.expectEqual(@as(usize, 36), circuit.statistics.roster_rows_per_kind[1]);
    try std.testing.expectEqual(@as(usize, 36), circuit.statistics.roster_rows_per_kind[2]);
    for (circuit.statistics.constraints_per_kind) |count|
        try std.testing.expectEqual(@as(usize, manifest.total_constraints), count);
    try std.testing.expectEqual(@as(u32, 17), circuit.statistics.composition_log_size);
    try std.testing.expectEqual(@as(u32, 1), circuit.statistics.composition_log_split);
    try std.testing.expectEqual(@as(u32, 16), circuit.statistics.quotient_max_log_degree_bound);
    try std.testing.expectEqual(@as(u32, 1), circuit.statistics.fri_log_blowup);
    try std.testing.expectEqual(
        try graph_mod.recursionInputCount(circuit.input_profile),
        circuit.bindings.len,
    );
    try std.testing.expectEqual(@as(usize, 5_872), circuit.bindings.len);
    try std.testing.expectEqual(
        @as(u32, subject.COMPOSITION_CLAIM_INPUT_COUNT),
        circuit.input_profile.claimed_sum_count,
    );
    for (circuit.bindings, 0..) |binding, index| {
        try std.testing.expectEqual(@as(u32, @intCast(index)), binding.node_id);
        try std.testing.expectEqual(
            graph_mod.expectedRecursionSource(circuit.input_profile, index).?,
            binding.source,
        );
    }

    var statement_words = [_]M31{M31.zero()} ** subject.STATEMENT_WORD_COUNT;
    statement_words[span_statement.canonical_layout.body_tag] = M31.fromU64(
        @intFromEnum(span_statement.Tag.executed_body),
    );
    var claims = [_]QM31{QM31.zero()} ** subject.ROSTER_CLAIM_COUNT;
    claims[@intFromEnum(roster.Component.poseidon2)] =
        poseidon_partials[0].add(poseidon_partials[1]);
    claims[0] = (try parentPublicSum(&statement_words, &relations)).neg()
        .sub(claims[@intFromEnum(roster.Component.poseidon2)]);
    const composition_randomness = QM31.fromBase(M31.fromU64(13));
    const oods_seed = QM31.fromBase(M31.fromU64(7));
    const expected_accumulation = try nativeAccumulation(
        program,
        relation_plan,
        .segment_leaf,
        &claims,
        poseidon_partials,
        &relations,
        &provider_relations.native,
        composition_randomness,
        oods_seed,
    );
    capture.sampled_values[capture.compositionValueOffset()] = expected_accumulation;

    const inputs = try allocator.alloc(QM31, circuit.recorded.input_count);
    defer allocator.free(inputs);
    const values = try allocator.alloc(QM31, circuit.recorded.nodes.len);
    defer allocator.free(values);
    const witness = subject.Witness{
        .parent_binary_selector = true,
        .child_kind = .segment_leaf,
        .statement_words = &statement_words,
        .sampled_values = capture.sampled_values,
        .claimed_sums = &claims,
        .poseidon2_partials = &poseidon_partials,
        .relations = &relations,
        .composition_randomness = composition_randomness,
        .oods_seed = oods_seed,
    };
    try circuit.evaluateInto(witness, inputs, values);

    // The same graph is fixed for all kinds. Zero committed masks make this
    // synthetic authenticated program kind-independent, so all three selected
    // equalities exercise the same native oracle value.
    inline for (std.meta.fields(graph_mod.ProofKind)) |field| {
        var selected = witness;
        selected.child_kind = @enumFromInt(field.value);
        if (selected.child_kind == .empty_leaf) {
            statement_words[span_statement.canonical_layout.body_tag] = M31.fromU64(
                @intFromEnum(span_statement.Tag.empty_body),
            );
            statement_words[span_statement.canonical_layout.slot_height] = M31.zero();
        } else if (selected.child_kind == .binary_node) {
            statement_words[span_statement.canonical_layout.slot_height] = M31.one();
            // The public LogUp term changes with both words; preserve closure.
        } else {
            statement_words[span_statement.canonical_layout.body_tag] = M31.fromU64(
                @intFromEnum(span_statement.Tag.executed_body),
            );
            statement_words[span_statement.canonical_layout.slot_height] = M31.zero();
        }
        claims[0] = (try parentPublicSum(&statement_words, &relations)).neg()
            .sub(claims[@intFromEnum(roster.Component.poseidon2)]);
        const kind_accumulation = try nativeAccumulation(
            program,
            relation_plan,
            selected.child_kind,
            &claims,
            poseidon_partials,
            &relations,
            &provider_relations.native,
            composition_randomness,
            oods_seed,
        );
        capture.sampled_values[capture.compositionValueOffset()] = kind_accumulation;
        try circuit.evaluateInto(selected, inputs, values);
    }
}

test "binary composition graph rejects selector statement claim and composition mutations" {
    const allocator = std.testing.allocator;
    var fixture = try BuiltFixture.init(allocator);
    defer fixture.deinit();

    try fixture.circuit.writeInputs(fixture.witness(), fixture.inputs);
    try fixture.circuit.recorded.evaluateInto(fixture.inputs, fixture.values);

    fixture.circuit.manifest_seal[0] ^= 1;
    try std.testing.expectError(
        error.CircuitIdentityMismatch,
        fixture.circuit.validate(),
    );
    fixture.circuit.manifest_seal[0] ^= 1;

    fixture.circuit.bindings[0].source = .{ .statement_word = 0 };
    try std.testing.expectError(
        error.BindingCountMismatch,
        fixture.circuit.validate(),
    );
    fixture.circuit.bindings[0].source = .parent_binary_selector;

    // Exact row-18 order places parent and child-kind selectors first.
    fixture.inputs[2] = QM31.one();
    try expectRejected(fixture.circuit.recorded.evaluateInto(
        fixture.inputs,
        fixture.values,
    ));
    fixture.inputs[2] = QM31.zero();

    var wrong_statement = fixture.statement_words;
    wrong_statement[span_statement.canonical_layout.body_tag] = M31.fromU64(
        @intFromEnum(span_statement.Tag.empty_body),
    );
    var witness = fixture.witness();
    witness.statement_words = &wrong_statement;
    try expectRejected(fixture.circuit.evaluateInto(
        witness,
        fixture.inputs,
        fixture.values,
    ));

    var wrong_claims = fixture.claims;
    wrong_claims[7] = QM31.one();
    witness = fixture.witness();
    witness.claimed_sums = &wrong_claims;
    try expectRejected(fixture.circuit.evaluateInto(
        witness,
        fixture.inputs,
        fixture.values,
    ));

    for (0..fixture.poseidon_partials.len) |partial_index| {
        var wrong_partials = fixture.poseidon_partials;
        wrong_partials[partial_index] = wrong_partials[partial_index].add(QM31.one());
        witness = fixture.witness();
        witness.poseidon2_partials = &wrong_partials;
        try expectRejected(fixture.circuit.evaluateInto(
            witness,
            fixture.inputs,
            fixture.values,
        ));
    }

    // Keep the global roster sum unchanged so only the explicit row-34
    // partial-to-total closure catches this mutation.
    wrong_claims = fixture.claims;
    const poseidon_row = @intFromEnum(roster.Component.poseidon2);
    wrong_claims[poseidon_row] = wrong_claims[poseidon_row].add(QM31.one());
    wrong_claims[0] = wrong_claims[0].sub(QM31.one());
    witness = fixture.witness();
    witness.claimed_sums = &wrong_claims;
    try expectRejected(fixture.circuit.evaluateInto(
        witness,
        fixture.inputs,
        fixture.values,
    ));

    fixture.capture.sampled_values[fixture.capture.compositionValueOffset()] =
        fixture.capture.sampled_values[fixture.capture.compositionValueOffset()].add(QM31.one());
    try expectRejected(fixture.circuit.evaluateInto(
        fixture.witness(),
        fixture.inputs,
        fixture.values,
    ));
}

test "binary composition capture and roster preflight fail closed" {
    const allocator = std.testing.allocator;
    const manifest = try testManifest();
    var capture = try CaptureFixture.init(allocator, &manifest);
    defer capture.deinit();

    capture.column_log_sizes[0][0] += 1;
    try std.testing.expectError(
        error.InvalidTraceLogGeometry,
        subject.Session.create(allocator, &manifest, capture.view()),
    );
    capture.column_log_sizes[0][0] -= 1;

    const original = capture.sampled_points[2][7];
    capture.sampled_points[2][7] = capture.sampled_points[2][7][0..0];
    try std.testing.expectError(
        error.InvalidSampleGeometry,
        subject.Session.create(allocator, &manifest, capture.view()),
    );
    capture.sampled_points[2][7] = original;

    const poseidon_placement = manifest.placements[
        @intFromEnum(roster.Component.poseidon2)
    ].?;
    const poseidon_interaction_column: usize = poseidon_placement.interaction_offset;
    const provider_original = capture.sampled_points[
        manifest_mod.INTERACTION_TREE_INDEX
    ][poseidon_interaction_column];
    capture.sampled_points[manifest_mod.INTERACTION_TREE_INDEX][poseidon_interaction_column] =
        provider_original[0..1];
    try std.testing.expectError(
        error.InvalidSampleGeometry,
        subject.Session.create(allocator, &manifest, capture.view()),
    );
    capture.sampled_points[manifest_mod.INTERACTION_TREE_INDEX][poseidon_interaction_column] =
        provider_original;

    var partial_builder = manifest_mod.Builder{};
    _ = try partial_builder.append(testGeometry(0));
    const partial = try partial_builder.seal();
    try std.testing.expectError(
        error.InvalidManifest,
        subject.Session.create(allocator, &partial, capture.view()),
    );
}

test "binary composition session rejects incomplete order and generic provider replay" {
    const allocator = std.testing.allocator;
    const manifest = try testManifest();
    var capture = try CaptureFixture.init(allocator, &manifest);
    defer capture.deinit();
    var session = try subject.Session.create(allocator, &manifest, capture.view());
    defer session.deinit();

    var definition = try control.build(allocator);
    defer definition.deinit();
    const program = try direct.authenticate(
        &definition.arena,
        control.SEMANTIC_DIGEST,
        control.LOGICAL_INPUT_COUNT,
    );
    const relation_plan = try control_relation.authenticate(&definition);
    for (manifest.roster_rows[0..CORE_ROW_COUNT]) |row_index| {
        const component = FakeComponent{
            .log_size = LOG_SIZE,
            .placement = manifest.placements[row_index].?,
            .parameters = kindParameters(.segment_leaf),
            .direct = program,
            .relation_plan = relation_plan,
        };
        _ = try session.recordComponent(
            control_relation.Runtime,
            .segment_leaf,
            @enumFromInt(row_index),
            &component,
        );
    }
    const generic_provider = FakeComponent{
        .log_size = LOG_SIZE,
        .placement = manifest.placements[@intFromEnum(roster.Component.poseidon2)].?,
        .parameters = kindParameters(.segment_leaf),
        .direct = program,
        .relation_plan = relation_plan,
    };
    try std.testing.expectError(
        error.ProviderRequiresExactRecorder,
        session.recordComponent(
            control_relation.Runtime,
            .segment_leaf,
            .poseidon2,
            &generic_provider,
        ),
    );
    try std.testing.expectError(
        error.IncompleteProofKindProgram,
        session.finish(),
    );
}

const BuiltFixture = struct {
    allocator: std.mem.Allocator,
    capture: CaptureFixture,
    circuit: subject.Circuit,
    statement_words: [subject.STATEMENT_WORD_COUNT]M31,
    claims: [subject.ROSTER_CLAIM_COUNT]QM31,
    poseidon_partials: [poseidon_air.N_SUMS]QM31,
    relations: universal.UniversalRelations,
    composition_randomness: QM31,
    oods_seed: QM31,
    inputs: []QM31,
    values: []QM31,

    fn init(allocator: std.mem.Allocator) !BuiltFixture {
        var definition = try control.build(allocator);
        defer definition.deinit();
        const program = try direct.authenticate(
            &definition.arena,
            control.SEMANTIC_DIGEST,
            control.LOGICAL_INPUT_COUNT,
        );
        const relation_plan = try control_relation.authenticate(&definition);
        const manifest = try testManifest();
        var capture = try CaptureFixture.init(allocator, &manifest);
        errdefer capture.deinit();
        const relations = universal.UniversalRelations.dummy();
        var provider_relations = try provider.SharedProviderRelations.init(&relations);
        const poseidon_partials = testPoseidonPartials();
        var poseidon = try provider.Poseidon2Adapter.init(
            &manifest,
            LOG_SIZE,
            1,
            &provider_relations,
            &relations,
            poseidon_partials,
        );
        var range_definition = try range_bridge.build(allocator);
        defer range_definition.deinit();
        const range_binding = try range_bridge.Binding.canonical(&range_definition);
        const range_executor = try range_bridge.Executor.init(
            &range_definition,
            &range_binding,
        );
        var range = try provider.RangeCheck8x8Adapter.init(
            &range_definition,
            &range_executor,
            &manifest,
            &provider_relations,
            &relations,
            QM31.zero(),
        );
        var session = try subject.Session.create(allocator, &manifest, capture.view());
        var session_live = true;
        errdefer if (session_live) session.deinit();
        try recordPrograms(
            session,
            &manifest,
            program,
            relation_plan,
            &poseidon,
            &range,
        );
        var circuit = try session.finish();
        session_live = false;
        errdefer circuit.deinit();

        var words = [_]M31{M31.zero()} ** subject.STATEMENT_WORD_COUNT;
        words[span_statement.canonical_layout.body_tag] = M31.fromU64(
            @intFromEnum(span_statement.Tag.executed_body),
        );
        var claims = [_]QM31{QM31.zero()} ** subject.ROSTER_CLAIM_COUNT;
        claims[@intFromEnum(roster.Component.poseidon2)] =
            poseidon_partials[0].add(poseidon_partials[1]);
        claims[0] = (try parentPublicSum(&words, &relations)).neg()
            .sub(claims[@intFromEnum(roster.Component.poseidon2)]);
        const random = QM31.fromBase(M31.fromU64(13));
        const seed = QM31.fromBase(M31.fromU64(7));
        capture.sampled_values[capture.compositionValueOffset()] = try nativeAccumulation(
            program,
            relation_plan,
            .segment_leaf,
            &claims,
            poseidon_partials,
            &relations,
            &provider_relations.native,
            random,
            seed,
        );
        const inputs = try allocator.alloc(QM31, circuit.recorded.input_count);
        errdefer allocator.free(inputs);
        const values = try allocator.alloc(QM31, circuit.recorded.nodes.len);
        errdefer allocator.free(values);
        return .{
            .allocator = allocator,
            .capture = capture,
            .circuit = circuit,
            .statement_words = words,
            .claims = claims,
            .poseidon_partials = poseidon_partials,
            .relations = relations,
            .composition_randomness = random,
            .oods_seed = seed,
            .inputs = inputs,
            .values = values,
        };
    }

    fn deinit(self: *BuiltFixture) void {
        self.allocator.free(self.values);
        self.allocator.free(self.inputs);
        self.circuit.deinit();
        self.capture.deinit();
        self.* = undefined;
    }

    fn witness(self: *const BuiltFixture) subject.Witness {
        return .{
            .parent_binary_selector = true,
            .child_kind = .segment_leaf,
            .statement_words = &self.statement_words,
            .sampled_values = self.capture.sampled_values,
            .claimed_sums = &self.claims,
            .poseidon2_partials = &self.poseidon_partials,
            .relations = &self.relations,
            .composition_randomness = self.composition_randomness,
            .oods_seed = self.oods_seed,
        };
    }
};

const CaptureFixture = struct {
    allocator: std.mem.Allocator,
    sampled_points: [][][]u8,
    column_log_sizes: [][]u32,
    sampled_values: []QM31,

    const View = struct {
        sampled_points: [][][]u8,
        column_log_sizes: [][]u32,
        sampled_values: []QM31,
    };

    fn init(
        allocator: std.mem.Allocator,
        manifest: *const manifest_mod.Manifest,
    ) !CaptureFixture {
        const column_counts = [subject.TREE_COUNT]usize{
            manifest.total_preprocessed_columns,
            manifest.total_main_columns,
            manifest.total_interaction_columns,
            COMPOSITION_COLUMN_COUNT,
        };
        const points = try allocator.alloc([][]u8, subject.TREE_COUNT);
        errdefer allocator.free(points);
        const logs = try allocator.alloc([]u32, subject.TREE_COUNT);
        errdefer allocator.free(logs);
        var initialized_trees: usize = 0;
        errdefer {
            for (0..initialized_trees) |tree| {
                for (points[tree]) |column| allocator.free(column);
                allocator.free(points[tree]);
                allocator.free(logs[tree]);
            }
        }
        var sample_count: usize = 0;
        for (column_counts, 0..) |column_count, tree| {
            points[tree] = try allocator.alloc([]u8, column_count);
            logs[tree] = try allocator.alloc(u32, column_count);
            initialized_trees += 1;
            var initialized_columns: usize = 0;
            errdefer for (points[tree][0..initialized_columns]) |column|
                allocator.free(column);
            for (points[tree], 0..) |*column, index| {
                const samples = if (tree == manifest_mod.INTERACTION_TREE_INDEX)
                    interactionSamples(manifest, index)
                else
                    1;
                column.* = try allocator.alloc(u8, samples);
                initialized_columns += 1;
                @memset(column.*, 0);
                sample_count += samples;
            }
            for (logs[tree], 0..) |*log_size, column| {
                log_size.* = if (tree == subject.COMPOSITION_TREE_INDEX)
                    range_bridge.LOG_SIZE + FRI_LOG_BLOWUP
                else
                    traceColumnLog(manifest, tree, column);
            }
        }
        const values = try allocator.alloc(QM31, sample_count);
        @memset(values, QM31.zero());
        return .{
            .allocator = allocator,
            .sampled_points = points,
            .column_log_sizes = logs,
            .sampled_values = values,
        };
    }

    fn deinit(self: *CaptureFixture) void {
        self.allocator.free(self.sampled_values);
        for (self.sampled_points, self.column_log_sizes) |tree, logs| {
            for (tree) |column| self.allocator.free(column);
            self.allocator.free(tree);
            self.allocator.free(logs);
        }
        self.allocator.free(self.sampled_points);
        self.allocator.free(self.column_log_sizes);
        self.* = undefined;
    }

    fn view(self: *CaptureFixture) View {
        return .{
            .sampled_points = self.sampled_points,
            .column_log_sizes = self.column_log_sizes,
            .sampled_values = self.sampled_values,
        };
    }

    fn compositionValueOffset(self: *const CaptureFixture) usize {
        return self.sampled_values.len - COMPOSITION_COLUMN_COUNT;
    }
};

fn testManifest() !manifest_mod.Manifest {
    var builder = manifest_mod.Builder{};
    for (0..CORE_ROW_COUNT) |row| _ = try builder.append(testGeometry(row));
    _ = try builder.append(provider.Poseidon2Adapter.manifestGeometry(LOG_SIZE));
    _ = try builder.append(provider.RangeCheck8x8Adapter.manifestGeometry());
    return builder.seal();
}

fn testGeometry(row: usize) manifest_mod.Geometry {
    return .{
        .roster_row = @intCast(row),
        .log_size = LOG_SIZE,
        .preprocessed_columns = control.PREPROCESSED_COLUMN_COUNT,
        .main_columns = control.PHYSICAL_MAIN_COLUMN_COUNT,
        .interaction_columns = control.INTERACTION_COLUMN_COUNT,
        .direct_constraints = control.DIRECT_CONSTRAINT_COUNT,
        .interaction_batches = control.INTERACTION_BATCH_COUNT,
        .protocol_constraint_degree = PROTOCOL_DEGREE,
        .profiled_constraint_degree = PROTOCOL_DEGREE,
        .semantic_digest = control.SEMANTIC_DIGEST,
    };
}

fn kindParameters(kind: graph_mod.ProofKind) [control.PROOF_KIND_PARAMETER_COUNT]M31 {
    const selectors = kind.selectors();
    return selectors[0..control.PROOF_KIND_PARAMETER_COUNT].*;
}

fn recordPrograms(
    session: *subject.Session,
    manifest: *const manifest_mod.Manifest,
    program: direct.Program,
    relation_plan: control_relation.Plan,
    poseidon: *const provider.Poseidon2Adapter,
    range: *const provider.RangeCheck8x8Adapter,
) !void {
    inline for (std.meta.fields(graph_mod.ProofKind)) |field| {
        const kind: graph_mod.ProofKind = @enumFromInt(field.value);
        for (manifest.roster_rows[0..CORE_ROW_COUNT]) |row_index| {
            const component = FakeComponent{
                .log_size = LOG_SIZE,
                .placement = manifest.placements[row_index].?,
                .parameters = kindParameters(kind),
                .direct = program,
                .relation_plan = relation_plan,
            };
            try std.testing.expectEqual(
                @as(usize, control.DIRECT_CONSTRAINT_COUNT +
                    control.INTERACTION_BATCH_COUNT),
                try session.recordComponent(
                    control_relation.Runtime,
                    kind,
                    @enumFromInt(row_index),
                    &component,
                ),
            );
        }
        try std.testing.expectEqual(
            @as(usize, provider.POSEIDON_DIRECT_CONSTRAINT_COUNT +
                provider.POSEIDON_INTERACTION_BATCH_COUNT),
            try session.recordPoseidonProvider(kind, poseidon),
        );
        try std.testing.expectEqual(
            @as(usize, provider.RANGE_DIRECT_CONSTRAINT_COUNT +
                provider.RANGE_INTERACTION_BATCH_COUNT),
            try session.recordRangeCheck8x8Provider(kind, range),
        );
    }
}

fn testPoseidonPartials() [poseidon_air.N_SUMS]QM31 {
    return .{
        QM31.fromU32Unchecked(2, 3, 5, 7),
        QM31.fromU32Unchecked(11, 13, 17, 19),
    };
}

fn interactionSamples(manifest: *const manifest_mod.Manifest, column: usize) usize {
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const placement = manifest.placements[row].?;
        const start: usize = placement.interaction_offset;
        const end = start + placement.geometry.interaction_columns;
        if (column >= start and column < end) {
            if (row == @intFromEnum(roster.Component.poseidon2)) return 2;
            return if (column >= end - 4) 2 else 1;
        }
    }
    unreachable;
}

fn traceColumnLog(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    column: usize,
) u32 {
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const placement = manifest.placements[row].?;
        const range = switch (tree) {
            manifest_mod.PREPROCESSED_TREE_INDEX => .{
                placement.preprocessed_offset,
                placement.geometry.preprocessed_columns,
            },
            manifest_mod.MAIN_TREE_INDEX => .{
                placement.main_offset,
                placement.geometry.main_columns,
            },
            manifest_mod.INTERACTION_TREE_INDEX => .{
                placement.interaction_offset,
                placement.geometry.interaction_columns,
            },
            else => unreachable,
        };
        const start: usize = range[0];
        const end = start + range[1];
        if (column >= start and column < end)
            return placement.geometry.log_size + FRI_LOG_BLOWUP;
    }
    unreachable;
}

fn parentPublicSum(
    words: *const [subject.STATEMENT_WORD_COUNT]M31,
    relations: *const universal.UniversalRelations,
) !QM31 {
    const challenge = relations.get(.recursion_statement_word);
    var sum = QM31.zero();
    for (words, 0..) |word, index| {
        const tuple = [_]M31{
            M31.fromU64(@import("air/statement_input.zig").PARENT_STATEMENT_SCOPE),
            M31.fromU64(index),
            word,
        };
        sum = sum.add(try (try challenge.combineBase(&tuple)).inv());
    }
    return sum;
}

fn nativeAccumulation(
    program: direct.Program,
    relation_plan: control_relation.Plan,
    kind: graph_mod.ProofKind,
    claims: *const [subject.ROSTER_CLAIM_COUNT]QM31,
    poseidon_partials: [poseidon_air.N_SUMS]QM31,
    relations: *const universal.UniversalRelations,
    native_relations: anytype,
    random: QM31,
    oods_seed: QM31,
) !QM31 {
    var row = [_]QM31{QM31.zero()} ** control.LOGICAL_INPUT_COUNT;
    const parameters = kindParameters(kind);
    for (parameters, 0..) |parameter, index|
        row[control.PREPROCESSED_COLUMN_COUNT + index] = QM31.fromBase(parameter);
    var direct_scratch: [direct.MAX_NODES]QM31 = undefined;
    var direct_roots: [control.DIRECT_CONSTRAINT_COUNT]QM31 = undefined;
    try program.evaluateSecureInto(&row, &direct_scratch, &direct_roots);
    const pairs = try relation_plan.preparedSecureRowPairs(row, relations);
    const point = circle.secureFieldPointFromRandomSeed(oods_seed);
    const core_point = point.repeatedDouble(range_bridge.LOG_SIZE - LOG_SIZE);
    const core_denominator = try constraints.cosetVanishing(
        QM31,
        canonic.CanonicCoset.new(LOG_SIZE).coset(),
        core_point,
    ).inv();
    const n = M31.fromU64(@as(u64, 1) << @intCast(LOG_SIZE));
    var accumulation = QM31.zero();
    for (0..CORE_ROW_COUNT) |row_index| {
        for (direct_roots) |root|
            accumulation = accumulation.mul(random).add(root.mul(core_denominator));
        for (pairs, 0..) |pair, batch| {
            const final = batch + 1 == pairs.len;
            const shift = if (final)
                try claims[row_index].divM31(n)
            else
                QM31.zero();
            const pair_denominator = pair.d1.mul(pair.d2);
            const numerator = pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1));
            const root = shift.mul(pair_denominator).sub(numerator);
            accumulation = accumulation.mul(random).add(root.mul(core_denominator));
        }
    }

    const poseidon_main = [_]QM31{QM31.zero()} ** poseidon_air.N_MAIN_COLUMNS;
    const poseidon_current = [_]QM31{QM31.zero()} ** poseidon_air.N_SUMS;
    const poseidon_previous = [_]QM31{QM31.zero()} ** poseidon_air.N_SUMS;
    const poseidon_direct = poseidon_air.evaluate(poseidon_main);
    const poseidon_interaction = poseidon_air.interactionConstraints(
        poseidon_main,
        QM31.zero(),
        poseidon_current,
        poseidon_previous,
        poseidon_partials,
        native_relations,
    );
    for (poseidon_direct) |root|
        accumulation = accumulation.mul(random).add(root.mul(core_denominator));
    for (poseidon_interaction) |root|
        accumulation = accumulation.mul(random).add(root.mul(core_denominator));

    const range_denominator = try constraints.cosetVanishing(
        QM31,
        canonic.CanonicCoset.new(range_bridge.LOG_SIZE).coset(),
        point,
    ).inv();
    const range_tuple = [_]QM31{ QM31.zero(), QM31.zero() };
    const range_root = try table_interaction.evaluate(
        .range_check_8_8,
        &range_tuple,
        QM31.zero(),
        QM31.zero(),
        QM31.zero(),
        QM31.zero(),
        claims[@intFromEnum(roster.Component.range_check_8_8)],
        native_relations,
    );
    accumulation = accumulation.mul(random).add(range_root.mul(range_denominator));
    return accumulation;
}

fn expectRejected(result: anyerror!void) !void {
    if (result) |_| return error.ExpectedCompositionRejection else |err| {
        try std.testing.expect(err == error.UnsatisfiedCircuit or
            err == error.DivisionByZero);
    }
}
