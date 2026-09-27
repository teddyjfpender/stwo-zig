//! Exactness, schedule, mutation, and performance gates for universal row 9.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const degree = @import("../../air/lang/degree.zig");
const digest = @import("../../air/lang/digest.zig");
const relation = @import("../../air/lang/relation.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const types = @import("../../air/lang/types.zig");
const component = @import("verifier_randomness.zig");
const interaction_mod = @import("verifier_randomness_relation.zig");
const schedule = @import("verifier_schedule.zig");
const support = @import("test_support.zig");
const universal = @import("universal_challenges.zig");
const witness = @import("verifier_randomness_witness.zig");

const SECURE_DRAW_COUNT: usize = 5;
const QUERY_DRAW_COUNT: usize = 25;
const DRAW_COUNT: usize = SECURE_DRAW_COUNT + QUERY_DRAW_COUNT;
const ROW_COUNT: usize = 3 * DRAW_COUNT;

test "R-012 verifier randomness preserves exact row-9 source geometry and seals" {
    try std.testing.expectEqualStrings(
        "59172a201bd01f2f4b699bc2f7d4442d8ee81597",
        &component.STARK_V_REVISION,
    );
    try std.testing.expectEqualStrings(
        "edc6ddb6858636253859ede01812f23ceca576177c0e8eeb855c2dcdab1e28c8",
        component.STARK_V_SOURCE_SHA256_HEX,
    );
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    try std.testing.expectEqual(@as(usize, 9), definition.main.physical().len);
    try std.testing.expectEqual(@as(usize, 21), definition.preprocessed.physical().len);
    try std.testing.expectEqual(@as(usize, 2), definition.parameters.physical().len);
    try std.testing.expectEqual(@as(usize, 9), definition.constraints.len);
    try std.testing.expectEqual(@as(usize, 9), definition.events.len);
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
    const plan = try interaction_mod.authenticate(&definition);
    try std.testing.expectEqual(@as(usize, 5), interaction_mod.Runtime.BATCH_COUNT);
    try std.testing.expectEqual(@as(usize, 20), interaction_mod.Runtime.INTERACTION_COLUMN_COUNT);
    try std.testing.expectEqual(
        relation.Domain.recursion_transcript_draw_output,
        plan.events[0].domain,
    );
    try std.testing.expectEqual(relation.Role.consume, plan.events[0].role);
    for (plan.events[1..]) |event| {
        try std.testing.expectEqual(
            relation.Domain.recursion_verifier_randomness_word,
            event.domain,
        );
        try std.testing.expectEqual(relation.Role.emit, event.role);
    }
    const binding = try witness.Binding.canonical(&definition);
    _ = try witness.Executor.init(&definition, &binding);
    try std.testing.expectEqualStrings(
        witness.BINDING_DIGEST_HEX,
        &std.fmt.bytesToHex(binding.identityDigest(), .lower),
    );
}

test "R-012 verifier randomness static profile is exact" {
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
    try std.testing.expectEqual(@as(u32, 32), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 9), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 9), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 5), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 20), profile.interaction_columns);
    try std.testing.expectEqual(@as(u32, 3), profile.maximum_logical_constraint_degree);
    try std.testing.expectEqual(@as(?u32, 3), profile.maximum_modeled_interaction_degree);
    try std.testing.expectEqual(@as(u32, 87), profile.expression_dag_nodes);
    try std.testing.expectEqual(@as(u32, 94), profile.expression_dag_edges);
    try std.testing.expectEqual(@as(u32, 13), profile.expression_dag_shared_nodes);
    try std.testing.expectEqual(@as(u32, 0), profile.nodes_outside_constraint_effect_closure);
    try std.testing.expectEqualStrings(
        component.STATIC_PROFILE_DIGEST_HEX,
        &std.fmt.bytesToHex(profile.profile_digest, .lower),
    );
}

test "R-012 verifier randomness preprocessing derives exact secure and query draws" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var preprocessing = try witness.Preprocessed.init(
        measured.allocator(),
        &fixture.vm,
        &fixture.recursion,
    );
    defer preprocessing.deinit();
    try std.testing.expectEqual(@as(usize, 1), measured.alloc_index);
    try preprocessing.validateAgainst(&fixture.vm, &fixture.recursion);
    try std.testing.expectEqual(@as(usize, DRAW_COUNT), preprocessing.vm_randomness_count);
    try std.testing.expectEqual(
        @as(usize, DRAW_COUNT),
        preprocessing.recursion_randomness_count,
    );
    try std.testing.expectEqual(@as(usize, ROW_COUNT), preprocessing.rows.len);
    try std.testing.expectEqual(@as(u32, 7), preprocessing.log_size);

    for (0..3) |lane| {
        const rows = preprocessing.rows[lane * DRAW_COUNT ..][0..DRAW_COUNT];
        try std.testing.expectEqual(@as(u32, @intCast(lane)), rows[0].verifier_id);
        try expectDescriptor(rows[0], .composition_randomness, 0, false, 4, 1);
        try expectDescriptor(rows[1], .oods_point, 0, false, 4, 2);
        try expectDescriptor(rows[2], .deep_randomness, 0, false, 4, 1);
        try expectDescriptor(rows[3], .fri_alpha, 0, false, 4, 1);
        try expectDescriptor(rows[4], .fri_alpha, 1, false, 4, 1);
        for (rows[SECURE_DRAW_COUNT..], 0..) |row, block| {
            const item_base: u32 = @intCast(block * component.WORD_COUNT);
            const word_count: u32 = @intCast(@min(
                component.WORD_COUNT,
                @as(usize, 193) - block * component.WORD_COUNT,
            ));
            try expectDescriptor(row, .raw_query, item_base, true, word_count, 1);
        }
    }

    preprocessing.rows[0].kind = .raw_query;
    try std.testing.expectError(
        error.ScheduleAuthorityMismatch,
        preprocessing.validateAgainst(&fixture.vm, &fixture.recursion),
    );
}

test "R-012 verifier randomness witnesses satisfy all modes and reject inactive words" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var preprocessing = try witness.Preprocessed.init(
        std.testing.allocator,
        &fixture.vm,
        &fixture.recursion,
    );
    defer preprocessing.deinit();
    var draws = try OwnedDraws.init(std.testing.allocator, &preprocessing);
    defer draws.deinit();

    const cases = [_]witness.DrawWitness{
        .{ .segment_leaf = draws.segment },
        .{ .binary_node = .{ .left = draws.left, .right = draws.right } },
        .empty_leaf,
    };
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    for (cases) |draw_witness| {
        var main = try witness.MainWitness.init(
            std.testing.allocator,
            &preprocessing,
            draw_witness,
        );
        defer main.deinit();
        try main.validateAgainst(&preprocessing);
        for (main.rows, preprocessing.rows) |row, metadata| {
            try expectSatisfied(
                &definition,
                witness.logicalInputs(row, metadata, main.proof_kind),
            );
            const expected_active = switch (main.proof_kind) {
                .segment_leaf => metadata.verifier_id == witness.SEGMENT_VERIFIER_ID,
                .binary_node => metadata.verifier_id != witness.SEGMENT_VERIFIER_ID,
                .empty_leaf => false,
            };
            try std.testing.expectEqual(
                @as(u32, @intFromBool(expected_active)),
                row.enabler,
            );
        }
    }

    var inactive = witness.MainRow{
        .enabler = 0,
        .outputs = [_]M31{M31.zero()} ** component.WORD_COUNT,
    };
    for (0..component.WORD_COUNT) |word| {
        inactive.outputs[word] = M31.one();
        try expectRejected(
            &definition,
            witness.logicalInputs(inactive, preprocessing.rows[DRAW_COUNT], .segment_leaf),
        );
        inactive.outputs[word] = M31.zero();
    }
}

test "R-012 verifier randomness relation tuples preserve kind item limb and use count" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var preprocessing = try witness.Preprocessed.init(
        std.testing.allocator,
        &fixture.vm,
        &fixture.recursion,
    );
    defer preprocessing.deinit();
    var draws = try OwnedDraws.init(std.testing.allocator, &preprocessing);
    defer draws.deinit();
    var main = try witness.MainWitness.init(
        std.testing.allocator,
        &preprocessing,
        .{ .segment_leaf = draws.segment },
    );
    defer main.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);

    for (preprocessing.rows[0..DRAW_COUNT], main.rows[0..DRAW_COUNT], 0..) |
        metadata,
        row,
        draw_index,
    | {
        const entries = try plan.entries(
            &definition.arena,
            component.SEMANTIC_DIGEST,
            definition.events,
            witness.logicalInputs(row, metadata, .segment_leaf),
        );
        try std.testing.expect(entries[0].numerator.eql(QM31.one().neg()));
        for (entries[1..], 0..) |entry, word| {
            const expected_item = metadata.item_base +
                metadata.query_items * @as(u32, @intCast(word));
            const expected_limb = (1 - metadata.query_items) *
                @as(u32, @intCast(word));
            const expected_multiplicity = metadata.multiplicities[word];
            try std.testing.expect(entry.numerator.eql(QM31.fromBase(
                M31.fromCanonical(expected_multiplicity),
            )));
            try std.testing.expect(entry.values[0].eql(QM31.zero()));
            try std.testing.expect(entry.values[1].eql(QM31.fromBase(
                M31.fromCanonical(@intFromEnum(metadata.kind)),
            )));
            try std.testing.expect(entry.values[2].eql(QM31.fromBase(
                M31.fromCanonical(expected_item),
            )));
            try std.testing.expect(entry.values[3].eql(QM31.fromBase(
                M31.fromCanonical(expected_limb),
            )));
            try std.testing.expect(entry.values[4].eql(QM31.fromBase(
                draws.segment[draw_index][word],
            )));
        }
    }

    const inactive = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        witness.logicalInputs(
            main.rows[DRAW_COUNT],
            preprocessing.rows[DRAW_COUNT],
            .segment_leaf,
        ),
    );
    for (inactive) |entry| try std.testing.expect(entry.numerator.isZero());
}

test "R-012 verifier randomness writers are allocation-free padded and atomic" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var preprocessing = try witness.Preprocessed.init(
        std.testing.allocator,
        &fixture.vm,
        &fixture.recursion,
    );
    defer preprocessing.deinit();
    var draws = try OwnedDraws.init(std.testing.allocator, &preprocessing);
    defer draws.deinit();

    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var main = try witness.MainWitness.init(
        measured.allocator(),
        &preprocessing,
        .{ .binary_node = .{ .left = draws.left, .right = draws.right } },
    );
    defer main.deinit();
    try std.testing.expectEqual(@as(usize, 1), measured.alloc_index);

    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    try assertWriter(
        witness.PREPROCESSED_COLUMN_COUNT,
        &executor,
        &preprocessing,
        &fixture,
    );
    try assertWriter(
        witness.MAIN_COLUMN_COUNT,
        &executor,
        &main,
        &preprocessing,
    );

    var changed = binding;
    changed.main[0] = changed.main[1];
    try std.testing.expectError(
        error.BindingMismatch,
        witness.Executor.init(&definition, &changed),
    );
}

test "R-012 verifier randomness interaction is bounded and releases every OOM path" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var preprocessing = try witness.Preprocessed.init(
        std.testing.allocator,
        &fixture.vm,
        &fixture.recursion,
    );
    defer preprocessing.deinit();
    var draws = try OwnedDraws.init(std.testing.allocator, &preprocessing);
    defer draws.deinit();
    var main = try witness.MainWitness.init(
        std.testing.allocator,
        &preprocessing,
        .{ .segment_leaf = draws.segment },
    );
    defer main.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    const rows = try std.testing.allocator.alloc(interaction_mod.Row, main.rows.len);
    defer std.testing.allocator.free(rows);
    for (rows, main.rows, preprocessing.rows) |*target, main_row, metadata|
        target.* = witness.logicalInputs(main_row, metadata, .segment_leaf);
    const relations = universal.UniversalRelations.dummy();
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    {
        var interaction = try plan.generateInteraction(
            measured.allocator(),
            &definition.arena,
            component.SEMANTIC_DIGEST,
            definition.events,
            rows,
            preprocessing.log_size,
            &relations,
        );
        defer interaction.deinit(measured.allocator());
        try std.testing.expectEqual(@as(usize, 5), measured.alloc_index);
        try plan.validateInteraction(
            std.testing.allocator,
            &definition.arena,
            component.SEMANTIC_DIGEST,
            definition.events,
            rows,
            preprocessing.log_size,
            &relations,
            &interaction,
        );
    }
    try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        componentFailureCase,
        .{},
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        preprocessingFailureCase,
        .{ &fixture.vm, &fixture.recursion },
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        mainFailureCase,
        .{ &preprocessing, witness.DrawWitness{ .segment_leaf = draws.segment } },
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        interactionFailureCase,
        .{ &definition, &plan, rows, preprocessing.log_size, &relations },
    );
}

const Fixture = struct {
    vm: schedule.Plan,
    recursion: schedule.Plan,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const shape = try testShape();
        var vm = try schedule.Plan.init(
            allocator,
            try schedule.ProgramSpec.init(.vm, 4, 2, 3, 2),
            shape,
        );
        errdefer vm.deinit();
        return .{
            .vm = vm,
            .recursion = try schedule.Plan.init(
                allocator,
                try schedule.ProgramSpec.init(.recursion, 4, 0, 3, 2),
                shape,
            ),
        };
    }

    fn deinit(self: *Fixture) void {
        self.recursion.deinit();
        self.vm.deinit();
        self.* = undefined;
    }
};

const OwnedDraws = struct {
    allocator: std.mem.Allocator,
    segment: []witness.Draw,
    left: []witness.Draw,
    right: []witness.Draw,

    fn init(
        allocator: std.mem.Allocator,
        preprocessing: *const witness.Preprocessed,
    ) !OwnedDraws {
        const segment = try allocator.alloc(
            witness.Draw,
            preprocessing.vm_randomness_count,
        );
        errdefer allocator.free(segment);
        const left = try allocator.alloc(
            witness.Draw,
            preprocessing.recursion_randomness_count,
        );
        errdefer allocator.free(left);
        const right = try allocator.alloc(
            witness.Draw,
            preprocessing.recursion_randomness_count,
        );
        errdefer allocator.free(right);
        fillDraws(segment, 100);
        fillDraws(left, 10_000);
        fillDraws(right, 20_000);
        return .{
            .allocator = allocator,
            .segment = segment,
            .left = left,
            .right = right,
        };
    }

    fn deinit(self: *OwnedDraws) void {
        self.allocator.free(self.right);
        self.allocator.free(self.left);
        self.allocator.free(self.segment);
        self.* = undefined;
    }
};

fn fillDraws(draws: []witness.Draw, offset: u32) void {
    for (draws, 0..) |*draw, draw_index| {
        for (draw, 0..) |*word, word_index| {
            word.* = M31.fromCanonical(
                offset + @as(u32, @intCast(17 * draw_index + word_index)),
            );
        }
    }
}

fn expectDescriptor(
    row: witness.PreprocessedRow,
    kind: witness.Kind,
    item_base: u32,
    query_items: bool,
    word_count: u32,
    semantic_use_count: u32,
) !void {
    try std.testing.expectEqual(kind, row.kind);
    try std.testing.expectEqual(item_base, row.item_base);
    try std.testing.expectEqual(@as(u32, @intFromBool(query_items)), row.query_items);
    for (row.multiplicities, 0..) |multiplicity, word| {
        try std.testing.expectEqual(
            semantic_use_count * @as(u32, @intFromBool(word < word_count)),
            multiplicity,
        );
    }
}

fn testShape() !@import("../fixed_profile.zig").ProofShapeV1 {
    const fixed_profile = @import("../fixed_profile.zig");
    const protocol = @import("../protocol.zig");
    const channel = @import("../poseidon2_channel.zig");
    const fri = try fixed_profile.FriSchedule.init(8, protocol.PCS_CONFIG.fri_config);
    return .{
        .air_program_id = channel.hashBytes("verifier-randomness-air", 0x5450),
        .preprocessing_id = channel.hashBytes("verifier-randomness-preprocessing", 0x5450),
        .table_layout_id = channel.hashBytes("verifier-randomness-layout", 0x5450),
        .table_count = 16,
        .claimed_sum_count = 4,
        .sampled_value_count = 8,
        .preprocessed_column_count = 4,
        .tree_column_counts = .{ 4, 4, 4, 4 },
        .tree_heights = .{ 9, 9, 9, 9 },
        .column_log_degree = 8,
        .proof_wire_bytes = 1024,
        .fri = fri,
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

fn expectRejected(
    definition: *const component.Definition,
    inputs: [component.LOGICAL_INPUT_COUNT]M31,
) !void {
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &inputs);
    defer std.testing.allocator.free(values);
    for (definition.constraints) |constraint_id| {
        const constraint = definition.arena.constraint(constraint_id).?;
        if (!values[types.idIndex(constraint.root)].isZero()) return;
    }
    return error.TestExpectedConstraintFailure;
}

fn assertWriter(
    comptime count: usize,
    executor: *const witness.Executor,
    source_value: anytype,
    authority: anytype,
) !void {
    const log_size = if (count == witness.PREPROCESSED_COLUMN_COUNT)
        source_value.log_size
    else
        authority.log_size;
    const size = @as(usize, 1) << @intCast(log_size);
    const storage = try std.testing.allocator.alloc(M31, count * size);
    defer std.testing.allocator.free(storage);
    var columns: [count][]M31 = undefined;
    splitColumns(count, size, storage, &columns);
    if (count == witness.PREPROCESSED_COLUMN_COUNT)
        try executor.generatePreprocessedInto(
            source_value,
            &columns,
            &authority.vm,
            &authority.recursion,
        )
    else
        try executor.generateMainInto(source_value, authority, &columns);
    for (columns) |column| for (column[source_value.rows.len..]) |padding|
        try std.testing.expect(padding.isZero());

    const sentinel = M31.fromCanonical(12345);
    @memset(storage, sentinel);
    var malformed = columns;
    malformed[0] = malformed[0][0 .. size - 1];
    if (count == witness.PREPROCESSED_COLUMN_COUNT)
        try std.testing.expectError(
            error.InvalidTraceShape,
            executor.generatePreprocessedInto(
                source_value,
                &malformed,
                &authority.vm,
                &authority.recursion,
            ),
        )
    else
        try std.testing.expectError(
            error.InvalidTraceShape,
            executor.generateMainInto(source_value, authority, &malformed),
        );
    for (storage) |value| try std.testing.expect(value.eql(sentinel));

    var aliased = columns;
    aliased[1] = aliased[0];
    if (count == witness.PREPROCESSED_COLUMN_COUNT)
        try std.testing.expectError(
            error.AliasedDestination,
            executor.generatePreprocessedInto(
                source_value,
                &aliased,
                &authority.vm,
                &authority.recursion,
            ),
        )
    else
        try std.testing.expectError(
            error.AliasedDestination,
            executor.generateMainInto(source_value, authority, &aliased),
        );
    for (storage) |value| try std.testing.expect(value.eql(sentinel));
}

fn splitColumns(
    comptime count: usize,
    size: usize,
    storage: []M31,
    columns: *[count][]M31,
) void {
    for (columns, 0..) |*column, index| column.* = storage[index * size ..][0..size];
}

fn componentFailureCase(allocator: std.mem.Allocator) !void {
    var definition = try component.build(allocator);
    defer definition.deinit();
}

fn preprocessingFailureCase(
    allocator: std.mem.Allocator,
    vm: *const schedule.Plan,
    recursion: *const schedule.Plan,
) !void {
    var preprocessing = try witness.Preprocessed.init(allocator, vm, recursion);
    defer preprocessing.deinit();
}

fn mainFailureCase(
    allocator: std.mem.Allocator,
    preprocessing: *const witness.Preprocessed,
    draws: witness.DrawWitness,
) !void {
    var main = try witness.MainWitness.init(allocator, preprocessing, draws);
    defer main.deinit();
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
