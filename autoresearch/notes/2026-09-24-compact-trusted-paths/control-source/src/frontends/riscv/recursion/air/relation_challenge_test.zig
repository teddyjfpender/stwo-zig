//! Exactness, schedule, mutation, and performance gates for universal row 8.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const degree = @import("../../air/lang/degree.zig");
const digest = @import("../../air/lang/digest.zig");
const relation = @import("../../air/lang/relation.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const types = @import("../../air/lang/types.zig");
const component = @import("relation_challenge.zig");
const interaction_mod = @import("relation_challenge_relation.zig");
const schedule = @import("verifier_schedule.zig");
const support = @import("test_support.zig");
const universal = @import("universal_challenges.zig");
const witness = @import("relation_challenge_witness.zig");

const CHALLENGE_COUNT: usize = 4;
const ROW_COUNT: usize = 3 * CHALLENGE_COUNT;

test "R-012 relation challenge preserves exact row-8 geometry and seals" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    try std.testing.expectEqual(@as(usize, 9), definition.main.physical().len);
    try std.testing.expectEqual(@as(usize, 12), definition.preprocessed.physical().len);
    try std.testing.expectEqual(@as(usize, 4), definition.parameters.physical().len);
    try std.testing.expectEqual(@as(usize, 9), definition.constraints.len);
    try std.testing.expectEqual(@as(usize, 17), definition.events.len);
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
    try std.testing.expectEqual(@as(usize, 9), interaction_mod.Runtime.BATCH_COUNT);
    try std.testing.expectEqual(@as(usize, 36), interaction_mod.Runtime.INTERACTION_COLUMN_COUNT);
    try std.testing.expectEqual(
        relation.Domain.recursion_transcript_draw_output,
        plan.events[0].domain,
    );
    try std.testing.expectEqual(relation.Role.consume, plan.events[0].role);
    for (plan.events[1..]) |event| {
        try std.testing.expectEqual(
            relation.Domain.recursion_relation_challenge_word,
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

test "R-012 relation challenge static profile is exact" {
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
    try std.testing.expectEqual(@as(u32, 25), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 9), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 17), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 9), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 36), profile.interaction_columns);
    try std.testing.expectEqual(@as(u32, 3), profile.maximum_logical_constraint_degree);
    try std.testing.expectEqual(@as(?u32, 3), profile.maximum_modeled_interaction_degree);
    try std.testing.expectEqual(@as(u32, 48), profile.expression_dag_nodes);
    try std.testing.expectEqual(@as(u32, 30), profile.expression_dag_edges);
    try std.testing.expectEqual(@as(u32, 2), profile.expression_dag_shared_nodes);
    try std.testing.expectEqual(@as(u32, 0), profile.nodes_outside_constraint_effect_closure);
    try std.testing.expectEqualStrings(
        component.STATIC_PROFILE_DIGEST_HEX,
        &std.fmt.bytesToHex(profile.profile_digest, .lower),
    );
}

test "R-012 relation challenge preprocessing derives canonical three-lane schedule" {
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
    try std.testing.expectEqual(@as(usize, ROW_COUNT), preprocessing.rows.len);
    try std.testing.expectEqual(@as(u32, 4), preprocessing.log_size);
    for (preprocessing.rows, 0..) |row, index| {
        const lane = index / CHALLENGE_COUNT;
        const challenge: u32 = @intCast(index % CHALLENGE_COUNT);
        try std.testing.expectEqual(@as(u32, @intCast(lane)), row.verifier_id);
        try std.testing.expectEqual(challenge, row.challenge);
        try std.testing.expectEqual(challenge, row.args[0]);
        try std.testing.expectEqual(@as(u32, 7), row.tag);
        try std.testing.expectEqual(
            @as(u32, @intFromBool(lane == 0)),
            row.public_logup_mask,
        );
    }
    preprocessing.rows[0].challenge = 1;
    try std.testing.expectError(
        error.ScheduleAuthorityMismatch,
        preprocessing.validateAgainst(&fixture.vm, &fixture.recursion),
    );
}

test "R-012 relation challenge witnesses satisfy every proof kind" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var preprocessing = try witness.Preprocessed.init(
        std.testing.allocator,
        &fixture.vm,
        &fixture.recursion,
    );
    defer preprocessing.deinit();
    const draws = fixtureDraws();
    const cases = [_]witness.DrawWitness{
        .{ .segment_leaf = &draws.segment },
        .{ .binary_node = .{ .left = &draws.left, .right = &draws.right } },
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
            const logical = witness.logicalInputs(row, metadata, main.proof_kind);
            try expectSatisfied(&definition, logical);
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
            witness.logicalInputs(inactive, preprocessing.rows[CHALLENGE_COUNT], .segment_leaf),
        );
        inactive.outputs[word] = M31.zero();
    }
}

test "R-012 relation challenge relation fan-out is exact and lane scoped" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var preprocessing = try witness.Preprocessed.init(
        std.testing.allocator,
        &fixture.vm,
        &fixture.recursion,
    );
    defer preprocessing.deinit();
    const draws = fixtureDraws();
    var main = try witness.MainWitness.init(
        std.testing.allocator,
        &preprocessing,
        .{ .segment_leaf = &draws.segment },
    );
    defer main.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    for (0..CHALLENGE_COUNT) |challenge| {
        const entries = try plan.entries(
            &definition.arena,
            component.SEMANTIC_DIGEST,
            definition.events,
            witness.logicalInputs(
                main.rows[challenge],
                preprocessing.rows[challenge],
                .segment_leaf,
            ),
        );
        try std.testing.expect(entries[0].numerator.eql(QM31.one().neg()));
        for (0..component.WORD_COUNT) |word| {
            const air = entries[1 + 2 * word];
            const public = entries[2 + 2 * word];
            try std.testing.expect(air.numerator.eql(QM31.one()));
            try std.testing.expect(public.numerator.eql(
                if (challenge < 4) QM31.one() else QM31.zero(),
            ));
            try std.testing.expect(air.values[0].eql(QM31.zero()));
            try std.testing.expect(air.values[1].eql(QM31.one()));
            try std.testing.expect(public.values[1].eql(QM31.zero()));
            try std.testing.expect(air.values[2].eql(QM31.fromBase(
                M31.fromCanonical(@intCast(challenge)),
            )));
            try std.testing.expect(air.values[3].eql(QM31.fromBase(
                M31.fromCanonical(@intCast(word)),
            )));
            try std.testing.expect(air.values[4].eql(QM31.fromBase(
                draws.segment[challenge][word],
            )));
        }
    }
    const inactive = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        witness.logicalInputs(
            main.rows[CHALLENGE_COUNT],
            preprocessing.rows[CHALLENGE_COUNT],
            .segment_leaf,
        ),
    );
    for (inactive) |entry| try std.testing.expect(entry.numerator.isZero());
}

test "R-012 relation challenge writers are allocation-free padded and atomic" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var preprocessing = try witness.Preprocessed.init(
        std.testing.allocator,
        &fixture.vm,
        &fixture.recursion,
    );
    defer preprocessing.deinit();
    const draws = fixtureDraws();
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var main = try witness.MainWitness.init(
        measured.allocator(),
        &preprocessing,
        .{ .binary_node = .{ .left = &draws.left, .right = &draws.right } },
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

test "R-012 relation challenge interaction is bounded and releases all OOM paths" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var preprocessing = try witness.Preprocessed.init(
        std.testing.allocator,
        &fixture.vm,
        &fixture.recursion,
    );
    defer preprocessing.deinit();
    const draws = fixtureDraws();
    var main = try witness.MainWitness.init(
        std.testing.allocator,
        &preprocessing,
        .{ .segment_leaf = &draws.segment },
    );
    defer main.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    var rows: [ROW_COUNT]interaction_mod.Row = undefined;
    for (&rows, main.rows, preprocessing.rows) |*target, main_row, metadata|
        target.* = witness.logicalInputs(main_row, metadata, .segment_leaf);
    const relations = universal.UniversalRelations.dummy();
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    {
        var interaction = try plan.generateInteraction(
            measured.allocator(),
            &definition.arena,
            component.SEMANTIC_DIGEST,
            definition.events,
            &rows,
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
            &rows,
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
        .{ &preprocessing, witness.DrawWitness{ .segment_leaf = &draws.segment } },
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        interactionFailureCase,
        .{ &definition, &plan, &rows, preprocessing.log_size, &relations },
    );
}

const Fixture = struct {
    vm: schedule.Plan,
    recursion: schedule.Plan,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const shape = try testShape();
        var vm = try schedule.Plan.init(
            allocator,
            try schedule.ProgramSpec.init(.vm, CHALLENGE_COUNT, 2, 3, 2),
            shape,
        );
        errdefer vm.deinit();
        return .{
            .vm = vm,
            .recursion = try schedule.Plan.init(
                allocator,
                try schedule.ProgramSpec.init(.recursion, CHALLENGE_COUNT, 0, 3, 2),
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

const DrawFixture = struct {
    segment: [CHALLENGE_COUNT]witness.Draw,
    left: [CHALLENGE_COUNT]witness.Draw,
    right: [CHALLENGE_COUNT]witness.Draw,
};

fn fixtureDraws() DrawFixture {
    var result: DrawFixture = undefined;
    for (&result.segment, &result.left, &result.right, 0..) |
        *segment,
        *left,
        *right,
        challenge,
    | {
        for (0..component.WORD_COUNT) |word| {
            segment[word] = M31.fromCanonical(@intCast(100 + 17 * challenge + word));
            left[word] = M31.fromCanonical(@intCast(300 + 17 * challenge + word));
            right[word] = M31.fromCanonical(@intCast(500 + 17 * challenge + word));
        }
    }
    return result;
}

fn testShape() !@import("../fixed_profile.zig").ProofShapeV1 {
    const fixed_profile = @import("../fixed_profile.zig");
    const protocol = @import("../protocol.zig");
    const channel = @import("../poseidon2_channel.zig");
    const fri = try fixed_profile.FriSchedule.init(8, protocol.PCS_CONFIG.fri_config);
    return .{
        .air_program_id = channel.hashBytes("relation-challenge-air", 0x5450),
        .preprocessing_id = channel.hashBytes("relation-challenge-preprocessing", 0x5450),
        .table_layout_id = channel.hashBytes("relation-challenge-layout", 0x5450),
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
