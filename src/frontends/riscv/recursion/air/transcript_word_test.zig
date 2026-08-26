//! Exactness, schedule, source-rigidity, and performance gates for row 4.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const QM31 = stwo_core.fields.qm31.QM31;
const degree = @import("../../air/lang/degree.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const types = @import("../../air/lang/types.zig");
const poseidon2 = @import("../../air/memory_commitment/poseidon2.zig");
const fixed_profile = @import("../fixed_profile.zig");
const protocol = @import("../protocol.zig");
const channel = @import("../poseidon2_channel.zig");
const component = @import("transcript_word.zig");
const interaction_mod = @import("transcript_word_relation.zig");
const witness = @import("transcript_word_witness.zig");
const trace_mod = @import("pow_frame_witness.zig");
const check_witness = @import("pow_check_witness.zig");
const schedule = @import("verifier_schedule.zig");
const support = @import("test_support.zig");

const test_support = @import("transcript_word_test_support.zig");
const FullFixture = test_support.FullFixture;
const PlanFixture = test_support.PlanFixture;
const PendingPow = test_support.PendingPow;
const TraceStorage = test_support.TraceStorage;
const groupEnd = test_support.groupEnd;
const groupPurpose = test_support.groupPurpose;
const rawWordCount = test_support.rawWordCount;
const fixtureNonce = test_support.fixtureNonce;
const fixtureWord = test_support.fixtureWord;
const findRow = test_support.findRow;
const expectBatchValues = test_support.expectBatchValues;
const expectSatisfied = test_support.expectSatisfied;
const expectAnyRootNonzero = test_support.expectAnyRootNonzero;
const splitColumns = test_support.splitColumns;
const componentFailureCase = test_support.componentFailureCase;
const preprocessingFailureCase = test_support.preprocessingFailureCase;
const batchFailureCase = test_support.batchFailureCase;
const testShape = test_support.testShape;

test "R-012 transcript word pins exact source AIR binding and degree geometry" {
    const authority = component.SourceAuthority.pinned();
    try authority.validate();
    try std.testing.expectEqualStrings(
        component.SOURCE_AUTHORITY_DIGEST_HEX,
        &std.fmt.bytesToHex(authority.identityDigest(), .lower),
    );
    try std.testing.expectEqual(@as(u8, 2), authority.main_columns);
    try std.testing.expectEqual(@as(u8, 15), authority.preprocessed_columns);
    try std.testing.expectEqual(@as(u8, 3), authority.direct_constraints);
    try std.testing.expectEqual(@as(u8, 4), authority.framework_constraints);
    try std.testing.expectEqual(@as(u8, 2), authority.relation_events);
    try std.testing.expectEqual(@as(u8, 4), authority.interaction_columns);

    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    try std.testing.expectEqual(@as(usize, 19), component.LOGICAL_INPUT_COUNT);
    try std.testing.expectEqual(@as(usize, 3), definition.constraints.len);
    try std.testing.expectEqual(@as(usize, 2), definition.events.ordered().len);
    const identity = try component.identity(std.testing.allocator);
    try std.testing.expectEqualStrings(
        component.SEMANTIC_DIGEST_HEX,
        &std.fmt.bytesToHex(identity.bytes, .lower),
    );
    var degrees = try degree.analyze(std.testing.allocator, &definition.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(
        @as(degree.Degree, component.MAXIMUM_CONSTRAINT_DEGREE),
        degrees.maximumConstraintDegree(),
    );
    try std.testing.expectEqual(@as(u32, 3), component.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE);

    const relation_plan = try interaction_mod.authenticate(&definition);
    try std.testing.expectEqual(
        @as(u8, component.FRAME_WORD_RELATION_ARITY),
        relation_plan.events[0].arity,
    );
    try std.testing.expectEqual(
        @as(u8, component.PAYLOAD_WORD_RELATION_ARITY),
        relation_plan.events[1].arity,
    );
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    try executor.validate();
    try std.testing.expectEqualStrings(
        witness.BINDING_DIGEST_HEX,
        &std.fmt.bytesToHex(binding.identityDigest(), .lower),
    );
}

test "R-012 transcript word static profile seals one paired recurrence" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const profile = try static_profile.collect(
        std.testing.allocator,
        &definition.arena,
        .{
            .physical_main_columns = component.PHYSICAL_MAIN_COLUMN_COUNT,
            .lookup_layout = .{
                .batch_size = component.LOOKUP_BATCH_SIZE,
                .interaction_coordinates_per_batch = 4,
            },
        },
    );
    try profile.validate();
    try std.testing.expectEqual(@as(u32, 19), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 3), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 2), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 1), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 4), profile.interaction_columns);
    try std.testing.expectEqual(@as(u32, 4), profile.maximum_logical_constraint_degree);
    try std.testing.expectEqual(@as(?u32, 3), profile.maximum_lookup_numerator_degree);
    try std.testing.expectEqual(@as(?u32, 1), profile.maximum_lookup_denominator_degree);
    try std.testing.expectEqual(@as(?u32, 4), profile.maximum_modeled_interaction_degree);
    try std.testing.expectEqual(@as(u32, 31), profile.expression_dag_nodes);
    try std.testing.expectEqual(@as(u32, 22), profile.expression_dag_edges);
    try std.testing.expectEqual(@as(u32, 4), profile.expression_dag_shared_nodes);
    try std.testing.expectEqual(@as(u32, 0), profile.nodes_outside_constraint_effect_closure);
    try std.testing.expectEqualStrings(
        component.STATIC_PROFILE_DIGEST_HEX,
        &std.fmt.bytesToHex(profile.profile_digest, .lower),
    );
}

test "R-012 transcript preprocessing is the exact three-lane padded schedule" {
    var plans = try PlanFixture.init(std.testing.allocator);
    defer plans.deinit();
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var preprocessing = try witness.Preprocessed.init(
        measured.allocator(),
        &plans.vm,
        &plans.recursion,
    );
    defer preprocessing.deinit();
    try std.testing.expectEqual(@as(usize, 1), measured.alloc_index);
    try preprocessing.validateAgainst(&plans.vm, &plans.recursion);

    try std.testing.expectEqual(@as(usize, 1_592), preprocessing.vm_row_count);
    try std.testing.expectEqual(@as(usize, 1_584), preprocessing.recursion_row_count);
    try std.testing.expectEqual(@as(usize, 4_760), preprocessing.rows.len);
    try std.testing.expectEqual(@as(u32, 13), preprocessing.log_size);
    try std.testing.expectEqual(@as(usize, 1_592), preprocessing.activeWordCount(.segment_leaf));
    try std.testing.expectEqual(@as(usize, 3_168), preprocessing.activeWordCount(.binary_node));
    try std.testing.expectEqual(@as(usize, 0), preprocessing.activeWordCount(.empty_leaf));
    try std.testing.expectEqual(@as(usize, 560), preprocessing.activePayloadCount(.segment_leaf));
    try std.testing.expectEqual(@as(usize, 1_104), preprocessing.activePayloadCount(.binary_node));

    const first = preprocessing.rows[0];
    try std.testing.expectEqual(@as(u32, 0), first.verifier_id);
    try std.testing.expectEqual(@as(u32, 0), first.sequence);
    try std.testing.expectEqual(@as(u32, 1), first.tag);
    try std.testing.expectEqual(@as(u32, 8), first.word_index);
    try std.testing.expectEqual(component.TRANSCRIPT_OPERATION_TAG, first.constant_value);
    try std.testing.expectEqual(@as(u32, 1), preprocessing.rows[8].is_payload);
    try std.testing.expectEqual(@as(u32, 0), preprocessing.rows[8].payload_index);
    try std.testing.expectEqual(@as(u32, 1), preprocessing.rows[16].is_payload);
    try std.testing.expectEqual(@as(u32, 8), preprocessing.rows[16].payload_index);
    try std.testing.expectEqual(@as(u32, 1), preprocessing.rows[24].constant_value);
    try std.testing.expectEqual(@as(u32, 0), preprocessing.rows[31].constant_value);
    try std.testing.expectEqual(@as(u32, 1), preprocessing.rows[32].hash_id);

    const left_start = preprocessing.vm_row_count;
    const right_start = left_start + preprocessing.recursion_row_count;
    try std.testing.expectEqual(witness.LEFT_RECURSION_VERIFIER_ID, preprocessing.rows[left_start].verifier_id);
    try std.testing.expectEqual(witness.RIGHT_RECURSION_VERIFIER_ID, preprocessing.rows[right_start].verifier_id);
    try std.testing.expectEqual(@as(u32, 1), preprocessing.rows[left_start].binary_mask);
    try std.testing.expectEqual(@as(u32, 0), preprocessing.rows[left_start].segment_mask);
}

test "R-012 transcript words derive all proof modes from complete source traces" {
    var fixture = try FullFixture.init(std.testing.allocator);
    defer fixture.deinit();

    var segment = try witness.PreparedBatch.init(
        std.testing.allocator,
        &fixture.preprocessing,
        &fixture.plans.vm,
        &fixture.plans.recursion,
        .{ .segment_leaf = &fixture.vm.trace },
    );
    defer segment.deinit();
    try segment.validateAgainstSource(
        &fixture.preprocessing,
        &fixture.plans.vm,
        &fixture.plans.recursion,
        .{ .segment_leaf = &fixture.vm.trace },
    );
    try expectBatchValues(&fixture.preprocessing, &segment, .segment_leaf, .{
        .segment_leaf = &fixture.vm.trace,
    });

    var binary = try witness.PreparedBatch.init(
        std.testing.allocator,
        &fixture.preprocessing,
        &fixture.plans.vm,
        &fixture.plans.recursion,
        .{ .binary_node = .{
            .left = &fixture.left.trace,
            .right = &fixture.right.trace,
        } },
    );
    defer binary.deinit();
    try binary.validateAgainstSource(
        &fixture.preprocessing,
        &fixture.plans.vm,
        &fixture.plans.recursion,
        .{ .binary_node = .{
            .left = &fixture.left.trace,
            .right = &fixture.right.trace,
        } },
    );
    try expectBatchValues(&fixture.preprocessing, &binary, .binary_node, .{
        .binary_node = .{
            .left = &fixture.left.trace,
            .right = &fixture.right.trace,
        },
    });

    var empty = try witness.PreparedBatch.init(
        std.testing.allocator,
        &fixture.preprocessing,
        &fixture.plans.vm,
        &fixture.plans.recursion,
        .{ .empty_leaf = {} },
    );
    defer empty.deinit();
    try empty.validateAgainstSource(
        &fixture.preprocessing,
        &fixture.plans.vm,
        &fixture.plans.recursion,
        .{ .empty_leaf = {} },
    );
    try expectBatchValues(&fixture.preprocessing, &empty, .empty_leaf, .{
        .empty_leaf = {},
    });
}

test "R-012 transcript word constraints and relation signs cover every lane state" {
    var fixture = try FullFixture.init(std.testing.allocator);
    defer fixture.deinit();
    var batch = try witness.PreparedBatch.init(
        std.testing.allocator,
        &fixture.preprocessing,
        &fixture.plans.vm,
        &fixture.plans.recursion,
        .{ .segment_leaf = &fixture.vm.trace },
    );
    defer batch.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const relation_plan = try interaction_mod.authenticate(&definition);

    const payload_index = findRow(&fixture.preprocessing, 0, 1, true);
    const fixed_index = findRow(&fixture.preprocessing, 0, 0, true);
    const inactive_index = findRow(&fixture.preprocessing, 1, 1, true);
    const payload_row = try witness.logicalRow(
        fixture.preprocessing.rows[payload_index],
        batch.values[payload_index],
        .segment_leaf,
    );
    try expectSatisfied(&definition, payload_row);
    const payload_entries = try relation_plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events.ordered(),
        payload_row,
    );
    try std.testing.expect(payload_entries[0].numerator.eql(QM31.one()));
    try std.testing.expect(payload_entries[1].numerator.eql(QM31.one().neg()));
    try std.testing.expect(payload_entries[0].values[0].eql(QM31.zero()));
    try std.testing.expect(payload_entries[0].values[1].eql(QM31.fromBase(
        M31.fromCanonical(fixture.preprocessing.rows[payload_index].hash_id),
    )));
    try std.testing.expect(payload_entries[0].values[2].eql(QM31.fromBase(
        M31.fromCanonical(fixture.preprocessing.rows[payload_index].word_index),
    )));
    try std.testing.expect(payload_entries[0].values[3].eql(QM31.fromBase(
        batch.values[payload_index],
    )));
    try std.testing.expect(payload_entries[0].numerator
        .add(QM31.one().neg()).isZero());
    try std.testing.expect(payload_entries[1].numerator
        .add(QM31.one()).isZero());

    const fixed_row = try witness.logicalRow(
        fixture.preprocessing.rows[fixed_index],
        batch.values[fixed_index],
        .segment_leaf,
    );
    try expectSatisfied(&definition, fixed_row);
    const fixed_entries = try relation_plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events.ordered(),
        fixed_row,
    );
    try std.testing.expect(fixed_entries[0].numerator.eql(QM31.one()));
    try std.testing.expect(fixed_entries[1].numerator.isZero());
    try std.testing.expect(fixed_entries[0].values[3].eql(QM31.fromBase(
        M31.fromCanonical(fixture.preprocessing.rows[fixed_index].constant_value),
    )));

    const inactive_row = try witness.logicalRow(
        fixture.preprocessing.rows[inactive_index],
        batch.values[inactive_index],
        .segment_leaf,
    );
    try expectSatisfied(&definition, inactive_row);
    const inactive_entries = try relation_plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events.ordered(),
        inactive_row,
    );
    for (inactive_entries) |entry| try std.testing.expect(entry.numerator.isZero());

    var forged = fixed_row;
    forged[1] = M31.one();
    try expectAnyRootNonzero(&definition, forged);
    forged = inactive_row;
    forged[1] = M31.one();
    try expectAnyRootNonzero(&definition, forged);
    forged = payload_row;
    forged[0] = M31.zero();
    try expectAnyRootNonzero(&definition, forged);
}

test "R-012 transcript writers retain one cold snapshot and allocate nothing hot" {
    var fixture = try FullFixture.init(std.testing.allocator);
    defer fixture.deinit();
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var batch = try witness.PreparedBatch.init(
        measured.allocator(),
        &fixture.preprocessing,
        &fixture.plans.vm,
        &fixture.plans.recursion,
        .{ .segment_leaf = &fixture.vm.trace },
    );
    defer batch.deinit();
    try std.testing.expectEqual(@as(usize, 1), measured.alloc_index);

    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const size = @as(usize, 1) << @intCast(fixture.preprocessing.log_size);
    const pre_storage = try std.testing.allocator.alloc(
        M31,
        component.PREPROCESSED_COLUMN_COUNT * size,
    );
    defer std.testing.allocator.free(pre_storage);
    @memset(pre_storage, M31.fromCanonical(91));
    var pre_columns: [component.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    splitColumns(component.PREPROCESSED_COLUMN_COUNT, size, pre_storage, &pre_columns);
    const before = measured.alloc_index;
    try executor.generatePreprocessedInto(&fixture.preprocessing, &pre_columns);
    try std.testing.expectEqual(before, measured.alloc_index);

    const main_storage = try std.testing.allocator.alloc(
        M31,
        component.PHYSICAL_MAIN_COLUMN_COUNT * size,
    );
    defer std.testing.allocator.free(main_storage);
    @memset(main_storage, M31.fromCanonical(92));
    var main_columns: [component.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
    splitColumns(component.PHYSICAL_MAIN_COLUMN_COUNT, size, main_storage, &main_columns);
    try executor.generateMainInto(&fixture.preprocessing, &batch, &main_columns);
    try std.testing.expectEqual(before, measured.alloc_index);
    for (fixture.preprocessing.rows, batch.values, 0..) |row, value, index| {
        const pre_values = row.values();
        for (pre_columns, pre_values) |column, expected|
            try std.testing.expect(column[index].eql(expected));
        try std.testing.expect(main_columns[0][index].eql(M31.one()));
        try std.testing.expect(main_columns[1][index].eql(value));
    }
    for (pre_columns) |column| for (column[fixture.preprocessing.rows.len..]) |padding|
        try std.testing.expect(padding.isZero());
    for (main_columns) |column| for (column[fixture.preprocessing.rows.len..]) |padding|
        try std.testing.expect(padding.isZero());

    @memset(main_storage, M31.fromCanonical(93));
    var short = main_columns;
    short[1] = short[1][0 .. size - 1];
    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generateMainInto(&fixture.preprocessing, &batch, &short),
    );
    for (main_storage) |value| try std.testing.expectEqual(@as(u32, 93), value.v);

    @memset(main_storage, M31.fromCanonical(94));
    var aliased = main_columns;
    aliased[1] = aliased[0];
    try std.testing.expectError(
        error.AliasedDestination,
        executor.generateMainInto(&fixture.preprocessing, &batch, &aliased),
    );
    for (main_storage) |value| try std.testing.expectEqual(@as(u32, 94), value.v);
}

test "R-012 transcript source and retained seals reject every authority mutation" {
    var fixture = try FullFixture.init(std.testing.allocator);
    defer fixture.deinit();
    const segment_source = witness.Source{ .segment_leaf = &fixture.vm.trace };

    const header = fixture.vm.words[component.RATE];
    const header_call = fixture.vm.frames[0].first_call_id + 1;
    const header_input = fixture.vm.calls[header_call].input[0];
    fixture.vm.words[component.RATE] = M31.one();
    fixture.vm.calls[header_call].input[0] = header_input.sub(header).add(M31.one());
    try std.testing.expectError(
        error.InvalidTranscriptSource,
        witness.PreparedBatch.init(
            std.testing.allocator,
            &fixture.preprocessing,
            &fixture.plans.vm,
            &fixture.plans.recursion,
            segment_source,
        ),
    );
    fixture.vm.words[component.RATE] = header;
    fixture.vm.calls[header_call].input[0] = header_input;

    const nonce = fixture.vm.checks[0].nonce;
    fixture.vm.checks[0].nonce +%= 1;
    try std.testing.expectError(
        error.InvalidTranscriptSource,
        witness.PreparedBatch.init(
            std.testing.allocator,
            &fixture.preprocessing,
            &fixture.plans.vm,
            &fixture.plans.recursion,
            segment_source,
        ),
    );
    fixture.vm.checks[0].nonce = nonce;

    fixture.vm.frames[0].hash_id += 1;
    try std.testing.expectError(
        error.InvalidTranscriptTrace,
        witness.PreparedBatch.init(
            std.testing.allocator,
            &fixture.preprocessing,
            &fixture.plans.vm,
            &fixture.plans.recursion,
            segment_source,
        ),
    );
    fixture.vm.frames[0].hash_id -= 1;

    const all_frames = fixture.vm.trace.hash_frames;
    fixture.vm.trace.hash_frames = all_frames[0 .. all_frames.len - 1];
    try std.testing.expectError(
        error.InvalidTranscriptTrace,
        witness.PreparedBatch.init(
            std.testing.allocator,
            &fixture.preprocessing,
            &fixture.plans.vm,
            &fixture.plans.recursion,
            segment_source,
        ),
    );
    fixture.vm.trace.hash_frames = all_frames;

    try std.testing.expectError(
        error.SchemaMismatch,
        witness.PreparedBatch.init(
            std.testing.allocator,
            &fixture.preprocessing,
            &fixture.plans.recursion,
            &fixture.plans.vm,
            .{ .empty_leaf = {} },
        ),
    );

    var batch = try witness.PreparedBatch.init(
        std.testing.allocator,
        &fixture.preprocessing,
        &fixture.plans.vm,
        &fixture.plans.recursion,
        segment_source,
    );
    defer batch.deinit();
    batch.values[0] = M31.one();
    try std.testing.expectError(error.AuthorityMismatch, batch.validate());

    fixture.preprocessing.rows[0].sequence += 1;
    try std.testing.expectError(error.AuthorityMismatch, fixture.preprocessing.validate());
}

test "R-012 transcript word constructors release every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        componentFailureCase,
        .{},
    );
    var plans = try PlanFixture.init(std.testing.allocator);
    defer plans.deinit();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        preprocessingFailureCase,
        .{ &plans.vm, &plans.recursion },
    );
    var preprocessing = try witness.Preprocessed.init(
        std.testing.allocator,
        &plans.vm,
        &plans.recursion,
    );
    defer preprocessing.deinit();
    var trace = try TraceStorage.init(
        std.testing.allocator,
        preprocessing.rows[0..preprocessing.vm_row_count],
        701,
    );
    defer trace.deinit();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        batchFailureCase,
        .{
            &preprocessing,
            &plans.vm,
            &plans.recursion,
            witness.Source{ .segment_leaf = &trace.trace },
        },
    );
}
