//! Exactness, source-rigidity, cancellation, and performance gates for row 5.

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
const component = @import("transcript_payload.zig");
const interaction_mod = @import("transcript_payload_relation.zig");
const witness = @import("transcript_payload_witness.zig");
const word_component = @import("transcript_word.zig");
const word_interaction = @import("transcript_word_relation.zig");
const word_witness = @import("transcript_word_witness.zig");
const trace_mod = @import("pow_frame_witness.zig");
const check_witness = @import("pow_check_witness.zig");
const schedule = @import("verifier_schedule.zig");
const support = @import("test_support.zig");

const test_support = @import("transcript_payload_test_support.zig");
const FullFixture = test_support.FullFixture;
const PlanFixture = test_support.PlanFixture;
const PendingPow = test_support.PendingPow;
const TraceStorage = test_support.TraceStorage;
const wordGroupEnd = test_support.wordGroupEnd;
const wordGroupPurpose = test_support.wordGroupPurpose;
const rawWordCount = test_support.rawWordCount;
const findPayloadSource = test_support.findPayloadSource;
const expectLaneSourceCounts = test_support.expectLaneSourceCounts;
const fixtureNonce = test_support.fixtureNonce;
const fixtureWord = test_support.fixtureWord;
const findKind = test_support.findKind;
const findWordRow = test_support.findWordRow;
const expectBatchValues = test_support.expectBatchValues;
const expectSatisfied = test_support.expectSatisfied;
const expectAnyRootNonzero = test_support.expectAnyRootNonzero;
const splitColumns = test_support.splitColumns;
const componentFailureCase = test_support.componentFailureCase;
const preprocessingFailureCase = test_support.preprocessingFailureCase;
const batchFailureCase = test_support.batchFailureCase;
const testShape = test_support.testShape;

test "R-012 transcript payload pins exact source AIR binding and degree geometry" {
    const authority = component.SourceAuthority.pinned();
    try authority.validate();
    try std.testing.expectEqualStrings(
        component.SOURCE_AUTHORITY_DIGEST_HEX,
        &std.fmt.bytesToHex(authority.identityDigest(), .lower),
    );
    try std.testing.expectEqual(@as(u8, 2), authority.main_columns);
    try std.testing.expectEqual(@as(u8, 17), authority.preprocessed_columns);
    try std.testing.expectEqual(@as(u8, 2), authority.parameters);
    try std.testing.expectEqual(@as(u8, 3), authority.direct_constraints);
    try std.testing.expectEqual(@as(u8, 4), authority.framework_constraints);
    try std.testing.expectEqual(@as(u8, 2), authority.relation_events);
    try std.testing.expectEqual(@as(u8, 4), authority.interaction_columns);

    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    try std.testing.expectEqual(@as(usize, 21), component.LOGICAL_INPUT_COUNT);
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
        @as(u8, component.PAYLOAD_WORD_RELATION_ARITY),
        relation_plan.events[0].arity,
    );
    try std.testing.expectEqual(
        @as(u8, component.INPUT_WORD_RELATION_ARITY),
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

test "R-012 transcript payload profile seals paired plus singleton recurrences" {
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
    try std.testing.expectEqual(@as(u32, 21), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 3), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 2), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 1), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 4), profile.interaction_columns);
    try std.testing.expectEqual(@as(u32, 4), profile.maximum_logical_constraint_degree);
    try std.testing.expectEqual(@as(?u32, 3), profile.maximum_lookup_numerator_degree);
    try std.testing.expectEqual(@as(?u32, 1), profile.maximum_lookup_denominator_degree);
    try std.testing.expectEqual(@as(?u32, 4), profile.maximum_modeled_interaction_degree);
    try std.testing.expectEqual(@as(u32, 31), profile.expression_dag_nodes);
    try std.testing.expectEqual(@as(u32, 20), profile.expression_dag_edges);
    try std.testing.expectEqual(@as(u32, 3), profile.expression_dag_shared_nodes);
    try std.testing.expectEqual(@as(u32, 0), profile.nodes_outside_constraint_effect_closure);
    try std.testing.expectEqualStrings(
        component.STATIC_PROFILE_DIGEST_HEX,
        &std.fmt.bytesToHex(profile.profile_digest, .lower),
    );
}

test "R-012 transcript payload preprocessing assigns every exact semantic source" {
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
    try std.testing.expectEqual(@as(usize, 560), preprocessing.vm_row_count);
    try std.testing.expectEqual(@as(usize, 552), preprocessing.recursion_row_count);
    try std.testing.expectEqual(@as(usize, 1_664), preprocessing.rows.len);
    try std.testing.expectEqual(@as(u32, 11), preprocessing.log_size);
    try std.testing.expectEqual(@as(usize, 560), preprocessing.activePayloadCount(.segment_leaf));
    try std.testing.expectEqual(@as(usize, 1_104), preprocessing.activePayloadCount(.binary_node));
    try std.testing.expectEqual(@as(usize, 520), preprocessing.activeInputCount(.segment_leaf));
    try std.testing.expectEqual(@as(usize, 1_024), preprocessing.activeInputCount(.binary_node));
    try std.testing.expectEqual(@as(usize, 552), preprocessing.activeInputMultiplicity(.segment_leaf));
    try std.testing.expectEqual(@as(usize, 1_088), preprocessing.activeInputMultiplicity(.binary_node));

    try expectLaneSourceCounts(
        preprocessing.rows[0..preprocessing.vm_row_count],
        .{ 16, 412, 16, 32, 16, 32, 16, 4, 4, 4, 8, 0 },
    );
    const left = preprocessing.vm_row_count;
    const right = left + preprocessing.recursion_row_count;
    try expectLaneSourceCounts(
        preprocessing.rows[left..right],
        .{ 16, 412, 16, 32, 16, 32, 16, 4, 4, 4, 0, 0 },
    );
    try expectLaneSourceCounts(
        preprocessing.rows[right..],
        .{ 16, 412, 16, 32, 16, 32, 16, 4, 4, 4, 0, 0 },
    );

    var protocol_at = [_]usize{ 0, 0 };
    var pcs_at: usize = 0;
    var commitment_limbs: [4][component.DIGEST_WORD_COUNT]bool =
        .{.{false} ** component.DIGEST_WORD_COUNT} ** 4;
    for (preprocessing.rows[0..preprocessing.vm_row_count]) |row| {
        switch (row.source_kind) {
            .protocol => {
                try std.testing.expect(row.item_index < protocol_at.len);
                try std.testing.expect(row.limb_index < component.DIGEST_WORD_COUNT);
                const item: usize = @intCast(row.item_index);
                const limb: usize = @intCast(row.limb_index);
                try std.testing.expectEqual(
                    @as(u32, @intCast(protocol_at[item])),
                    row.limb_index,
                );
                const expected = if (item == 0)
                    protocol.protocolId()[limb]
                else
                    plans.vm.shape_id[limb];
                try std.testing.expectEqual(expected, row.constant_value);
                protocol_at[item] += 1;
            },
            .pcs_parameters => {
                try std.testing.expectEqual(@as(u32, 0), row.item_index);
                try std.testing.expectEqual(@as(u32, @intCast(pcs_at)), row.limb_index);
                try std.testing.expectEqual(witness.PCS_PARAMETER_WORDS[pcs_at], row.constant_value);
                pcs_at += 1;
            },
            .commitment => {
                try std.testing.expect(row.item_index < commitment_limbs.len);
                try std.testing.expect(row.limb_index < component.DIGEST_WORD_COUNT);
                const item: usize = @intCast(row.item_index);
                const limb: usize = @intCast(row.limb_index);
                try std.testing.expect(!commitment_limbs[item][limb]);
                commitment_limbs[item][limb] = true;
            },
            else => {},
        }
    }
    for (protocol_at) |count|
        try std.testing.expectEqual(component.DIGEST_WORD_COUNT, count);
    try std.testing.expectEqual(component.PCS_PARAMETER_WORD_COUNT, pcs_at);
    for (commitment_limbs) |limbs| for (limbs) |seen|
        try std.testing.expect(seen);

    const first = preprocessing.rows[0];
    try std.testing.expectEqual(witness.VerifierInputKind.protocol, first.source_kind);
    try std.testing.expectEqual(@as(u32, 1), first.constant_mask);
    try std.testing.expectEqual(protocol.protocolId()[0], first.constant_value);
    try std.testing.expectEqual(@as(u32, 16), first.source_word_index);
    const shape_word = preprocessing.rows[component.DIGEST_WORD_COUNT];
    try std.testing.expectEqual(witness.VerifierInputKind.protocol, shape_word.source_kind);
    try std.testing.expectEqual(@as(u32, 1), shape_word.item_index);
    try std.testing.expectEqual(plans.vm.shape_id[0], shape_word.constant_value);
    const statement = preprocessing.rows[component.PROTOCOL_BINDING_WORD_COUNT];
    try std.testing.expectEqual(witness.VerifierInputKind.statement, statement.source_kind);
    try std.testing.expectEqual(@as(u32, 1), statement.input_use_count);
    try std.testing.expectEqual(@as(u32, 0), statement.constant_mask);

    const pcs_index = findKind(&preprocessing, 0, .pcs_parameters);
    try std.testing.expectEqual(@as(u32, 20), preprocessing.rows[pcs_index].constant_value);
    try std.testing.expectEqual(@as(u32, 0), preprocessing.rows[pcs_index].item_index);
    const commitment_index = findKind(&preprocessing, 0, .commitment);
    try std.testing.expectEqual(@as(u32, 0), preprocessing.rows[commitment_index].item_index);
    const claimed_index = findKind(&preprocessing, 0, .claimed_sum);
    try std.testing.expectEqual(@as(u32, 1), preprocessing.rows[claimed_index].input_use_count);
    const sampled_index = findKind(&preprocessing, 0, .sampled_value);
    try std.testing.expectEqual(@as(u32, 2), preprocessing.rows[sampled_index].input_use_count);

    try std.testing.expectEqual(witness.LEFT_RECURSION_VERIFIER_ID, preprocessing.rows[left].verifier_id);
    try std.testing.expectEqual(witness.RIGHT_RECURSION_VERIFIER_ID, preprocessing.rows[right].verifier_id);
    const recursion_claimed = findKind(&preprocessing, 1, .claimed_sum);
    try std.testing.expectEqual(@as(u32, 1), preprocessing.rows[recursion_claimed].input_use_count);
}

test "R-012 transcript payload derives all proof modes from complete source traces" {
    var fixture = try FullFixture.init(std.testing.allocator);
    defer fixture.deinit();
    const segment_source = witness.Source{ .segment_leaf = &fixture.vm.trace };
    var segment = try witness.PreparedBatch.init(
        std.testing.allocator,
        &fixture.preprocessing,
        &fixture.plans.vm,
        &fixture.plans.recursion,
        segment_source,
    );
    defer segment.deinit();
    try segment.validateAgainstSource(
        &fixture.preprocessing,
        &fixture.plans.vm,
        &fixture.plans.recursion,
        segment_source,
    );
    try expectBatchValues(&fixture.preprocessing, &segment, segment_source);

    const binary_source = witness.Source{ .binary_node = .{
        .left = &fixture.left.trace,
        .right = &fixture.right.trace,
    } };
    var binary = try witness.PreparedBatch.init(
        std.testing.allocator,
        &fixture.preprocessing,
        &fixture.plans.vm,
        &fixture.plans.recursion,
        binary_source,
    );
    defer binary.deinit();
    try binary.validateAgainstSource(
        &fixture.preprocessing,
        &fixture.plans.vm,
        &fixture.plans.recursion,
        binary_source,
    );
    try expectBatchValues(&fixture.preprocessing, &binary, binary_source);

    const empty_source = witness.Source{ .empty_leaf = {} };
    var empty = try witness.PreparedBatch.init(
        std.testing.allocator,
        &fixture.preprocessing,
        &fixture.plans.vm,
        &fixture.plans.recursion,
        empty_source,
    );
    defer empty.deinit();
    try empty.validateAgainstSource(
        &fixture.preprocessing,
        &fixture.plans.vm,
        &fixture.plans.recursion,
        empty_source,
    );
    try expectBatchValues(&fixture.preprocessing, &empty, empty_source);
}

test "R-012 transcript payload multiplicities and row-4 cancellation are exact" {
    var fixture = try FullFixture.init(std.testing.allocator);
    defer fixture.deinit();
    const source = witness.Source{ .segment_leaf = &fixture.vm.trace };
    var batch = try witness.PreparedBatch.init(
        std.testing.allocator,
        &fixture.preprocessing,
        &fixture.plans.vm,
        &fixture.plans.recursion,
        source,
    );
    defer batch.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const relation_plan = try interaction_mod.authenticate(&definition);

    const sampled_index = findKind(&fixture.preprocessing, 0, .sampled_value);
    const sampled_row = try witness.logicalRow(
        fixture.preprocessing.rows[sampled_index],
        batch.values[sampled_index],
        .segment_leaf,
    );
    try expectSatisfied(&definition, sampled_row);
    const sampled_entries = try relation_plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events.ordered(),
        sampled_row,
    );
    try std.testing.expect(sampled_entries[0].numerator.eql(QM31.one()));
    try std.testing.expect(sampled_entries[1].numerator.eql(
        QM31.fromBase(M31.fromCanonical(2)),
    ));

    const claimed_index = findKind(&fixture.preprocessing, 0, .claimed_sum);
    const claimed_row = try witness.logicalRow(
        fixture.preprocessing.rows[claimed_index],
        batch.values[claimed_index],
        .segment_leaf,
    );
    try expectSatisfied(&definition, claimed_row);
    const claimed_entries = try relation_plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events.ordered(),
        claimed_row,
    );
    for (claimed_entries) |entry| try std.testing.expect(entry.numerator.eql(QM31.one()));
    try std.testing.expect(claimed_entries[1].values[1].eql(QM31.fromBase(
        M31.fromCanonical(@intFromEnum(witness.VerifierInputKind.claimed_sum)),
    )));

    const constant_index = findKind(&fixture.preprocessing, 0, .protocol);
    const constant_row = try witness.logicalRow(
        fixture.preprocessing.rows[constant_index],
        batch.values[constant_index],
        .segment_leaf,
    );
    try expectSatisfied(&definition, constant_row);
    const constant_entries = try relation_plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events.ordered(),
        constant_row,
    );
    try std.testing.expect(constant_entries[0].numerator.eql(QM31.one()));
    try std.testing.expect(constant_entries[1].numerator.isZero());

    const inactive_index = findKind(&fixture.preprocessing, 1, .sampled_value);
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

    var word_definition = try word_component.build(std.testing.allocator);
    defer word_definition.deinit();
    const word_plan = try word_interaction.authenticate(&word_definition);
    const payload_descriptor = fixture.preprocessing.rows[sampled_index];
    const word_index = findWordRow(
        &fixture.word_preprocessing,
        payload_descriptor.verifier_id,
        payload_descriptor.sequence,
        payload_descriptor.payload_index,
    );
    const word_row = try word_witness.logicalRow(
        fixture.word_preprocessing.rows[word_index],
        batch.values[sampled_index],
        .segment_leaf,
    );
    const word_entries = try word_plan.entries(
        &word_definition.arena,
        word_component.SEMANTIC_DIGEST,
        word_definition.events.ordered(),
        word_row,
    );
    try std.testing.expect(word_entries[1].numerator
        .add(sampled_entries[0].numerator).isZero());
    for (0..component.PAYLOAD_WORD_RELATION_ARITY) |index| {
        try std.testing.expect(word_entries[1].values[index].eql(
            sampled_entries[0].values[index],
        ));
    }

    var forged = constant_row;
    forged[1] = forged[1].add(M31.one());
    try expectAnyRootNonzero(&definition, forged);
    forged = inactive_row;
    forged[1] = M31.one();
    try expectAnyRootNonzero(&definition, forged);
    forged = sampled_row;
    forged[0] = M31.zero();
    try expectAnyRootNonzero(&definition, forged);
}

test "R-012 transcript payload writers are one-allocation cold and allocation-free hot" {
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
        const expected_fixed = row.values();
        for (pre_columns, expected_fixed) |column, expected|
            try std.testing.expect(column[index].eql(expected));
        try std.testing.expect(main_columns[0][index].eql(M31.one()));
        try std.testing.expect(main_columns[1][index].eql(value));
    }
    for (pre_columns) |column| for (column[fixture.preprocessing.rows.len..]) |padding|
        try std.testing.expect(padding.isZero());
    for (main_columns) |column| for (column[fixture.preprocessing.rows.len..]) |padding|
        try std.testing.expect(padding.isZero());

    @memset(pre_storage, M31.fromCanonical(95));
    var short_preprocessed = pre_columns;
    short_preprocessed[component.PREPROCESSED_COLUMN_COUNT - 1] =
        short_preprocessed[component.PREPROCESSED_COLUMN_COUNT - 1][0 .. size - 1];
    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generatePreprocessedInto(
            &fixture.preprocessing,
            &short_preprocessed,
        ),
    );
    for (pre_storage) |value| try std.testing.expectEqual(@as(u32, 95), value.v);

    @memset(pre_storage, M31.fromCanonical(96));
    var aliased_preprocessed = pre_columns;
    aliased_preprocessed[component.PREPROCESSED_COLUMN_COUNT - 1] =
        aliased_preprocessed[0];
    try std.testing.expectError(
        error.AliasedDestination,
        executor.generatePreprocessedInto(
            &fixture.preprocessing,
            &aliased_preprocessed,
        ),
    );
    for (pre_storage) |value| try std.testing.expectEqual(@as(u32, 96), value.v);

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

test "R-012 transcript payload rejects source schedule constant and retained mutations" {
    var fixture = try FullFixture.init(std.testing.allocator);
    defer fixture.deinit();
    const source = witness.Source{ .segment_leaf = &fixture.vm.trace };

    const fixed = fixture.preprocessing.rows[0];
    const old_word = fixture.vm.frames[fixed.source_hash_id].words[fixed.source_word_index];
    const new_word = old_word.add(M31.one());
    const fixed_call = fixture.vm.frames[fixed.source_hash_id].first_call_id +
        fixed.source_word_index / component.DIGEST_WORD_COUNT;
    const fixed_lane = fixed.source_word_index % component.DIGEST_WORD_COUNT;
    const old_input = fixture.vm.calls[fixed_call].input[fixed_lane];
    fixture.vm.words[fixture.vm.frame_offsets[fixed.source_hash_id] + fixed.source_word_index] = new_word;
    fixture.vm.calls[fixed_call].input[fixed_lane] = old_input.sub(old_word).add(new_word);
    try std.testing.expectError(
        error.InvalidTranscriptSource,
        witness.PreparedBatch.init(
            std.testing.allocator,
            &fixture.preprocessing,
            &fixture.plans.vm,
            &fixture.plans.recursion,
            source,
        ),
    );
    fixture.vm.words[fixture.vm.frame_offsets[fixed.source_hash_id] + fixed.source_word_index] = old_word;
    fixture.vm.calls[fixed_call].input[fixed_lane] = old_input;

    const header_word = fixture.vm.words[component.DIGEST_WORD_COUNT];
    const header_call = fixture.vm.frames[0].first_call_id + 1;
    const header_input = fixture.vm.calls[header_call].input[0];
    fixture.vm.words[component.DIGEST_WORD_COUNT] = M31.one();
    fixture.vm.calls[header_call].input[0] = header_input.sub(header_word).add(M31.one());
    try std.testing.expectError(
        error.InvalidTranscriptSource,
        witness.PreparedBatch.init(
            std.testing.allocator,
            &fixture.preprocessing,
            &fixture.plans.vm,
            &fixture.plans.recursion,
            source,
        ),
    );
    fixture.vm.words[component.DIGEST_WORD_COUNT] = header_word;
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
            source,
        ),
    );
    fixture.vm.checks[0].nonce = nonce;

    const all_frames = fixture.vm.trace.hash_frames;
    fixture.vm.trace.hash_frames = all_frames[0 .. all_frames.len - 1];
    try std.testing.expectError(
        error.InvalidTranscriptTrace,
        witness.PreparedBatch.init(
            std.testing.allocator,
            &fixture.preprocessing,
            &fixture.plans.vm,
            &fixture.plans.recursion,
            source,
        ),
    );
    fixture.vm.trace.hash_frames = all_frames;

    fixture.vm.frames[0].hash_id += 1;
    try std.testing.expectError(
        error.InvalidTranscriptTrace,
        witness.PreparedBatch.init(
            std.testing.allocator,
            &fixture.preprocessing,
            &fixture.plans.vm,
            &fixture.plans.recursion,
            source,
        ),
    );
    fixture.vm.frames[0].hash_id -= 1;

    var batch = try witness.PreparedBatch.init(
        std.testing.allocator,
        &fixture.preprocessing,
        &fixture.plans.vm,
        &fixture.plans.recursion,
        source,
    );
    defer batch.deinit();
    const dynamic_index = findKind(&fixture.preprocessing, 0, .sampled_value);
    const dynamic = fixture.preprocessing.rows[dynamic_index];
    const dynamic_offset = fixture.vm.frame_offsets[dynamic.source_hash_id] +
        dynamic.source_word_index;
    const dynamic_word = fixture.vm.words[dynamic_offset];
    const changed_dynamic = dynamic_word.add(M31.one());
    const dynamic_call = fixture.vm.frames[dynamic.source_hash_id].first_call_id +
        dynamic.source_word_index / component.DIGEST_WORD_COUNT;
    const dynamic_lane = dynamic.source_word_index % component.DIGEST_WORD_COUNT;
    const dynamic_input = fixture.vm.calls[dynamic_call].input[dynamic_lane];
    fixture.vm.words[dynamic_offset] = changed_dynamic;
    fixture.vm.calls[dynamic_call].input[dynamic_lane] = dynamic_input
        .sub(dynamic_word).add(changed_dynamic);
    try std.testing.expectError(
        error.AuthorityMismatch,
        batch.validateAgainstSource(
            &fixture.preprocessing,
            &fixture.plans.vm,
            &fixture.plans.recursion,
            source,
        ),
    );
    fixture.vm.words[dynamic_offset] = dynamic_word;
    fixture.vm.calls[dynamic_call].input[dynamic_lane] = dynamic_input;

    batch.values[0] = batch.values[0].add(M31.one());
    try std.testing.expectError(error.AuthorityMismatch, batch.validate());
    fixture.preprocessing.rows[0].sequence += 1;
    try std.testing.expectError(error.AuthorityMismatch, fixture.preprocessing.validate());
    fixture.preprocessing.rows[0].sequence -= 1;

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
}

test "R-012 transcript payload constructors release every allocation failure" {
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
    var word_preprocessing = try word_witness.Preprocessed.init(
        std.testing.allocator,
        &plans.vm,
        &plans.recursion,
    );
    defer word_preprocessing.deinit();
    var preprocessing = try witness.Preprocessed.init(
        std.testing.allocator,
        &plans.vm,
        &plans.recursion,
    );
    defer preprocessing.deinit();
    var trace = try TraceStorage.init(
        std.testing.allocator,
        word_preprocessing.rows[0..word_preprocessing.vm_row_count],
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
