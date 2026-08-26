//! Exactness, cancellation, mutation, and performance gates for universal row 3.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const degree = @import("../../air/lang/degree.zig");
const digest = @import("../../air/lang/digest.zig");
const relation = @import("../../air/lang/relation.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const component = @import("transcript_state.zig");
const direct_program = @import("direct_constraint_program.zig");
const interaction_mod = @import("transcript_state_relation.zig");
const binding_component = @import("transcript_binding.zig");
const binding_relation = @import("transcript_binding_relation.zig");
const binding_witness = @import("transcript_binding_witness.zig");
const pow_check_witness = @import("pow_check_witness.zig");
const pow_frame_witness = @import("pow_frame_witness.zig");
const challenge_component = @import("relation_challenge.zig");
const challenge_relation = @import("relation_challenge_relation.zig");
const challenge_witness = @import("relation_challenge_witness.zig");
const schedule = @import("verifier_schedule.zig");
const universal = @import("universal_challenges.zig");
const witness = @import("transcript_state_witness.zig");

const test_support = @import("transcript_state_test_support.zig");
const Fixture = test_support.Fixture;
const OwnedTrace = test_support.OwnedTrace;
const fillFrameWords = test_support.fillFrameWords;
const testStreamWordCount = test_support.testStreamWordCount;
const mulFour = test_support.mulFour;
const testShape = test_support.testShape;
const stateEntriesAt = test_support.stateEntriesAt;
const expectEntryCancellation = test_support.expectEntryCancellation;
const expectSameTuple = test_support.expectSameTuple;
const findCall = test_support.findCall;
const findDoubleProducer = test_support.findDoubleProducer;
const findDrawTag = test_support.findDrawTag;
const findNonInitialActive = test_support.findNonInitialActive;
const assertPreprocessedWriter = test_support.assertPreprocessedWriter;
const assertMainWriter = test_support.assertMainWriter;
const splitColumns = test_support.splitColumns;
const componentFailureCase = test_support.componentFailureCase;
const preprocessingFailureCase = test_support.preprocessingFailureCase;
const mainFailureCase = test_support.mainFailureCase;
const interactionFailureCase = test_support.interactionFailureCase;

test "R-012 transcript state preserves exact row-3 geometry and source seals" {
    try component.SourceAuthority.pinned().validate();
    try std.testing.expectEqualStrings(
        component.SOURCE_AUTHORITY_DIGEST_HEX,
        &std.fmt.bytesToHex(
            component.SourceAuthority.pinned().identityDigest(),
            .lower,
        ),
    );
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    try std.testing.expectEqual(@as(usize, 17), definition.main.physical().len);
    try std.testing.expectEqual(@as(usize, 17), definition.preprocessed.physical().len);
    try std.testing.expectEqual(@as(usize, 2), definition.parameters.physical().len);
    try std.testing.expectEqual(@as(usize, 25), definition.constraints.len);
    try std.testing.expectEqual(@as(usize, 12), definition.events.len);
    var degrees = try degree.analyze(std.testing.allocator, &definition.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(
        @as(degree.Degree, component.MAXIMUM_CONSTRAINT_DEGREE),
        degrees.maximumConstraintDegree(),
    );
    try std.testing.expectEqual(@as(u32, 3), component.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE);
    try std.testing.expectEqualStrings(
        component.SEMANTIC_DIGEST_HEX,
        &std.fmt.bytesToHex((try digest.computeIdentity(&definition.arena)).bytes, .lower),
    );

    const plan = try interaction_mod.authenticate(&definition);
    const domains = [component.RELATION_EVENT_COUNT]relation.Domain{
        .recursion_transcript_frame_output,
        .recursion_transcript_draw_output,
        .recursion_transcript_digest_state,
        .recursion_transcript_digest_state,
        .recursion_transcript_frame_word,
        .recursion_transcript_frame_word,
        .recursion_transcript_frame_word,
        .recursion_transcript_frame_word,
        .recursion_transcript_frame_word,
        .recursion_transcript_frame_word,
        .recursion_transcript_frame_word,
        .recursion_transcript_frame_word,
    };
    const roles = [component.RELATION_EVENT_COUNT]relation.Role{
        .consume,
        .emit,
        .consume,
        .emit,
        .emit,
        .emit,
        .emit,
        .emit,
        .emit,
        .emit,
        .emit,
        .emit,
    };
    for (plan.events, domains, roles, 0..) |event, domain, role, index| {
        try std.testing.expectEqual(@as(u8, @intCast(index)), event.ordinal);
        try std.testing.expectEqual(domain, event.domain);
        try std.testing.expectEqual(role, event.role);
    }
    try std.testing.expectEqual(@as(usize, 6), interaction_mod.Runtime.BATCH_COUNT);
    try std.testing.expectEqual(@as(usize, 24), interaction_mod.Runtime.INTERACTION_COLUMN_COUNT);
    const binding = try witness.Binding.canonical(&definition);
    _ = try witness.Executor.init(&definition, &binding);
    try std.testing.expectEqualStrings(
        witness.BINDING_DIGEST_HEX,
        &std.fmt.bytesToHex(binding.identityDigest(), .lower),
    );
}

test "R-012 transcript state static profile is exact and parameter-aware" {
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
    try std.testing.expectEqual(@as(u32, 36), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 25), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 12), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 6), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 24), profile.interaction_columns);
    try std.testing.expectEqual(@as(u32, 4), profile.maximum_logical_constraint_degree);
    // Proof-kind parameters are verifier constants in the adapter. Treating
    // them as degree-one trace inputs is deliberately conservative; the exact
    // pinned Stark-V protocol declaration remains cubic.
    try std.testing.expectEqual(@as(?u32, 4), profile.maximum_modeled_interaction_degree);
    try std.testing.expectEqual(@as(u32, 77), profile.expression_dag_nodes);
    try std.testing.expectEqual(@as(u32, 66), profile.expression_dag_edges);
    try std.testing.expectEqual(@as(u32, 12), profile.expression_dag_shared_nodes);
    try std.testing.expectEqual(@as(u32, 0), profile.nodes_outside_constraint_effect_closure);
    try std.testing.expectEqualStrings(
        component.STATIC_PROFILE_DIGEST_HEX,
        &std.fmt.bytesToHex(profile.profile_digest, .lower),
    );
}

test "R-012 transcript state preprocessing derives exact frame-state lanes" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try std.testing.expectEqual(@as(usize, 85), fixture.preprocessing.vm_frame_count);
    try std.testing.expectEqual(@as(usize, 85), fixture.preprocessing.recursion_frame_count);
    try std.testing.expectEqual(@as(usize, 287), fixture.preprocessing.vm_call_count);
    try std.testing.expectEqual(@as(usize, 286), fixture.preprocessing.recursion_call_count);
    try std.testing.expectEqual(@as(usize, 255), fixture.preprocessing.rows.len);
    try std.testing.expectEqual(@as(u32, 8), fixture.preprocessing.log_size);
    try fixture.preprocessing.validateAgainst(&fixture.call_preprocessing);
    const first = fixture.preprocessing.rows[0];
    try std.testing.expectEqual(@as(u32, 0), first.verifier_id);
    try std.testing.expectEqual(@as(u32, 0), first.sequence);
    try std.testing.expectEqual(@as(u32, 1), first.tag);
    try std.testing.expectEqual(@as(u32, 0), first.hash_id);
    try std.testing.expectEqual(@as(u32, 0), first.input_state_key);
    try std.testing.expectEqual(@as(u32, 1), first.output_state_key);
    try std.testing.expectEqual(@as(u32, 1), first.initial_mask);
    try std.testing.expectEqual(@as(u32, 0), first.state_consume_mask);
    const left_start = fixture.preprocessing.vm_frame_count;
    for (fixture.preprocessing.rows[0..left_start]) |row|
        try std.testing.expectEqual(@as(u32, 0), row.verifier_id);
    for (fixture.preprocessing.rows[left_start .. left_start + fixture.preprocessing.recursion_frame_count]) |row|
        try std.testing.expectEqual(@as(u32, 1), row.verifier_id);
    for (fixture.preprocessing.rows[left_start + fixture.preprocessing.recursion_frame_count ..]) |row|
        try std.testing.expectEqual(@as(u32, 2), row.verifier_id);

    fixture.preprocessing.rows[0].input_state_key = 1;
    try std.testing.expectError(
        error.InvalidPreprocessedRow,
        fixture.preprocessing.validate(),
    );
    fixture.preprocessing.rows[0].input_state_key = 0;
    try fixture.preprocessing.validate();
}

test "R-012 transcript state witnesses satisfy every row in every proof kind" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const direct = try direct_program.authenticate(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        component.LOGICAL_INPUT_COUNT,
    );
    const sources = [_]witness.Source{
        fixture.segmentSource(),
        fixture.binarySource(),
        .{ .empty_leaf = {} },
    };
    for (sources) |source_value| {
        var main = try witness.MainWitness.init(
            std.testing.allocator,
            &fixture.preprocessing,
            source_value,
        );
        defer main.deinit();
        try main.validateAgainstSource(&fixture.preprocessing, source_value);
        var scratch: [direct_program.MAX_NODES]M31 = undefined;
        var roots: [component.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
        for (main.rows, fixture.preprocessing.rows) |row, metadata| {
            try direct.evaluateBaseInto(
                &witness.logicalInputs(row, metadata, main.proof_kind),
                &scratch,
                &roots,
            );
            for (roots) |root| try std.testing.expect(root.isZero());
        }
    }
}

test "R-012 transcript state relations cancel binding state-chain and draw consumers" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var state_main = try witness.MainWitness.init(
        std.testing.allocator,
        &fixture.preprocessing,
        fixture.segmentSource(),
    );
    defer state_main.deinit();
    var binding_main = try binding_witness.MainWitness.init(
        std.testing.allocator,
        &fixture.call_preprocessing,
        fixture.segmentBindingSource(),
    );
    defer binding_main.deinit();
    var state_definition = try component.build(std.testing.allocator);
    defer state_definition.deinit();
    const state_plan = try interaction_mod.authenticate(&state_definition);
    var binding_definition = try binding_component.build(std.testing.allocator);
    defer binding_definition.deinit();
    const binding_plan = try binding_relation.authenticate(&binding_definition);

    const state_entries = try state_plan.entries(
        &state_definition.arena,
        component.SEMANTIC_DIGEST,
        state_definition.events,
        witness.logicalInputs(
            state_main.rows[0],
            fixture.preprocessing.rows[0],
            .segment_leaf,
        ),
    );
    const binding_last = findCall(
        fixture.call_preprocessing.rows[0..fixture.call_preprocessing.vm_call_count],
        fixture.preprocessing.rows[0].hash_id,
        true,
    ).?;
    const binding_entries = try binding_plan.entries(
        &binding_definition.arena,
        binding_component.SEMANTIC_DIGEST,
        binding_definition.events,
        binding_witness.logicalInputs(
            binding_main.rows[binding_last],
            fixture.call_preprocessing.rows[binding_last],
            .segment_leaf,
        ),
    );
    try expectEntryCancellation(state_entries[0], binding_entries[3]);
    const binding_first = findCall(
        fixture.call_preprocessing.rows[0..fixture.call_preprocessing.vm_call_count],
        fixture.preprocessing.rows[0].hash_id,
        false,
    ).?;
    const first_binding_entries = try binding_plan.entries(
        &binding_definition.arena,
        binding_component.SEMANTIC_DIGEST,
        binding_definition.events,
        binding_witness.logicalInputs(
            binding_main.rows[binding_first],
            fixture.call_preprocessing.rows[binding_first],
            .segment_leaf,
        ),
    );
    try expectEntryCancellation(state_entries[4], first_binding_entries[6]);

    const producer_index = findDoubleProducer(
        fixture.preprocessing.rows[0..fixture.preprocessing.vm_frame_count],
    ).?;
    const producer = try stateEntriesAt(
        &state_plan,
        &state_definition,
        &state_main,
        &fixture.preprocessing,
        producer_index,
    );
    const draw = try stateEntriesAt(
        &state_plan,
        &state_definition,
        &state_main,
        &fixture.preprocessing,
        producer_index + 1,
    );
    const next = try stateEntriesAt(
        &state_plan,
        &state_definition,
        &state_main,
        &fixture.preprocessing,
        producer_index + 2,
    );
    try std.testing.expect(producer[3].numerator
        .add(draw[2].numerator).add(next[2].numerator).isZero());
    try expectSameTuple(producer[3], draw[2]);
    try expectSameTuple(producer[3], next[2]);

    const challenge_index = findDrawTag(
        fixture.preprocessing.rows[0..fixture.preprocessing.vm_frame_count],
        7,
    ).?;
    const challenge_metadata = fixture.preprocessing.rows[challenge_index];
    const challenge_state_entries = try stateEntriesAt(
        &state_plan,
        &state_definition,
        &state_main,
        &fixture.preprocessing,
        challenge_index,
    );
    var challenge_definition = try challenge_component.build(std.testing.allocator);
    defer challenge_definition.deinit();
    const challenge_plan = try challenge_relation.authenticate(&challenge_definition);
    const challenge_entries = try challenge_plan.entries(
        &challenge_definition.arena,
        challenge_component.SEMANTIC_DIGEST,
        challenge_definition.events,
        challenge_witness.logicalInputs(
            .{ .enabler = 1, .outputs = state_main.rows[challenge_index].outputs },
            .{
                .row_mask = 1,
                .segment_mask = 1,
                .binary_mask = 0,
                .public_logup_mask = @intFromBool(challenge_metadata.args[0] < 4),
                .verifier_id = challenge_metadata.verifier_id,
                .sequence = challenge_metadata.sequence,
                .tag = challenge_metadata.tag,
                .args = challenge_metadata.args,
                .challenge = challenge_metadata.args[0],
            },
            .segment_leaf,
        ),
    );
    try expectEntryCancellation(challenge_state_entries[1], challenge_entries[0]);
}

test "R-012 transcript state rejects direct tuple and compiled-entry mutations" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var main = try witness.MainWitness.init(
        std.testing.allocator,
        &fixture.preprocessing,
        fixture.segmentSource(),
    );
    defer main.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const compiled = try direct_program.authenticate(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        component.LOGICAL_INPUT_COUNT,
    );
    const plan = try interaction_mod.authenticate(&definition);
    const inactive_index = fixture.preprocessing.vm_frame_count;
    const inactive = witness.logicalInputs(
        main.rows[inactive_index],
        fixture.preprocessing.rows[inactive_index],
        .segment_leaf,
    );
    var scratch: [direct_program.MAX_NODES]M31 = undefined;
    var roots: [component.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    for (0..component.PHYSICAL_MAIN_COLUMN_COUNT) |column| {
        var changed = inactive;
        changed[column] = if (column == 0) M31.zero() else M31.one();
        try compiled.evaluateBaseInto(&changed, &scratch, &roots);
        var rejected = false;
        for (roots) |root| rejected = rejected or !root.isZero();
        try std.testing.expect(rejected);
    }
    var initial = witness.logicalInputs(
        main.rows[0],
        fixture.preprocessing.rows[0],
        .segment_leaf,
    );
    initial[1] = M31.one();
    try compiled.evaluateBaseInto(&initial, &scratch, &roots);
    try std.testing.expect(!roots[1 + 2 * component.RATE].isZero());

    const row_index = findNonInitialActive(
        fixture.preprocessing.rows[0..fixture.preprocessing.vm_frame_count],
    ).?;
    const honest_row = witness.logicalInputs(
        main.rows[row_index],
        fixture.preprocessing.rows[row_index],
        .segment_leaf,
    );
    const honest = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        honest_row,
    );
    for (1..component.PHYSICAL_MAIN_COLUMN_COUNT) |column| {
        var changed = honest_row;
        changed[column] = changed[column].add(M31.one());
        const forged = try plan.entries(
            &definition.arena,
            component.SEMANTIC_DIGEST,
            definition.events,
            changed,
        );
        var tuple_changed = false;
        for (honest, forged) |lhs, rhs| {
            for (0..lhs.arity) |index|
                tuple_changed = tuple_changed or !lhs.values[index].eql(rhs.values[index]);
        }
        try std.testing.expect(tuple_changed);
    }
    var forged_entries = honest;
    forged_entries[0].role = .emit;
    try std.testing.expectError(
        error.EntryRoleMismatch,
        plan.validateEntries(
            &definition.arena,
            component.SEMANTIC_DIGEST,
            definition.events,
            honest_row,
            forged_entries,
        ),
    );
    forged_entries = honest;
    forged_entries[0].values[0] = forged_entries[0].values[0].add(QM31.one());
    try std.testing.expectError(
        error.EntryTupleMismatch,
        plan.validateEntries(
            &definition.arena,
            component.SEMANTIC_DIGEST,
            definition.events,
            honest_row,
            forged_entries,
        ),
    );
}

test "R-012 transcript state cold preparation is one allocation and writers are atomic" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var measured_pp = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var preprocessing = try witness.Preprocessed.init(
        measured_pp.allocator(),
        &fixture.call_preprocessing,
    );
    defer preprocessing.deinit();
    try std.testing.expectEqual(@as(usize, 1), measured_pp.alloc_index);
    var measured_main = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var main = try witness.MainWitness.init(
        measured_main.allocator(),
        &preprocessing,
        fixture.binarySource(),
    );
    defer main.deinit();
    try std.testing.expectEqual(@as(usize, 1), measured_main.alloc_index);
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    try assertPreprocessedWriter(&executor, &preprocessing);
    try assertMainWriter(&executor, &main, &preprocessing);

    var changed = binding;
    changed.main[0] = changed.main[1];
    try std.testing.expectError(
        error.BindingMismatch,
        witness.Executor.init(&definition, &changed),
    );
}

test "R-012 transcript state rejects schedule transcript receipt and snapshot mutations" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var main = try witness.MainWitness.init(
        std.testing.allocator,
        &fixture.preprocessing,
        fixture.segmentSource(),
    );
    defer main.deinit();
    main.rows[1].inputs[0] = main.rows[1].inputs[0].add(M31.one());
    try std.testing.expectError(
        error.AuthorityMismatch,
        main.validateAgainst(&fixture.preprocessing),
    );
    main.rows[1].inputs[0] = main.rows[1].inputs[0].sub(M31.one());
    try main.validateAgainst(&fixture.preprocessing);

    fixture.segment.word_storage[0][8] = fixture.segment.word_storage[0][8].add(M31.one());
    try std.testing.expectError(
        error.InvalidTranscriptTrace,
        main.validateAgainstSource(&fixture.preprocessing, fixture.segmentSource()),
    );
    fixture.segment.word_storage[0][8] = fixture.segment.word_storage[0][8].sub(M31.one());
    try main.validateAgainstSource(&fixture.preprocessing, fixture.segmentSource());

    fixture.call_preprocessing.authority_digest[0] ^= 1;
    try std.testing.expectError(
        error.AuthorityMismatch,
        fixture.preprocessing.validateAgainst(&fixture.call_preprocessing),
    );
    fixture.call_preprocessing.authority_digest[0] ^= 1;
    try fixture.preprocessing.validateAgainst(&fixture.call_preprocessing);
}

test "R-012 transcript state interaction is bounded and releases every OOM path" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var main = try witness.MainWitness.init(
        std.testing.allocator,
        &fixture.preprocessing,
        fixture.segmentSource(),
    );
    defer main.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    const rows = try std.testing.allocator.alloc(
        interaction_mod.Row,
        fixture.preprocessing.rows.len,
    );
    defer std.testing.allocator.free(rows);
    for (rows, main.rows, fixture.preprocessing.rows) |*target, main_row, metadata|
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
            fixture.preprocessing.log_size,
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
            fixture.preprocessing.log_size,
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
        .{&fixture.call_preprocessing},
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        mainFailureCase,
        .{ &fixture.preprocessing, fixture.segmentSource() },
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        interactionFailureCase,
        .{
            &definition,
            &plan,
            rows,
            fixture.preprocessing.log_size,
            &relations,
        },
    );
}
