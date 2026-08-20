//! Exactness, schedule, mutation, and performance gates for universal row 2.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const degree = @import("../../air/lang/degree.zig");
const digest = @import("../../air/lang/digest.zig");
const relation = @import("../../air/lang/relation.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const types = @import("../../air/lang/types.zig");
const component = @import("transcript_binding.zig");
const direct_program = @import("direct_constraint_program.zig");
const interaction_mod = @import("transcript_binding_relation.zig");
const pow_frame = @import("pow_frame.zig");
const pow_frame_relation = @import("pow_frame_relation.zig");
const pow_frame_witness = @import("pow_frame_witness.zig");
const pow_check_witness = @import("pow_check_witness.zig");
const schedule = @import("verifier_schedule.zig");
const universal = @import("universal_challenges.zig");
const witness = @import("transcript_binding_witness.zig");

const test_support = @import("transcript_binding_test_support.zig");
const Fixture = test_support.Fixture;
const OwnedTrace = test_support.OwnedTrace;
const fillFrameWords = test_support.fillFrameWords;
const testStreamWordCount = test_support.testStreamWordCount;
const mulFour = test_support.mulFour;
const findPowFinal = test_support.findPowFinal;
const findLast = test_support.findLast;
const findCheck = test_support.findCheck;
const testShape = test_support.testShape;
const assertPreprocessedWriter = test_support.assertPreprocessedWriter;
const assertMainWriter = test_support.assertMainWriter;
const assertMalformedPreprocessedWriter = test_support.assertMalformedPreprocessedWriter;
const splitColumns = test_support.splitColumns;
const componentFailureCase = test_support.componentFailureCase;
const preprocessingFailureCase = test_support.preprocessingFailureCase;
const mainFailureCase = test_support.mainFailureCase;
const interactionFailureCase = test_support.interactionFailureCase;

test "R-012 transcript binding preserves exact row-2 geometry and source seals" {
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
    try std.testing.expectEqual(@as(usize, 18), definition.preprocessed.physical().len);
    try std.testing.expectEqual(@as(usize, 2), definition.parameters.physical().len);
    try std.testing.expectEqual(@as(usize, 25), definition.constraints.len);
    try std.testing.expectEqual(@as(usize, 14), definition.events.len);
    var degrees = try degree.analyze(std.testing.allocator, &definition.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(
        @as(degree.Degree, component.MAXIMUM_CONSTRAINT_DEGREE),
        degrees.maximumConstraintDegree(),
    );
    try std.testing.expectEqualStrings(
        component.SEMANTIC_DIGEST_HEX,
        &std.fmt.bytesToHex((try digest.computeIdentity(&definition.arena)).bytes, .lower),
    );

    const plan = try interaction_mod.authenticate(&definition);
    const domains = [component.RELATION_EVENT_COUNT]relation.Domain{
        .recursion_hash_call_control,
        .recursion_hash_data,
        .recursion_hash_output,
        .recursion_transcript_frame_output,
        .recursion_transcript_pow_frame,
        .recursion_step,
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
        .emit,
        .emit,
        .consume,
        .emit,
        .emit,
        .consume,
        .consume,
        .consume,
        .consume,
        .consume,
        .consume,
        .consume,
        .consume,
        .consume,
    };
    for (plan.events, domains, roles, 0..) |event, domain, role, index| {
        try std.testing.expectEqual(@as(u8, @intCast(index)), event.ordinal);
        try std.testing.expectEqual(domain, event.domain);
        try std.testing.expectEqual(role, event.role);
    }
    try std.testing.expectEqual(@as(usize, 7), interaction_mod.Runtime.BATCH_COUNT);
    try std.testing.expectEqual(@as(usize, 28), interaction_mod.Runtime.INTERACTION_COLUMN_COUNT);

    const binding = try witness.Binding.canonical(&definition);
    _ = try witness.Executor.init(&definition, &binding);
    try std.testing.expectEqualStrings(
        witness.BINDING_DIGEST_HEX,
        &std.fmt.bytesToHex(binding.identityDigest(), .lower),
    );
}

test "R-012 transcript binding static profile is exact and parameter-aware" {
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
    try std.testing.expectEqual(@as(u32, 37), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 25), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 14), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 7), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 28), profile.interaction_columns);
    try std.testing.expectEqual(@as(u32, 3), profile.maximum_logical_constraint_degree);
    // The generic profiler conservatively gives embedded proof-kind parameters
    // trace degree one. They are verifier constants in the actual adapter, so
    // this modeled four becomes the pinned framework degree three.
    try std.testing.expectEqual(@as(?u32, 4), profile.maximum_modeled_interaction_degree);
    try std.testing.expectEqual(@as(u32, 86), profile.expression_dag_nodes);
    try std.testing.expectEqual(@as(u32, 82), profile.expression_dag_edges);
    try std.testing.expectEqual(@as(u32, 14), profile.expression_dag_shared_nodes);
    try std.testing.expectEqual(@as(u32, 0), profile.nodes_outside_constraint_effect_closure);
    try std.testing.expectEqualStrings(
        component.STATIC_PROFILE_DIGEST_HEX,
        &std.fmt.bytesToHex(profile.profile_digest, .lower),
    );
}

test "R-012 transcript preprocessing derives the exact three-lane call layout" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try std.testing.expectEqual(@as(usize, 287), fixture.preprocessing.vm_call_count);
    try std.testing.expectEqual(@as(usize, 286), fixture.preprocessing.recursion_call_count);
    try std.testing.expectEqual(@as(usize, 859), fixture.preprocessing.rows.len);
    try std.testing.expectEqual(@as(u32, 10), fixture.preprocessing.log_size);
    try fixture.preprocessing.validateAgainst(&fixture.vm, &fixture.recursion);
    try std.testing.expectEqual(
        fixture.preprocessing.vm_call_count + 2 * fixture.preprocessing.recursion_call_count,
        fixture.preprocessing.rows.len,
    );
    try std.testing.expect(fixture.preprocessing.log_size >= witness.MIN_LOG_SIZE);
    const first = fixture.preprocessing.rows[0];
    try std.testing.expectEqual(@as(u32, 0), first.verifier_id);
    try std.testing.expectEqual(@as(u32, 0), first.sequence);
    try std.testing.expectEqual(@as(u32, 1), first.tag);
    try std.testing.expectEqual(@as(u32, 0), first.call_id);
    try std.testing.expectEqual(@as(u32, 0), first.hash_id);
    try std.testing.expectEqual(@as(u32, 0), first.hash_step);
    try std.testing.expectEqual(@as(u32, 1), first.is_first);
    try std.testing.expectEqual(@as(u32, 1), first.is_operation_first);
    // BindProtocol owns 8 digest + 8 header + 16 protocol/shape words and
    // therefore exactly five rate calls after the mandatory sponge marker.
    const statement_first = fixture.preprocessing.rows[5];
    try std.testing.expectEqual(@as(u32, 1), statement_first.sequence);
    try std.testing.expectEqual(@as(u32, 2), statement_first.tag);
    try std.testing.expectEqual(@as(u32, 5), statement_first.call_id);
    try std.testing.expectEqual(@as(u32, 1), statement_first.hash_id);
    for (fixture.preprocessing.rows[0..fixture.preprocessing.vm_call_count]) |row|
        try std.testing.expectEqual(@as(u32, 0), row.verifier_id);
    const left_start = fixture.preprocessing.vm_call_count;
    for (fixture.preprocessing.rows[left_start .. left_start + fixture.preprocessing.recursion_call_count]) |row|
        try std.testing.expectEqual(@as(u32, 1), row.verifier_id);
    for (fixture.preprocessing.rows[left_start + fixture.preprocessing.recursion_call_count ..]) |row|
        try std.testing.expectEqual(@as(u32, 2), row.verifier_id);

    fixture.preprocessing.rows[0].hash_step = 1;
    try std.testing.expectError(
        error.InvalidPreprocessedRow,
        fixture.preprocessing.validate(),
    );
    fixture.preprocessing.rows[0].hash_step = 0;
    try fixture.preprocessing.validate();
}

test "R-012 transcript witnesses satisfy all rows in every proof kind" {
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
            const inputs = witness.logicalInputs(row, metadata, main.proof_kind);
            try direct.evaluateBaseInto(&inputs, &scratch, &roots);
            for (roots) |root| try std.testing.expect(root.isZero());
        }
    }
}

test "R-012 transcript relation fanout is compiler-owned and PoW cancels row 7" {
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

    const first_inputs = witness.logicalInputs(
        main.rows[0],
        fixture.preprocessing.rows[0],
        .segment_leaf,
    );
    const first_entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        first_inputs,
    );
    try std.testing.expect(first_entries[0].numerator.eql(QM31.one()));
    try std.testing.expect(first_entries[1].numerator.eql(QM31.one()));
    try std.testing.expect(first_entries[2].numerator.isZero());
    try std.testing.expect(first_entries[3].numerator.isZero());
    try std.testing.expect(first_entries[4].numerator.isZero());
    try std.testing.expect(first_entries[5].numerator.eql(QM31.one().neg()));
    for (first_entries[6..]) |entry|
        try std.testing.expect(entry.numerator.eql(QM31.one().neg()));

    const pow_index = findPowFinal(
        fixture.preprocessing.rows[0..fixture.preprocessing.vm_call_count],
    ).?;
    const metadata = fixture.preprocessing.rows[pow_index];
    const binding_entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        witness.logicalInputs(main.rows[pow_index], metadata, .segment_leaf),
    );
    try std.testing.expect(binding_entries[4].numerator.eql(QM31.one()));

    const check = findCheck(&fixture.segment.trace, metadata.call_id).?;
    const kind: pow_frame_witness.PowKind = if (metadata.tag == 6)
        .interaction
    else
        .pcs;
    const frame_invocation = pow_frame_witness.Invocation{
        .verifier_id = metadata.verifier_id,
        .sequence = metadata.sequence,
        .kind = kind,
        .hash_id = metadata.hash_id,
        .check = check,
        .words = main.rows[pow_index].outputs,
    };
    var frame_definition = try pow_frame.build(std.testing.allocator);
    defer frame_definition.deinit();
    const frame_plan = try pow_frame_relation.authenticate(&frame_definition);
    const frame_row = try pow_frame_witness.mainRow(frame_invocation);
    const frame_entries = try frame_plan.entries(
        &frame_definition.arena,
        pow_frame.SEMANTIC_DIGEST,
        frame_definition.events,
        frame_row,
    );
    try std.testing.expect(binding_entries[4].numerator
        .add(frame_entries[0].numerator).isZero());
    try std.testing.expectEqual(binding_entries[4].arity, frame_entries[0].arity);
    for (0..binding_entries[4].arity) |index|
        try std.testing.expect(binding_entries[4].values[index].eql(
            frame_entries[0].values[index],
        ));
}

test "R-012 transcript binding rejects direct tuple and compiled-entry mutations" {
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

    const inactive_index = fixture.preprocessing.vm_call_count;
    const inactive_inputs = witness.logicalInputs(
        main.rows[inactive_index],
        fixture.preprocessing.rows[inactive_index],
        .segment_leaf,
    );
    var scratch: [direct_program.MAX_NODES]M31 = undefined;
    var roots: [component.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    for (0..component.PHYSICAL_MAIN_COLUMN_COUNT) |column| {
        var changed = inactive_inputs;
        changed[column] = if (column == 0) M31.zero() else M31.one();
        try compiled.evaluateBaseInto(&changed, &scratch, &roots);
        var rejected = false;
        for (roots) |root| rejected = rejected or !root.isZero();
        try std.testing.expect(rejected);
    }

    const final_index = findLast(
        fixture.preprocessing.rows[0..fixture.preprocessing.vm_call_count],
    ).?;
    const honest_row = witness.logicalInputs(
        main.rows[final_index],
        fixture.preprocessing.rows[final_index],
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
    forged_entries[0].role = .consume;
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

test "R-012 transcript binding writers are allocation-free padded and atomic" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var main = try witness.MainWitness.init(
        measured.allocator(),
        &fixture.preprocessing,
        fixture.binarySource(),
    );
    defer main.deinit();
    try std.testing.expectEqual(@as(usize, 1), measured.alloc_index);
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    try assertPreprocessedWriter(&executor, &fixture.preprocessing);
    try assertMainWriter(&executor, &main, &fixture.preprocessing);

    var changed = binding;
    changed.main[0] = changed.main[1];
    try std.testing.expectError(
        error.BindingMismatch,
        witness.Executor.init(&definition, &changed),
    );
}

test "R-012 transcript binding rejects schedule transcript receipt and snapshot mutations" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var main = try witness.MainWitness.init(
        std.testing.allocator,
        &fixture.preprocessing,
        fixture.segmentSource(),
    );
    defer main.deinit();

    main.rows[0].chunks[0] = main.rows[0].chunks[0].add(M31.one());
    try std.testing.expectError(
        error.AuthorityMismatch,
        main.validateAgainst(&fixture.preprocessing),
    );
    main.rows[0].chunks[0] = main.rows[0].chunks[0].sub(M31.one());
    try main.validateAgainst(&fixture.preprocessing);

    fixture.segment.word_storage[0][8] = fixture.segment.word_storage[0][8].add(M31.one());
    try std.testing.expectError(
        error.InvalidTranscriptTrace,
        main.validateAgainstSource(&fixture.preprocessing, fixture.segmentSource()),
    );
    fixture.segment.word_storage[0][8] = fixture.segment.word_storage[0][8].sub(M31.one());
    try main.validateAgainstSource(&fixture.preprocessing, fixture.segmentSource());

    fixture.vm.authority_digest[0] ^= 1;
    try std.testing.expectError(
        error.ScheduleDigestMismatch,
        fixture.preprocessing.validateAgainst(&fixture.vm, &fixture.recursion),
    );
    fixture.vm.authority_digest[0] ^= 1;
}

test "R-012 transcript binding interaction is bounded and releases every OOM path" {
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
        .{ &fixture.vm, &fixture.recursion },
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
