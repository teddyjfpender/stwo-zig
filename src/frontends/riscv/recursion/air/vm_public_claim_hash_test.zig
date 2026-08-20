//! Exactness, cancellation, adversarial, and performance gates for row 13.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const compat = @import("../../air/lang/typed_poseidon2_compat.zig");
const degree = @import("../../air/lang/degree.zig");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const materializer = @import("../../air/lang/degree3_materializer.zig");
const poseidon_typed = @import("../../air/lang/typed_poseidon2.zig");
const poseidon_witness = @import("../../air/lang/typed_poseidon2_witness.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const types = @import("../../air/lang/types.zig");
const poseidon_production = @import("../../air/memory_commitment/poseidon2_air.zig");
const poseidon_channel = @import("../poseidon2_channel.zig");
const component = @import("vm_public_claim_hash.zig");
const interaction_mod = @import("vm_public_claim_hash_relation.zig");
const claim_input = @import("vm_public_claim_input_witness.zig");
const support = @import("test_support.zig");
const universal = @import("universal_challenges.zig");
const witness = @import("vm_public_claim_hash_witness.zig");

const SHAPE = claim_input.Shape{ .max_input_words = 2, .max_output_words = 2 };
const WORD_COUNT = claim_input.FIXED_CLAIM_WORDS +
    2 * claim_input.INPUT_SLOT_WORDS + 2 * claim_input.OUTPUT_SLOT_WORDS;
const HASH_ROW_COUNT = (WORD_COUNT + 1 + component.RATE - 1) / component.RATE;

const test_support = @import("vm_public_claim_hash_test_support.zig");
const Fixture = test_support.Fixture;
const fixtureWords = test_support.fixtureWords;
const expectSatisfied = test_support.expectSatisfied;
const expectRejected = test_support.expectRejected;
const completeRelationSum = test_support.completeRelationSum;
const sourceTerm = test_support.sourceTerm;
const permutationInput = test_support.permutationInput;
const OwnedColumns = test_support.OwnedColumns;
const expectPaddingZero = test_support.expectPaddingZero;
const PoseidonHarness = test_support.PoseidonHarness;
const PoseidonFixture = test_support.PoseidonFixture;
const distinctSpans = test_support.distinctSpans;
const spanAt = test_support.spanAt;
const componentFailureCase = test_support.componentFailureCase;
const preprocessingFailureCase = test_support.preprocessingFailureCase;
const witnessFailureCase = test_support.witnessFailureCase;
const interactionFailureCase = test_support.interactionFailureCase;

test "R-012 VM public-claim hash preserves pinned row-13 geometry and seals" {
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
    try std.testing.expectEqual(@as(usize, 41), definition.main.physical().len);
    try std.testing.expectEqual(@as(usize, 28), definition.preprocessed.physical().len);
    try std.testing.expectEqual(@as(usize, 5), definition.parameters.physical().len);
    try std.testing.expectEqual(@as(usize, 65), definition.constraints.len);
    try std.testing.expectEqual(@as(usize, 19), definition.events.len);
    const identity_value = try digest.computeIdentity(&definition.arena);
    try std.testing.expectEqualStrings(
        component.SEMANTIC_DIGEST_HEX,
        &std.fmt.bytesToHex(identity_value.bytes, .lower),
    );
    var degrees = try degree.analyze(std.testing.allocator, &definition.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(
        @as(degree.Degree, component.MAXIMUM_CONSTRAINT_DEGREE),
        degrees.maximumConstraintDegree(),
    );
    const binding = try witness.Binding.canonical(&definition);
    try std.testing.expectEqualStrings(
        witness.BINDING_DIGEST_HEX,
        &std.fmt.bytesToHex(binding.identityDigest(), .lower),
    );
    _ = try witness.Executor.init(&definition, &binding);
    const plan = try interaction_mod.authenticate(&definition);
    try std.testing.expectEqual(@as(usize, 10), interaction_mod.Runtime.BATCH_COUNT);
    try std.testing.expectEqual(@as(usize, 40), interaction_mod.Runtime.INTERACTION_COLUMN_COUNT);
    const expected_domains = [_]relation.Domain{
        .poseidon2_io,
        .recursion_vm_public_claim_word,
        .recursion_vm_public_claim_word,
        .recursion_vm_public_claim_word,
        .recursion_vm_public_claim_word,
        .recursion_vm_public_claim_word,
        .recursion_vm_public_claim_word,
        .recursion_vm_public_claim_word,
        .recursion_vm_public_claim_word,
        .recursion_vm_public_claim_hash_state,
        .recursion_vm_public_claim_hash_state,
        .recursion_verifier_input_word,
        .recursion_verifier_input_word,
        .recursion_verifier_input_word,
        .recursion_verifier_input_word,
        .recursion_verifier_input_word,
        .recursion_verifier_input_word,
        .recursion_verifier_input_word,
        .recursion_verifier_input_word,
    };
    for (plan.events, expected_domains, 0..) |event, domain, index| {
        try std.testing.expectEqual(@as(u8, @intCast(index)), event.ordinal);
        try std.testing.expectEqual(domain, event.domain);
        try std.testing.expectEqual(
            if (index == 0) relation.Role.request else if (index == 10)
                relation.Role.emit
            else
                relation.Role.consume,
            event.role,
        );
    }
}

test "R-012 VM public-claim hash static profile is exact and closed" {
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
    try std.testing.expectEqual(
        @as(u32, component.LOGICAL_INPUT_COUNT),
        profile.logical_input_nodes,
    );
    try std.testing.expectEqual(@as(u32, 65), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 19), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 10), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 40), profile.interaction_columns);
    try std.testing.expectEqual(@as(u32, 3), profile.maximum_logical_constraint_degree);
    try std.testing.expectEqual(@as(u32, 0), profile.nodes_outside_constraint_effect_closure);
    if (std.mem.allEqual(u8, component.STATIC_PROFILE_DIGEST_HEX, '0')) {
        std.debug.print("\nprofile={s} nodes={d} edges={d} shared={d} outside={d}\n", .{
            std.fmt.bytesToHex(profile.profile_digest, .lower),
            profile.expression_dag_nodes,
            profile.expression_dag_edges,
            profile.expression_dag_shared_nodes,
            profile.nodes_outside_constraint_effect_closure,
        });
    } else try std.testing.expectEqualStrings(
        component.STATIC_PROFILE_DIGEST_HEX,
        &std.fmt.bytesToHex(profile.profile_digest, .lower),
    );
}

test "R-012 VM public-claim hash schedule derives marker and padding from row 12" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try fixture.preprocessing.validateAgainst(&fixture.claim_preprocessing);
    try std.testing.expectEqual(@as(usize, HASH_ROW_COUNT), fixture.preprocessing.rows.len);
    try std.testing.expectEqual(@as(u32, 6), fixture.preprocessing.log_size);
    const first = fixture.preprocessing.rows[0];
    try std.testing.expectEqual(@as(u32, 1), first.first);
    try std.testing.expectEqual(@as(u32, 0), first.last);
    for (first.chunks, 0..) |chunk, index| {
        try std.testing.expectEqual(@as(u32, 1), chunk.source_mask);
        try std.testing.expectEqual(@as(u32, @intCast(index)), chunk.word_index);
        try std.testing.expectEqual(@as(u32, 0), chunk.constant);
    }
    const marker_row = WORD_COUNT / component.RATE;
    const marker_slot = WORD_COUNT % component.RATE;
    const last = fixture.preprocessing.rows[marker_row];
    try std.testing.expectEqual(@as(u32, 1), last.last);
    try std.testing.expectEqual(@as(u32, 0), last.chunks[marker_slot].source_mask);
    try std.testing.expectEqual(@as(u32, 1), last.chunks[marker_slot].constant);
    for (last.chunks[marker_slot + 1 ..]) |chunk| {
        try std.testing.expectEqual(@as(u32, 0), chunk.source_mask);
        try std.testing.expectEqual(@as(u32, 0), chunk.constant);
    }

    fixture.preprocessing.rows[0].chunks[0].word_index = 1;
    try std.testing.expectError(error.AuthorityMismatch, fixture.preprocessing.validate());
}

test "R-012 VM public-claim hash materializes exact state chain in every mode" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const cases = [_]witness.Source{
        .{ .segment_leaf = &fixture.words },
        .{ .binary_node = {} },
        .{ .empty_leaf = {} },
    };
    for (cases) |source_value| {
        var main = try witness.MainWitness.init(
            std.testing.allocator,
            &fixture.preprocessing,
            source_value,
        );
        defer main.deinit();
        try main.validateAgainstSource(&fixture.preprocessing, source_value);
        for (main.rows, fixture.preprocessing.rows) |main_row, metadata| {
            if (source_value.proofKind() == .segment_leaf) {
                try std.testing.expectEqual(@as(u32, 1), main_row.enabler);
            } else {
                for (main_row.values()) |word| try std.testing.expect(word.isZero());
            }
            var definition = try component.build(std.testing.allocator);
            defer definition.deinit();
            try expectSatisfied(
                &definition,
                witness.logicalInputs(main_row, metadata, source_value.proofKind()),
            );
        }
    }
}

test "R-012 VM public-claim hash wire admission rejects missing inactive and wrong-size claims" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try std.testing.expectError(
        error.SegmentClaimMissing,
        witness.MainWitness.initRaw(
            std.testing.allocator,
            &fixture.preprocessing,
            .segment_leaf,
            null,
        ),
    );
    try std.testing.expectError(
        error.InactiveClaimProvided,
        witness.MainWitness.initRaw(
            std.testing.allocator,
            &fixture.preprocessing,
            .binary_node,
            &fixture.words,
        ),
    );
    try std.testing.expectError(
        error.WordCountMismatch,
        witness.MainWitness.initRaw(
            std.testing.allocator,
            &fixture.preprocessing,
            .segment_leaf,
            fixture.words[0 .. fixture.words.len - 1],
        ),
    );
}

test "R-012 VM public-claim hash direct roots reject domain marker and inactive mutations" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    var active = try witness.MainWitness.init(
        std.testing.allocator,
        &fixture.preprocessing,
        .{ .segment_leaf = &fixture.words },
    );
    defer active.deinit();

    var mutated = active.rows[0];
    mutated.previous[component.STATE_WIDTH - 1] = M31.zero();
    try expectRejected(
        &definition,
        witness.logicalInputs(mutated, fixture.preprocessing.rows[0], .segment_leaf),
    );
    const marker_row = WORD_COUNT / component.RATE;
    const marker_slot = WORD_COUNT % component.RATE;
    mutated = active.rows[marker_row];
    mutated.chunks[marker_slot] = M31.zero();
    try expectRejected(
        &definition,
        witness.logicalInputs(
            mutated,
            fixture.preprocessing.rows[marker_row],
            .segment_leaf,
        ),
    );
    mutated = witness.MainRow{
        .enabler = 0,
        .previous = .{M31.zero()} ** component.STATE_WIDTH,
        .chunks = .{M31.zero()} ** component.RATE,
        .output = .{M31.zero()} ** component.STATE_WIDTH,
    };
    mutated.previous[0] = M31.one();
    try expectRejected(
        &definition,
        witness.logicalInputs(mutated, fixture.preprocessing.rows[0], .empty_leaf),
    );
}

test "R-012 VM public-claim hash relation weights and internal chain are exact" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    var main = try witness.MainWitness.init(
        std.testing.allocator,
        &fixture.preprocessing,
        .{ .segment_leaf = &fixture.words },
    );
    defer main.deinit();

    const first_entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        witness.logicalInputs(main.rows[0], fixture.preprocessing.rows[0], .segment_leaf),
    );
    try std.testing.expect(first_entries[0].numerator.eql(QM31.one().neg()));
    for (first_entries[1..9]) |entry|
        try std.testing.expect(entry.numerator.eql(QM31.one().neg()));
    try std.testing.expect(first_entries[9].numerator.isZero());
    try std.testing.expect(first_entries[10].numerator.eql(QM31.one()));
    for (first_entries[11..]) |entry| try std.testing.expect(entry.numerator.isZero());

    const second_entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        witness.logicalInputs(main.rows[1], fixture.preprocessing.rows[1], .segment_leaf),
    );
    try std.testing.expect(second_entries[9].numerator.eql(QM31.one().neg()));
    for (
        first_entries[10].values[0..first_entries[10].arity],
        second_entries[9].values[0..second_entries[9].arity],
    ) |emitted, consumed| try std.testing.expect(emitted.eql(consumed));

    const last_index = main.rows.len - 1;
    const last_entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        witness.logicalInputs(
            main.rows[last_index],
            fixture.preprocessing.rows[last_index],
            .segment_leaf,
        ),
    );
    try std.testing.expect(last_entries[9].numerator.eql(QM31.one().neg()));
    try std.testing.expect(last_entries[10].numerator.isZero());
    for (last_entries[11..]) |entry|
        try std.testing.expect(entry.numerator.eql(QM31.one().neg()));
}

test "R-012 complete VM claim hash relations cancel with row 12 transcript and Poseidon" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    var main = try witness.MainWitness.init(
        std.testing.allocator,
        &fixture.preprocessing,
        .{ .segment_leaf = &fixture.words },
    );
    defer main.deinit();
    const relations = universal.UniversalRelations.dummy();
    const total = try completeRelationSum(
        &definition,
        &plan,
        &fixture,
        &main,
        &relations,
        false,
    );
    try std.testing.expect(total.isZero());
    const tampered = try completeRelationSum(
        &definition,
        &plan,
        &fixture,
        &main,
        &relations,
        true,
    );
    try std.testing.expect(!tampered.isZero());
}

test "R-012 VM public-claim hash reuses exact shared Poseidon provider calls" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    var main = try witness.MainWitness.init(
        std.testing.allocator,
        &fixture.preprocessing,
        .{ .segment_leaf = &fixture.words },
    );
    defer main.deinit();
    for (main.poseidon_calls, main.rows) |call, row| {
        try std.testing.expect(!call.wide);
        try std.testing.expect(call.io);
        try std.testing.expect(call.narrow_output == null);
        const provider_row = poseidon_production.fill(call);
        try std.testing.expectEqualSlices(
            M31,
            &row.output,
            &poseidon_production.output(provider_row),
        );
    }
    const expected_digest = poseidon_channel.hashCanonicalWords(
        &fixture.words,
        component.VM_PUBLIC_CLAIM_HASH_DOMAIN,
    );
    try main.validateDigest(&fixture.preprocessing, expected_digest);
    var wrong_digest = expected_digest;
    wrong_digest[0] = M31.fromCanonical(wrong_digest[0]).add(M31.one()).toU32();
    try std.testing.expectError(
        error.DigestMismatch,
        main.validateDigest(&fixture.preprocessing, wrong_digest),
    );

    var provider_harness = try PoseidonHarness.init(std.testing.allocator);
    defer provider_harness.deinit();
    var provider = try provider_harness.makeExecutor(std.testing.allocator);
    defer provider.deinit();
    const size = @as(usize, 1) << @intCast(fixture.preprocessing.log_size);
    var actual = try OwnedColumns(witness.POSEIDON_MAIN_COLUMN_COUNT).init(
        std.testing.allocator,
        size,
        M31.fromCanonical(0x5151),
    );
    defer actual.deinit();
    try executor.generatePoseidonProviderInto(
        &main,
        &fixture.preprocessing,
        &provider,
        &actual.views,
    );
    var expected = try poseidon_production.generateMain(
        std.testing.allocator,
        main.poseidon_calls,
        fixture.preprocessing.log_size,
    );
    defer expected.deinit(std.testing.allocator);
    for (actual.views, expected.values) |actual_column, expected_column|
        try std.testing.expectEqualSlices(M31, expected_column, actual_column);
}

test "R-012 VM public-claim hash writers allocate nothing and fail atomically" {
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var claim_preprocessing = try claim_input.Preprocessed.init(measured.allocator(), SHAPE);
    defer claim_preprocessing.deinit();
    var preprocessing = try witness.Preprocessed.init(
        measured.allocator(),
        &claim_preprocessing,
    );
    defer preprocessing.deinit();
    const words = fixtureWords(&claim_preprocessing);
    var main = try witness.MainWitness.init(
        measured.allocator(),
        &preprocessing,
        .{ .segment_leaf = &words },
    );
    defer main.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const size = @as(usize, 1) << @intCast(preprocessing.log_size);

    var pp = try OwnedColumns(component.PREPROCESSED_COLUMN_COUNT).init(
        std.testing.allocator,
        size,
        M31.fromCanonical(0x1111),
    );
    defer pp.deinit();
    const before_pp = measured.alloc_index;
    try executor.generatePreprocessedInto(&preprocessing, &pp.views);
    try std.testing.expectEqual(before_pp, measured.alloc_index);
    try expectPaddingZero(&pp.views, preprocessing.rows.len);

    var main_columns = try OwnedColumns(component.PHYSICAL_MAIN_COLUMN_COUNT).init(
        std.testing.allocator,
        size,
        M31.fromCanonical(0x2222),
    );
    defer main_columns.deinit();
    const before_main = measured.alloc_index;
    try executor.generateMainInto(&main, &preprocessing, &main_columns.views);
    try std.testing.expectEqual(before_main, measured.alloc_index);
    try expectPaddingZero(&main_columns.views, main.rows.len);

    const sentinel = M31.fromCanonical(0x3333);
    @memset(main_columns.slab, sentinel);
    const full = main_columns.views[0];
    const second_full = main_columns.views[1];
    main_columns.views[0] = full[0 .. size - 1];
    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generateMainInto(&main, &preprocessing, &main_columns.views),
    );
    for (main_columns.slab) |word| try std.testing.expect(word.eql(sentinel));
    main_columns.views[0] = full;
    main_columns.views[1] = main_columns.views[0];
    try std.testing.expectError(
        error.AliasedDestination,
        executor.generateMainInto(&main, &preprocessing, &main_columns.views),
    );
    for (main_columns.slab) |word| try std.testing.expect(word.eql(sentinel));

    main_columns.views[1] = second_full;
    main.rows[0].previous[0] = M31.one();
    try std.testing.expectError(
        error.InvalidWitnessRow,
        executor.generateMainInto(&main, &preprocessing, &main_columns.views),
    );
    for (main_columns.slab) |word| try std.testing.expect(word.eql(sentinel));
}

test "R-012 VM public-claim hash interaction and construction release every failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        componentFailureCase,
        .{},
    );
    var claim_preprocessing = try claim_input.Preprocessed.init(std.testing.allocator, SHAPE);
    defer claim_preprocessing.deinit();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        preprocessingFailureCase,
        .{&claim_preprocessing},
    );
    var preprocessing = try witness.Preprocessed.init(
        std.testing.allocator,
        &claim_preprocessing,
    );
    defer preprocessing.deinit();
    const words = fixtureWords(&claim_preprocessing);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        witnessFailureCase,
        .{ &preprocessing, &words },
    );

    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    var main = try witness.MainWitness.init(
        std.testing.allocator,
        &preprocessing,
        .{ .segment_leaf = &words },
    );
    defer main.deinit();
    const rows = try std.testing.allocator.alloc(interaction_mod.Row, main.rows.len);
    defer std.testing.allocator.free(rows);
    for (rows, main.rows, preprocessing.rows) |*row, main_row, metadata|
        row.* = witness.logicalInputs(main_row, metadata, .segment_leaf);
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
        try std.testing.expectEqual(@as(usize, 10), interaction.claims.sums.len);
        try std.testing.expectEqual(@as(usize, 40), interaction.columns.len);
    }
    try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        interactionFailureCase,
        .{ &definition, &plan, rows, preprocessing.log_size, &relations },
    );
}
