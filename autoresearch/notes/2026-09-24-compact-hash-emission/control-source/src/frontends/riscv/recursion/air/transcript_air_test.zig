//! Exactness, closure, source-rigidity, and performance gates for row 1.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const degree = @import("../../air/lang/degree.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const types = @import("../../air/lang/types.zig");
const poseidon2 = @import("../../air/memory_commitment/poseidon2.zig");
const poseidon_authority = @import("../../air/lang/typed_poseidon2_proof_authority.zig");
const typed_poseidon2_witness = @import("../../air/lang/typed_poseidon2_witness.zig");
const poseidon_production = @import("../../air/memory_commitment/poseidon2_air.zig");
const fixed_profile = @import("../fixed_profile.zig");
const protocol = @import("../protocol.zig");
const channel = @import("../poseidon2_channel.zig");
const component = @import("transcript_air.zig");
const interaction_mod = @import("transcript_air_relation.zig");
const witness = @import("transcript_air_witness.zig");
const binding_component = @import("transcript_binding.zig");
const binding_interaction = @import("transcript_binding_relation.zig");
const binding_witness = @import("transcript_binding_witness.zig");
const check_witness = @import("pow_check_witness.zig");
const schedule = @import("verifier_schedule.zig");
const support = @import("test_support.zig");
const universal = @import("universal_challenges.zig");

const test_support = @import("transcript_air_test_support.zig");
const Fixture = test_support.Fixture;
const OwnedTrace = test_support.OwnedTrace;
const fillFrameWords = test_support.fillFrameWords;
const testStreamWordCount = test_support.testStreamWordCount;
const mulFour = test_support.mulFour;
const findInternal = test_support.findInternal;
const findLast = test_support.findLast;
const expectSatisfied = test_support.expectSatisfied;
const expectAnyRootNonzero = test_support.expectAnyRootNonzero;
const expectCancellation = test_support.expectCancellation;
const splitColumns = test_support.splitColumns;
const componentFailureCase = test_support.componentFailureCase;
const batchFailureCase = test_support.batchFailureCase;
const interactionFailureCase = test_support.interactionFailureCase;
const testShape = test_support.testShape;

test "R-012 transcript air pins exact source AIR binding and degree geometry" {
    const authority = component.SourceAuthority.pinned();
    try authority.validate();
    try std.testing.expectEqualStrings(
        component.SOURCE_AUTHORITY_DIGEST_HEX,
        &std.fmt.bytesToHex(authority.identityDigest(), .lower),
    );
    try std.testing.expectEqual(@as(u8, 48), authority.main_columns);
    try std.testing.expectEqual(@as(u8, 24), authority.direct_constraints);
    try std.testing.expectEqual(@as(u8, 27), authority.framework_constraints);
    try std.testing.expectEqual(@as(u8, 6), authority.relation_events);
    try std.testing.expectEqual(@as(u8, 3), authority.interaction_batches);
    try std.testing.expectEqual(@as(u8, 12), authority.interaction_columns);

    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    try std.testing.expectEqual(@as(usize, 48), definition.main.physical().len);
    try std.testing.expectEqual(@as(usize, 24), definition.constraints.len);
    try std.testing.expectEqual(@as(usize, 6), definition.events.ordered().len);
    const identity = try component.identity(std.testing.allocator);
    try std.testing.expectEqualStrings(
        component.SEMANTIC_DIGEST_HEX,
        &std.fmt.bytesToHex(identity.bytes, .lower),
    );
    var degrees = try degree.analyze(std.testing.allocator, &definition.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(
        @as(degree.Degree, 2),
        degrees.maximumConstraintDegree(),
    );
    try std.testing.expectEqual(@as(u32, 3), component.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE);

    const plan = try interaction_mod.authenticate(&definition);
    const expected_domains = [_]@import("../../air/lang/relation.zig").Domain{
        .poseidon2_io,
        .recursion_hash_call_control,
        .recursion_hash_data,
        .recursion_hash_state,
        .recursion_hash_state,
        .recursion_hash_output,
    };
    const expected_roles = [_]types.RelationRole{
        .request,
        .consume,
        .consume,
        .consume,
        .emit,
        .emit,
    };
    for (plan.events, expected_domains, expected_roles, 0..) |
        event,
        domain,
        role,
        index,
    | {
        try std.testing.expectEqual(@as(u8, @intCast(index)), event.ordinal);
        try std.testing.expectEqual(domain, event.domain);
        try std.testing.expectEqual(role, event.role);
    }

    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    var changed_binding = binding;
    changed_binding.main[0] = changed_binding.main[1];
    try std.testing.expectError(
        error.InvalidWitnessBinding,
        witness.Executor.init(&definition, &changed_binding),
    );
    try executor.validate();
    try std.testing.expectEqualStrings(
        witness.BINDING_DIGEST_HEX,
        &std.fmt.bytesToHex(binding.identityDigest(), .lower),
    );
}

test "R-012 transcript air static profile seals six events in three batches" {
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
    try std.testing.expectEqual(@as(u32, 48), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 24), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 24), profile.unique_constraint_root_values);
    try std.testing.expectEqual(@as(u32, 6), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 3), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 12), profile.interaction_columns);
    try std.testing.expectEqual(@as(u32, 2), profile.maximum_logical_constraint_degree);
    try std.testing.expectEqual(@as(?u32, 1), profile.maximum_lookup_numerator_degree);
    try std.testing.expectEqual(@as(?u32, 1), profile.maximum_lookup_denominator_degree);
    try std.testing.expectEqual(@as(?u32, 3), profile.maximum_modeled_interaction_degree);
    try std.testing.expectEqual(@as(u32, 88), profile.expression_dag_nodes);
    try std.testing.expectEqual(@as(u32, 78), profile.expression_dag_edges);
    try std.testing.expectEqual(@as(u32, 15), profile.expression_dag_shared_nodes);
    try std.testing.expectEqual(@as(u32, 0), profile.nodes_outside_constraint_effect_closure);
    try std.testing.expectEqualStrings(
        component.STATIC_PROFILE_DIGEST_HEX,
        &std.fmt.bytesToHex(profile.profile_digest, .lower),
    );
}

test "R-012 transcript air derives exact active rows in every proof mode" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const sources = [_]witness.Source{
        fixture.segmentSource(),
        fixture.binarySource(),
        .{ .empty_leaf = {} },
    };
    const row_counts = [_]usize{ 287, 572, 0 };
    const log_sizes = [_]u32{ 9, 10, 4 };
    const lane_counts = [_]u8{ 1, 2, 0 };
    for (sources, row_counts, log_sizes, lane_counts) |
        source_value,
        row_count,
        log_size,
        lane_count,
    | {
        var batch = try witness.PreparedBatch.init(
            std.testing.allocator,
            source_value,
        );
        defer batch.deinit();
        try batch.validateAgainstSource(source_value);
        try std.testing.expectEqual(row_count, batch.rows.len);
        try std.testing.expectEqual(log_size, batch.log_size);
        try std.testing.expectEqual(lane_count, batch.lane_count);
        for (batch.rows) |row| {
            try std.testing.expectEqual(@as(u32, 1), row.enabler);
            const provider_input = row.providerInput();
            for (provider_input, row.previous, 0..) |actual, previous, index| {
                const expected = if (index < witness.RATE)
                    previous.add(row.chunk[index]).v
                else
                    previous.v;
                try std.testing.expectEqual(expected, actual);
            }
        }
    }
}

test "R-012 transcript air direct roots and event weights are exact" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var batch = try witness.PreparedBatch.init(
        std.testing.allocator,
        fixture.segmentSource(),
    );
    defer batch.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);

    const first = try witness.logicalRow(batch.rows[0]);
    try expectSatisfied(&definition, first);
    const first_entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events.ordered(),
        first,
    );
    for (first_entries[0..3]) |entry|
        try std.testing.expect(entry.numerator.eql(QM31.one().neg()));
    try std.testing.expect(first_entries[3].numerator.isZero());
    try std.testing.expect(first_entries[4].numerator.eql(QM31.one()));
    try std.testing.expect(first_entries[5].numerator.isZero());

    const middle_index = findInternal(batch.rows).?;
    const middle = try witness.logicalRow(batch.rows[middle_index]);
    try expectSatisfied(&definition, middle);
    const middle_entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events.ordered(),
        middle,
    );
    try std.testing.expect(middle_entries[3].numerator.eql(QM31.one().neg()));
    try std.testing.expect(middle_entries[4].numerator.eql(QM31.one()));

    const last_index = findLast(batch.rows).?;
    const last = try witness.logicalRow(batch.rows[last_index]);
    const last_entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events.ordered(),
        last,
    );
    try std.testing.expect(last_entries[4].numerator.isZero());
    try std.testing.expect(last_entries[5].numerator.eql(QM31.one()));

    var forged = first;
    forged[0] = M31.zero();
    try expectAnyRootNonzero(&definition, forged);
    forged = first;
    forged[5] = M31.fromCanonical(2);
    try expectAnyRootNonzero(&definition, forged);
    forged = first;
    forged[8] = M31.one();
    try expectAnyRootNonzero(&definition, forged);
}

test "R-012 transcript air closes row 2 state chains and shared Poseidon provider" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const source_value = fixture.segmentSource();
    var batch = try witness.PreparedBatch.init(std.testing.allocator, source_value);
    defer batch.deinit();
    var binding_main = try binding_witness.MainWitness.init(
        std.testing.allocator,
        &fixture.preprocessing,
        source_value,
    );
    defer binding_main.deinit();

    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    var row2_definition = try binding_component.build(std.testing.allocator);
    defer row2_definition.deinit();
    const row2_plan = try binding_interaction.authenticate(&row2_definition);

    const row1_first = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events.ordered(),
        try witness.logicalRow(batch.rows[0]),
    );
    const row2_first = try row2_plan.entries(
        &row2_definition.arena,
        binding_component.SEMANTIC_DIGEST,
        row2_definition.events,
        binding_witness.logicalInputs(
            binding_main.rows[0],
            fixture.preprocessing.rows[0],
            .segment_leaf,
        ),
    );
    try expectCancellation(row1_first[1], row2_first[0]);
    try expectCancellation(row1_first[2], row2_first[1]);

    const final_index = findLast(batch.rows).?;
    const row1_final = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events.ordered(),
        try witness.logicalRow(batch.rows[final_index]),
    );
    const row2_final = try row2_plan.entries(
        &row2_definition.arena,
        binding_component.SEMANTIC_DIGEST,
        row2_definition.events,
        binding_witness.logicalInputs(
            binding_main.rows[final_index],
            fixture.preprocessing.rows[final_index],
            .segment_leaf,
        ),
    );
    try expectCancellation(row1_final[5], row2_final[2]);

    const internal_index = findInternal(batch.rows).?;
    const before = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events.ordered(),
        try witness.logicalRow(batch.rows[internal_index - 1]),
    );
    const after = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events.ordered(),
        try witness.logicalRow(batch.rows[internal_index]),
    );
    try expectCancellation(before[4], after[3]);

    var provider_authority = try poseidon_authority.Authority.init(
        std.testing.allocator,
    );
    defer provider_authority.deinit();
    const call = try witness.providerCall(batch.rows[0]);
    const provider_main = poseidon_production.fill(call);
    const provider_row = try provider_authority.relation_plan.rowFromMain(
        std.testing.allocator,
        provider_authority.relationAuthority(),
        provider_main,
    );
    const provider_entries = try provider_authority.relation_plan.entries(
        std.testing.allocator,
        provider_authority.relationAuthority(),
        provider_row,
    );
    try expectCancellation(row1_first[0], provider_entries[3]);
    try std.testing.expectEqualSlices(M31, &batch.rows[0].output, &provider_row.output);
}

test "R-012 transcript air cold snapshot and both hot writers are bounded atomic" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var batch = try witness.PreparedBatch.init(
        measured.allocator(),
        fixture.binarySource(),
    );
    defer batch.deinit();
    try std.testing.expectEqual(@as(usize, 1), measured.alloc_index);

    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const size = @as(usize, 1) << @intCast(batch.log_size);
    const storage = try std.testing.allocator.alloc(
        M31,
        component.PHYSICAL_MAIN_COLUMN_COUNT * size,
    );
    defer std.testing.allocator.free(storage);
    var columns: [component.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
    splitColumns(component.PHYSICAL_MAIN_COLUMN_COUNT, size, storage, &columns);
    const before = measured.alloc_index;
    try executor.generateMainInto(&batch, &columns);
    try std.testing.expectEqual(before, measured.alloc_index);
    for (batch.rows, 0..) |row, index| {
        const values = row.values();
        for (columns, values) |column, expected|
            try std.testing.expect(column[index].eql(expected));
    }
    for (columns) |column| for (column[batch.rows.len..]) |padding|
        try std.testing.expect(padding.isZero());

    const sentinel = M31.fromCanonical(0x5151);
    @memset(storage, sentinel);
    var short = columns;
    short[component.PHYSICAL_MAIN_COLUMN_COUNT - 1] =
        short[component.PHYSICAL_MAIN_COLUMN_COUNT - 1][0 .. size - 1];
    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generateMainInto(&batch, &short),
    );
    for (storage) |value| try std.testing.expect(value.eql(sentinel));
    var aliased = columns;
    aliased[1] = aliased[0];
    try std.testing.expectError(
        error.AliasedDestination,
        executor.generateMainInto(&batch, &aliased),
    );
    for (storage) |value| try std.testing.expect(value.eql(sentinel));

    batch.rows[0].chunk[0] = batch.rows[0].chunk[0].add(M31.one());
    try std.testing.expectError(
        error.AuthorityMismatch,
        executor.generateMainInto(&batch, &columns),
    );
    for (storage) |value| try std.testing.expect(value.eql(sentinel));
    batch.rows[0].chunk[0] = batch.rows[0].chunk[0].sub(M31.one());

    const calls = try std.testing.allocator.alloc(witness.ProviderCall, batch.rows.len);
    defer std.testing.allocator.free(calls);
    const call_sentinel = witness.ProviderCall{
        .input = [_]u32{17} ** witness.WIDTH,
        .wide = true,
        .io = false,
        .narrow_output = 99,
    };
    @memset(calls, call_sentinel);
    try batch.fillProviderCallsInto(calls);
    try std.testing.expectEqual(before, measured.alloc_index);
    for (calls, batch.rows) |call, row| {
        try std.testing.expect(!call.wide);
        try std.testing.expect(call.io);
        try std.testing.expectEqual(@as(?u32, null), call.narrow_output);
        try std.testing.expectEqualSlices(u32, &row.providerInput(), &call.input);
    }

    var provider_authority = try poseidon_authority.Authority.init(
        std.testing.allocator,
    );
    defer provider_authority.deinit();
    const provider_column_count = typed_poseidon2_witness.N_MAIN_COLUMNS;
    const provider_storage = try std.testing.allocator.alloc(
        M31,
        provider_column_count * size,
    );
    defer std.testing.allocator.free(provider_storage);
    var provider_columns: [provider_column_count][]M31 = undefined;
    splitColumns(
        provider_column_count,
        size,
        provider_storage,
        &provider_columns,
    );
    try provider_authority.executor.generateMainInto(
        &provider_columns,
        calls,
        batch.log_size,
    );
    try std.testing.expectEqual(before, measured.alloc_index);
    var provider_active: usize = 0;
    for (provider_columns[0]) |value|
        provider_active += @intFromBool(value.eql(M31.one()));
    try std.testing.expectEqual(calls.len, provider_active);

    @memset(calls, call_sentinel);
    try std.testing.expectError(
        error.InvalidProviderCallGeometry,
        batch.fillProviderCallsInto(calls[0 .. calls.len - 1]),
    );
    for (calls) |call| try std.testing.expect(std.meta.eql(call, call_sentinel));
    const alias = @as([*]witness.ProviderCall, @ptrCast(batch.rows.ptr))[0..batch.rows.len];
    try std.testing.expectError(error.AliasedInput, batch.fillProviderCallsInto(alias));
}

test "R-012 transcript air rejects independent source schedule and snapshot mutations" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const source_value = fixture.segmentSource();

    const final_call = fixture.segment.frames[0].finalCallId().?;
    const old_output = fixture.segment.calls[final_call].output[0];
    const changed_output = old_output.add(M31.one());
    fixture.segment.calls[final_call].output[0] = changed_output;
    fixture.segment.frames[0].output[0] = changed_output;
    try std.testing.expectError(
        error.RecordedPoseidonOutputMismatch,
        witness.PreparedBatch.init(std.testing.allocator, source_value),
    );
    fixture.segment.calls[final_call].output[0] = old_output;
    fixture.segment.frames[0].output[0] = old_output;

    const header_word = fixture.segment.word_storage[0][witness.RATE];
    const header_input = fixture.segment.calls[1].input[0];
    fixture.segment.word_storage[0][witness.RATE] = M31.one();
    fixture.segment.calls[1].input[0] = header_input.sub(header_word).add(M31.one());
    try std.testing.expectError(
        error.InvalidTranscriptLayout,
        witness.PreparedBatch.init(std.testing.allocator, source_value),
    );
    fixture.segment.word_storage[0][witness.RATE] = header_word;
    fixture.segment.calls[1].input[0] = header_input;

    fixture.vm.authority_digest[0] ^= 1;
    try std.testing.expectError(
        error.ScheduleDigestMismatch,
        witness.PreparedBatch.init(std.testing.allocator, source_value),
    );
    fixture.vm.authority_digest[0] ^= 1;

    var batch = try witness.PreparedBatch.init(std.testing.allocator, source_value);
    defer batch.deinit();
    batch.rows[0].chunk[0] = batch.rows[0].chunk[0].add(M31.one());
    try std.testing.expectError(error.AuthorityMismatch, batch.validate());
    batch.rows[0].chunk[0] = batch.rows[0].chunk[0].sub(M31.one());
    batch.transcript_receipts[0][0] ^= 1;
    try std.testing.expectError(error.AuthorityMismatch, batch.validate());
}

test "R-012 transcript air releases component batch and interaction OOM paths" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        componentFailureCase,
        .{},
    );
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        batchFailureCase,
        .{fixture.segmentSource()},
    );

    var batch = try witness.PreparedBatch.init(
        std.testing.allocator,
        fixture.segmentSource(),
    );
    defer batch.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    const rows = [_]interaction_mod.Row{try witness.logicalRow(batch.rows[0])};
    const relations = universal.UniversalRelations.dummy();
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    {
        var interaction = try plan.generateInteraction(
            measured.allocator(),
            &definition.arena,
            component.SEMANTIC_DIGEST,
            definition.events.ordered(),
            &rows,
            witness.MIN_LOG_SIZE,
            &relations,
        );
        defer interaction.deinit(measured.allocator());
        try std.testing.expectEqual(@as(usize, 5), measured.alloc_index);
    }
    try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        interactionFailureCase,
        .{
            &definition,
            &plan,
            &rows,
            witness.MIN_LOG_SIZE,
            &relations,
        },
    );
}
